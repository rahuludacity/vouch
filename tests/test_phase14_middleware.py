"""Tests for Phase 14 — agent-differentiated serving middleware (PRD §3.7).

Covers: classify() precedence, the WSGI branch lanes with a stub
verifier (no network), fail-closed behavior on every error path, the
verdict cache (negative-only: allows are always live decisions),
the verifier_client envelope-forwarding contract against a loopback
server, and serve() over real loopback HTTP.

No external network: the stub verifier replaces verifier_client, and
serve() is exercised over 127.0.0.1 only.
"""
import http.client
import io
import json
import os
import sys
import threading
import time
import unittest
import urllib.parse
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from services.verifier.middleware import (  # noqa: E402
    VerdictCache,
    VerifierUnreachable,
    VouchMiddleware,
    classify,
    serve,
    verifier_client,
)


BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/126.0.0.0 Safari/537.36")
BOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


def _environ(path="/", method="GET", headers=None, query=""):
    headers = headers or {}
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "SERVER_NAME": "127.0.0.1",
        "SERVER_PORT": "80",
        "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(b""),
        "wsgi.errors": io.StringIO(),
        "wsgi.version": (1, 0),
        "wsgi.run_once": False,
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
    }
    for name, value in headers.items():
        environ["HTTP_" + name.upper().replace("-", "_")] = value
    return environ


def _run(app, environ):
    """Drive a WSGI app without a server; return (status, headers, body)."""
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = dict(headers)

    body = b"".join(app(environ, start_response))
    return captured["status"], captured["headers"], body


def _page(text):
    def app(environ, start_response):
        body = text.encode("utf-8")
        start_response("200 OK", [("Content-Type", "text/plain"),
                                  ("Content-Length", str(len(body)))])
        return [body]
    return app


class StubVerifier:
    """Stub with .verify(envelope) — no network. ``verdicts`` maps the
    canonical credential bytes key to a decision dict; unknown envelopes
    are denied."""

    def __init__(self):
        self.calls = []
        self.verdicts = {}
        self.raise_on = None  # set to an exception to raise instead

    def allow(self, envelope):
        self.verdicts[VerdictCache.key_for(envelope)] = {
            "decision": "allow", "lane": "verified-agent",
            "reason": "credential valid; action within scope"}

    def verify(self, envelope):
        self.calls.append(envelope)
        if self.raise_on is not None:
            raise self.raise_on
        return self.verdicts.get(
            VerdictCache.key_for(envelope),
            {"decision": "deny", "lane": "unverified",
             "reason": "credential not recognized"})


def _mw(verifier=None, **kw):
    verifier = verifier if verifier is not None else StubVerifier()
    return VouchMiddleware(_page("AGENT"), _page("HUMAN"), _page("CHALLENGE"),
                           verifier=verifier, **kw)


def _cred(**kw):
    c = {"credential_id": "cred-1", "signature": "sig-aaa",
         "principal": {"pubkey": "deadbeef"}}
    c.update(kw)
    return c


# ---------------------------------------------------------------- classify

class TestClassify(unittest.TestCase):
    def test_agent_query_override_wins_over_browser_ua(self):
        self.assertEqual(
            classify({"User-Agent": BROWSER_UA}, {"agent": "1"}), "agent")

    def test_known_bot_ua_is_agent(self):
        self.assertEqual(classify({"user-agent": BOT_UA}, {}), "agent")

    def test_normal_browser_ua_is_human(self):
        self.assertEqual(classify({"User-Agent": BROWSER_UA}, {}), "human")

    def test_empty_ua_is_unknown(self):
        self.assertEqual(classify({"User-Agent": ""}, {}), "unknown")

    def test_missing_ua_is_unknown(self):
        self.assertEqual(classify({}, {}), "unknown")

    def test_header_lookup_is_case_insensitive(self):
        self.assertEqual(classify({"uSeR-aGeNt": BROWSER_UA}, {}), "human")
        self.assertEqual(classify({"USER-AGENT": BOT_UA}, {}), "agent")
        # query names are case-insensitive too
        self.assertEqual(
            classify({"User-Agent": BROWSER_UA}, {"AGENT": "1"}), "agent")

    def test_query_list_shape_accepted(self):
        self.assertEqual(
            classify({"User-Agent": BROWSER_UA}, {"agent": ["1"]}), "agent")


# ------------------------------------------------------------- middleware

class TestMiddlewareLanes(unittest.TestCase):
    def test_verified_agent_reaches_agent_app(self):
        stub = StubVerifier()
        cred = _cred()
        stub.allow(cred)
        app = _mw(verifier=stub)
        status, _, body = _run(app, _environ(
            headers={"User-Agent": BOT_UA,
                     "X-Vouch-Credential": json.dumps(cred)}))
        self.assertEqual(body, b"AGENT")
        self.assertEqual(len(stub.calls), 1)

    def test_denied_credential_reaches_challenge(self):
        app = _mw()  # stub denies unknown envelopes
        status, _, body = _run(app, _environ(
            headers={"User-Agent": BOT_UA,
                     "X-Vouch-Credential": json.dumps(_cred())}))
        self.assertEqual(body, b"CHALLENGE")

    def test_human_ua_reaches_human_app(self):
        app = _mw()
        status, _, body = _run(app, _environ(
            headers={"User-Agent": BROWSER_UA}))
        self.assertEqual(body, b"HUMAN")

    def test_unknown_ua_reaches_challenge(self):
        app = _mw()
        status, _, body = _run(app, _environ(headers={}))
        self.assertEqual(body, b"CHALLENGE")

    def test_malformed_credential_header_reaches_challenge(self):
        app = _mw()
        status, _, body = _run(app, _environ(
            headers={"User-Agent": BOT_UA,
                     "X-Vouch-Credential": "{not json"}))
        self.assertEqual(body, b"CHALLENGE")

    def test_non_dict_credential_reaches_challenge(self):
        app = _mw()
        status, _, body = _run(app, _environ(
            headers={"User-Agent": BOT_UA,
                     "X-Vouch-Credential": json.dumps("just-a-string")}))
        self.assertEqual(body, b"CHALLENGE")

    def test_agent_without_credential_reaches_challenge(self):
        app = _mw()
        status, _, body = _run(app, _environ(
            headers={"User-Agent": BOT_UA}))
        self.assertEqual(body, b"CHALLENGE")

    def test_credential_via_query_param(self):
        stub = StubVerifier()
        cred = _cred()
        stub.allow(cred)
        app = _mw(verifier=stub)
        q = urllib.parse.urlencode(
            {"vouch_credential": json.dumps(cred), "agent": "1"})
        status, _, body = _run(app, _environ(
            headers={"User-Agent": BROWSER_UA}, query=q))
        self.assertEqual(body, b"AGENT")

    def test_oversize_credential_reaches_challenge(self):
        app = _mw()
        big = json.dumps({"credential_id": "x",
                          "pad": "y" * (VouchMiddleware.MAX_CREDENTIAL_BYTES)})
        status, _, body = _run(app, _environ(
            headers={"User-Agent": BOT_UA,
                     "X-Vouch-Credential": big}))
        self.assertEqual(body, b"CHALLENGE")

    def test_verifier_unreachable_fails_closed(self):
        stub = StubVerifier()
        stub.raise_on = VerifierUnreachable("down")
        app = _mw(verifier=stub)
        status, _, body = _run(app, _environ(
            headers={"User-Agent": BOT_UA,
                     "X-Vouch-Credential": json.dumps(_cred())}))
        self.assertEqual(body, b"CHALLENGE")

    def test_wrong_lane_never_reaches_agent_app(self):
        # allow decision but wrong lane -> challenge (lane must match)
        stub = StubVerifier()
        cred = _cred()
        stub.verdicts[VerdictCache.key_for(cred)] = {
            "decision": "allow", "lane": "unverified", "reason": "odd"}
        app = _mw(verifier=stub)
        status, _, body = _run(app, _environ(
            headers={"User-Agent": BOT_UA,
                     "X-Vouch-Credential": json.dumps(cred)}))
        self.assertEqual(body, b"CHALLENGE")

    def test_verdict_exposed_without_credential_material(self):
        stub = StubVerifier()
        cred = _cred()
        stub.allow(cred)
        seen = {}

        def spy(environ, start_response):
            seen.update(environ.get("vouch.verdict", {}))
            body = b"AGENT"
            start_response("200 OK", [("Content-Length", str(len(body)))])
            return [body]

        app = VouchMiddleware(spy, _page("HUMAN"), _page("CHALLENGE"),
                              verifier=stub)
        _run(app, _environ(headers={"User-Agent": BOT_UA,
                                    "X-Vouch-Credential": json.dumps(cred)}))
        self.assertEqual(seen.get("lane"), "agent")
        flat = json.dumps(seen)
        # no actual credential material: not the signature, not the id
        self.assertNotIn("sig-aaa", flat)
        self.assertNotIn("cred-1", flat)

    def test_metrics_counts(self):
        stub = StubVerifier()
        stub.allow(_cred())
        metrics = {}
        app = _mw(verifier=stub, metrics=metrics)
        # agent allow
        _run(app, _environ(headers={"User-Agent": BOT_UA,
                                    "X-Vouch-Credential": json.dumps(_cred())}))
        # agent challenged (unknown credential)
        _run(app, _environ(headers={"User-Agent": BOT_UA,
                                    "X-Vouch-Credential":
                                        json.dumps(_cred(credential_id="x2"))}))
        # human
        _run(app, _environ(headers={"User-Agent": BROWSER_UA}))
        # unknown
        _run(app, _environ(headers={}))
        self.assertEqual(metrics, {"agent_allow": 1, "agent_challenge": 1,
                                  "human": 1, "unknown": 1})


# ------------------------------------------------------------------- cache

class TestVerdictCache(unittest.TestCase):
    def test_allow_is_never_cached(self):
        # Security rule: an allow must always be a live verifier decision
        # (proof-of-possession is per-request). Two identical requests ->
        # the verifier is consulted twice.
        stub = StubVerifier()
        stub.allow(_cred())
        app = _mw(verifier=stub)
        env = lambda: _environ(headers={"User-Agent": BOT_UA,
                                        "X-Vouch-Credential": json.dumps(_cred())})
        _run(app, env())
        status, _, body = _run(app, env())
        self.assertEqual(body, b"AGENT")
        self.assertEqual(len(stub.calls), 2)

    def test_tampered_envelope_is_denied_live(self):
        stub = StubVerifier()
        stub.allow(_cred())  # allow only the original bytes
        app = _mw(verifier=stub)
        good = _environ(headers={"User-Agent": BOT_UA,
                                 "X-Vouch-Credential": json.dumps(_cred())})
        tampered = _environ(
            headers={"User-Agent": BOT_UA,
                     "X-Vouch-Credential": json.dumps(
                         _cred(signature="sig-TAMPERED"))})
        _run(app, good)
        status, _, body = _run(app, tampered)
        # same credential_id, different signature bytes -> the stub does
        # not recognize it -> deny -> challenge (and the good one was a
        # live allow, never cached)
        self.assertEqual(body, b"CHALLENGE")
        self.assertEqual(len(stub.calls), 2)

    def test_negative_cache_uses_short_ttl(self):
        import services.verifier.middleware as mwmod
        real_time = mwmod.time.time
        now = [1_000_000.0]
        mwmod.time.time = lambda: now[0]
        try:
            stub = StubVerifier()  # denies everything
            cache = VerdictCache(ttl_s=3600, negative_ttl_s=10)
            app = _mw(verifier=stub, cache=cache)
            env = lambda: _environ(
                headers={"User-Agent": BOT_UA,
                         "X-Vouch-Credential": json.dumps(_cred())})
            _run(app, env())
            self.assertEqual(len(stub.calls), 1)
            _run(app, env())  # within negative TTL -> cached deny
            self.assertEqual(len(stub.calls), 1)
            now[0] += 11  # past negative TTL
            _run(app, env())
            self.assertEqual(len(stub.calls), 2)
        finally:
            mwmod.time.time = real_time

    def test_allow_still_live_after_negative_ttl_passes(self):
        import services.verifier.middleware as mwmod
        real_time = mwmod.time.time
        now = [2_000_000.0]
        mwmod.time.time = lambda: now[0]
        try:
            stub = StubVerifier()
            stub.allow(_cred())
            cache = VerdictCache(ttl_s=3600, negative_ttl_s=10)
            app = _mw(verifier=stub, cache=cache)
            env = lambda: _environ(
                headers={"User-Agent": BOT_UA,
                         "X-Vouch-Credential": json.dumps(_cred())})
            _run(app, env())
            now[0] += 11  # past negative TTL
            _run(app, env())
            # allows are never cached: the verifier is consulted again
            self.assertEqual(len(stub.calls), 2)
        finally:
            mwmod.time.time = real_time

    def test_cache_size_cap_evicts_oldest(self):
        cache = VerdictCache(ttl_s=60, negative_ttl_s=10, max_entries=3)
        for i in range(5):
            cache.put(_cred(credential_id=f"c{i}"), "deny",
                      "unverified", "nope")
        self.assertLessEqual(len(cache._entries), 3)
        # newest entries survive, oldest evicted
        self.assertIsNotNone(cache.get(_cred(credential_id="c4")))
        self.assertIsNone(cache.get(_cred(credential_id="c0")))


def _signed_envelope(**kw):
    """A full agent-signed request envelope (what X-Vouch-Credential
    carries in a real deployment)."""
    env = {
        "credential": _cred(),
        "action": {"type": "middleware.page_access"},
        "nonce": "n-123",
        "ts": 1_700_000_000,
        "agent_signature": "sig-agent-abc",
    }
    env.update(kw)
    return env


class TestVerifierClient(unittest.TestCase):
    """The reference client must forward the agent's signed envelope
    AS-IS. Re-wrapping it with a fresh nonce/ts would break the agent's
    proof-of-possession signature and deny every real request."""

    def _server(self, handler):
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                handler.received = json.loads(
                    self.rfile.read(length).decode("utf-8"))
                body = json.dumps(handler.reply).encode("utf-8")
                self.send_response(handler.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def test_forwards_signed_envelope_as_is(self):
        class H:
            received = None
            status = 200
            reply = {"decision": "allow", "lane": "verified-agent",
                     "reason": "ok"}
        srv = self._server(H)
        try:
            client = verifier_client(
                f"http://127.0.0.1:{srv.server_address[1]}")
            env = _signed_envelope()
            out = client.verify(env)
            self.assertEqual(out["decision"], "allow")
            self.assertEqual(out["lane"], "verified-agent")
            # The agent's own fields arrive untouched — NOT re-wrapped
            # with a fresh nonce/ts.
            self.assertEqual(H.received["credential"], env["credential"])
            self.assertEqual(H.received["action"], env["action"])
            self.assertEqual(H.received["nonce"], "n-123")
            self.assertEqual(H.received["ts"], 1_700_000_000)
            self.assertEqual(H.received["agent_signature"],
                             "sig-agent-abc")
            self.assertEqual(H.received["tenant_id"], "default")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_malformed_envelope_raises_before_any_http(self):
        class H:
            received = None
            status = 200
            reply = {"decision": "allow", "lane": "verified-agent",
                     "reason": "ok"}
        srv = self._server(H)
        try:
            client = verifier_client(
                f"http://127.0.0.1:{srv.server_address[1]}")
            bad = _signed_envelope()
            del bad["agent_signature"]
            with self.assertRaises(VerifierUnreachable):
                client.verify(bad)
            self.assertIsNone(H.received)  # no request was sent
            with self.assertRaises(VerifierUnreachable):
                client.verify("not-a-dict")
            self.assertIsNone(H.received)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_verifier_error_raises_unreachable(self):
        class H:
            received = None
            status = 500
            reply = {"error": "boom"}
        srv = self._server(H)
        try:
            client = verifier_client(
                f"http://127.0.0.1:{srv.server_address[1]}")
            with self.assertRaises(VerifierUnreachable):
                client.verify(_signed_envelope())
        finally:
            srv.shutdown()
            srv.server_close()

    def test_verifier_nonsense_body_raises_unreachable(self):
        class H:
            received = None
            status = 200
            reply = {"surprise": "no decision here"}
        srv = self._server(H)
        try:
            client = verifier_client(
                f"http://127.0.0.1:{srv.server_address[1]}")
            with self.assertRaises(VerifierUnreachable):
                client.verify(_signed_envelope())
        finally:
            srv.shutdown()
            srv.server_close()


# ------------------------------------------------------------------- serve

class TestServe(unittest.TestCase):
    def test_all_three_lanes_over_loopback_http(self):
        stub = StubVerifier()
        cred = _cred()
        stub.allow(cred)
        server, port = serve(verifier=stub)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # http.client sends exactly the headers given (no automatic
            # User-Agent like urllib adds), so the unknown-UA case is a
            # genuine no-UA request.
            def get(headers=None, path="/"):
                conn = http.client.HTTPConnection("127.0.0.1", port,
                                                  timeout=5)
                conn.request("GET", path, headers=headers or {})
                resp = conn.getresponse()
                body = resp.read()
                conn.close()
                return resp.status, body

            # human lane: normal browser UA
            status, body = get({"User-Agent": BROWSER_UA})
            self.assertEqual(status, 200)
            self.assertIn(b"Acme Store", body)

            # agent lane: bot UA + valid credential header
            status, body = get({"User-Agent": BOT_UA,
                                "X-Vouch-Credential": json.dumps(cred)})
            self.assertEqual(status, 200)
            payload = json.loads(body.decode("utf-8"))
            self.assertEqual(payload["lane"], "verified-agent")
            self.assertIn("summary", payload)

            # challenge lane: no UA (unknown) -> verify-to-continue
            status, body = get()
            self.assertEqual(status, 402)
            self.assertIn(b"Verify to continue", body)

            # challenge lane: bot UA but no credential
            status, body = get({"User-Agent": BOT_UA})
            self.assertEqual(status, 402)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
