"""H-3 gap closure: principal_approval forwarded through the reference
middleware end-to-end.

The reference middleware's verifier client must forward the agent-attached
principal_approval to the verifier verbatim; without that, prepare-mode
effect actions fail closed through it (the headline PRD flow breaks). These
tests drive the REAL middleware code path (envelope extraction ->
verifier_client -> HTTP POST over loopback) against a stub server that runs
the REAL verifier core (verify_action_request_v2) on the received POST body
— so prepare -> principal approval -> execute is proved end to end, not
just asserted at one layer.

Fail-without-fix: revert the forwarding in _VerifierClient.verify and the
allow-path tests fail (the stub receives no principal_approval, the core
denies prepare+effect, the agent lane is never reached). The deny-path
tests pin that the fix did not weaken fail-closed behavior.
"""
import io
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.verifier.middleware import (  # noqa: E402
    VouchMiddleware,
    verifier_client,
)
from services.verifier.credentials import (  # noqa: E402
    default_tier_policy,
    verify_action_request_v2,
)
from test_h3_modes import MSG_SCOPE, ModeWorld, _mint_approval  # noqa: E402

BOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


def _environ(headers, query=""):
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/",
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
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status

    body = b"".join(app(environ, start_response))
    return captured["status"], body


def _page(text):
    def app(environ, start_response):
        body = text.encode("utf-8")
        start_response("200 OK", [("Content-Type", "text/plain"),
                                  ("Content-Length", str(len(body)))])
        return [body]
    return app


class _RealCoreHandler(BaseHTTPRequestHandler):
    """Stub verifier: runs the REAL verifier core on the POST body.

    Mirrors the real service path (decide -> verify_action_request_v2 with
    a fresh manifest), minus receipts/STATE plumbing, which is orthogonal
    to the forwarding contract under test.
    """
    world = None
    received = None

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        type(self).received = body
        manifest = type(self).world.manifest()
        ok, reasons, _ev = verify_action_request_v2(
            body, manifest=manifest,
            operator_pubkeys=type(self).world.op_pub,
            policy_hook=default_tier_policy({}),
            nonces=set(), usage={}, spending={}, approval_nonces=set())
        reply = {"decision": "allow" if ok else "deny",
                 "lane": "verified-agent" if ok else "unverified",
                 "reason": "; ".join(reasons)}
        raw = json.dumps(reply).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


def _serve(world):
    _RealCoreHandler.world = world
    _RealCoreHandler.received = None
    srv = HTTPServer(("127.0.0.1", 0), _RealCoreHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _Fixture:
    """prepare-mode credential + messaging.send (effect) action world."""

    def __init__(self):
        self.world = ModeWorld()
        self.cred = self.world.credential("prepare", MSG_SCOPE)
        self.action = {"type": "messaging.send",
                       "target": "ops-channel",
                       "text": "deploy approved"}

    def envelope(self, approval=None):
        env = self.world.request(self.cred, self.action, approval=approval)
        return env

    def approval(self, **kw):
        return _mint_approval(self.world.p_priv,
                              self.cred["credential_id"],
                              self.action, **kw)

    def request_environ(self, envelope):
        return _environ({
            "User-Agent": BOT_UA,
            "X-Vouch-Credential": json.dumps(envelope),
        })


class TestMiddlewareApprovalForwarding(unittest.TestCase):
    def _stack(self, world):
        srv = _serve(world)
        self.addCleanup(srv.shutdown)
        self.addCleanup(srv.server_close)
        mw = VouchMiddleware(_page("AGENT-LANE"), _page("HUMAN"),
                             _page("CHALLENGE-LANE"),
                             verifier=verifier_client(
                                 f"http://127.0.0.1:{srv.server_address[1]}"))
        return mw

    def test_prepare_effect_with_approval_reaches_agent_lane(self):
        fx = _Fixture()
        approval = fx.approval()
        mw = self._stack(fx.world)
        status, body = _run(mw, fx.request_environ(fx.envelope(approval)))
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, b"AGENT-LANE",
                         "valid principal approval must reach the agent lane")
        # The approval arrived at the verifier verbatim.
        self.assertEqual(_RealCoreHandler.received["principal_approval"],
                         approval)

    def test_prepare_effect_without_approval_still_fails_closed(self):
        fx = _Fixture()
        mw = self._stack(fx.world)
        _, body = _run(mw, fx.request_environ(fx.envelope()))
        self.assertEqual(body, b"CHALLENGE-LANE")
        self.assertNotIn("principal_approval", _RealCoreHandler.received)

    def test_forged_approval_denied_at_verifier_not_bypassed(self):
        fx = _Fixture()
        # Agent's own key signs instead of the principal's: forged.
        forged = _mint_approval(fx.world.a_priv,
                                fx.cred["credential_id"], fx.action)
        mw = self._stack(fx.world)
        _, body = _run(mw, fx.request_environ(fx.envelope(forged)))
        self.assertEqual(body, b"CHALLENGE-LANE")

    def test_cached_deny_cannot_poison_later_approval(self):
        fx = _Fixture()
        mw = self._stack(fx.world)
        # Deny first (no approval): the negative verdict is cached briefly.
        _, body = _run(mw, fx.request_environ(fx.envelope()))
        self.assertEqual(body, b"CHALLENGE-LANE")
        # Same action WITH a valid approval must still reach the agent
        # lane: the cache key binds the full envelope bytes, so the cached
        # deny cannot alias the approval-carrying request.
        _, body = _run(mw, fx.request_environ(fx.envelope(fx.approval())))
        self.assertEqual(body, b"AGENT-LANE")

    def test_client_forwards_approval_byte_for_byte(self):
        fx = _Fixture()
        srv = _serve(fx.world)
        self.addCleanup(srv.shutdown)
        self.addCleanup(srv.server_close)
        client = verifier_client(
            f"http://127.0.0.1:{srv.server_address[1]}")
        approval = fx.approval()
        out = client.verify(fx.envelope(approval))
        self.assertEqual(out["decision"], "allow")
        self.assertEqual(_RealCoreHandler.received["principal_approval"],
                         approval)


if __name__ == "__main__":
    unittest.main()
