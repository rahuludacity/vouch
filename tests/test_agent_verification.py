"""Tests for the agent verification layer (services/verifier).

Covers: vendored Ed25519 (pinned libsodium-generated vectors + RFC-style
round-trips), credential issuance/delegation/scope, action-request
verification (possession, scope, replay, rate limits), and the :9005
verifier service in-process on an ephemeral port — including the
three-lane gateway behavior (verified-agent / human / unverified).
"""
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from services.verifier import ed25519  # noqa: E402
from services.verifier import credentials  # noqa: E402
from services.verifier.credentials import (  # noqa: E402
    generate_keypair, issue_delegation, issue_credential,
    sign_action_request, verify_credential, verify_action_request,
    scope_allows, scope_narrows)

# Pinned vectors generated with libsodium (deterministic Ed25519).
V1_SEED = "9d61b19c9d61b19c9d61b19c9d61b19c9d61b19c9d61b19c9d61b19c9d61b19c"
V1_PUB = "3e7b525cc3ee41e36b30bf17eed6ef11ca86343221893f6902bb990a9f7b4919"
V1_MSG = b""
V1_SIG = ("ea5440c710c2b8dd2253a781e53adc3480070fcb6439d9329325177b158a9b0"
          "9809fc1b67bebc329b88f9e5c1755aceb8083bc502c0cdb6a094e4a60e9acc709")
V2_SEED = "4ccd089b4ccd089b4ccd089b4ccd089b4ccd089b4ccd089b4ccd089b4ccd089b"
V2_PUB = "e23b40c5db29e9fe3f2c64b187faa900a877e6f366c2009995b62df853b247eb"
V2_MSG = b"72"
V2_SIG = ("a6bef1c92958bd062233aa348a3ea0413a4bf3a594ca78625ae46566d93c9153"
          "9e21cc5c350b55c4c7db3f01eab1b557759caefa47bbb9ba85d5dc3041a38d0a")


def make_chain(scope_agent=None, scope_sub=None, ttl_s=3600):
    """principal -> agent -> sub-agent; returns dict of key material + cred."""
    p_priv, p_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()
    s_priv, s_pub = generate_keypair()
    scope_agent = scope_agent or {"allow": ["form.submit", "form.read"]}
    scope_sub = scope_sub or {"allow": ["form.submit"]}
    link1 = issue_delegation(delegator_priv_hex=p_priv,
                             delegator_pub_hex=p_pub,
                             delegatee_pub_hex=a_pub,
                             scope=scope_agent, ttl_s=ttl_s)
    link2 = issue_delegation(delegator_priv_hex=a_priv,
                             delegator_pub_hex=a_pub,
                             delegatee_pub_hex=s_pub,
                             scope=scope_sub, ttl_s=ttl_s)
    cred = issue_credential(principal_id="smallville-gov",
                            principal_priv_hex=p_priv,
                            principal_pub_hex=p_pub,
                            agent_id="permit-bot",
                            agent_pub_hex=s_pub,
                            scope=scope_sub,
                            delegations=[link1, link2],
                            ttl_s=ttl_s)
    return {"p_priv": p_priv, "p_pub": p_pub, "a_priv": a_priv,
            "a_pub": a_pub, "s_priv": s_priv, "s_pub": s_pub,
            "cred": cred}


def make_request(chain, action_type="form.submit", target="/permits/apply",
                 nonce=None, ts=None, priv=None):
    action = {"type": action_type, "target": target,
              "args": {"name": "Jane", "permit": "deck"}}
    env = sign_action_request(
        agent_priv_hex=priv or chain["s_priv"],
        credential_id=chain["cred"]["credential_id"],
        action=action, nonce=nonce, ts=ts)
    return {"tenant_id": "smallville", "credential": chain["cred"],
            "action": env["action"], "nonce": env["nonce"], "ts": env["ts"],
            "agent_signature": env["agent_signature"]}


class TestEd25519(unittest.TestCase):
    def test_pinned_vectors(self):
        sk = bytes.fromhex(V1_SEED)
        _, pk = ed25519.generate_keypair(sk)
        self.assertEqual(pk.hex(), V1_PUB)
        self.assertEqual(ed25519.sign(sk, V1_MSG).hex(), V1_SIG)
        self.assertTrue(ed25519.verify(bytes.fromhex(V1_PUB), V1_MSG,
                                       bytes.fromhex(V1_SIG)))
        sk2 = bytes.fromhex(V2_SEED)
        _, pk2 = ed25519.generate_keypair(sk2)
        self.assertEqual(pk2.hex(), V2_PUB)
        self.assertTrue(ed25519.verify(bytes.fromhex(V2_PUB), V2_MSG,
                                       bytes.fromhex(V2_SIG)))

    def test_roundtrip_random(self):
        import os as _os
        for _ in range(3):
            sk, pk = ed25519.generate_keypair()
            msg = _os.urandom(48)
            sig = ed25519.sign(sk, msg)
            self.assertTrue(ed25519.verify(pk, msg, sig))

    def test_rejects_tampering(self):
        import os as _os
        sk, pk = ed25519.generate_keypair()
        sig = ed25519.sign(sk, b"data")
        self.assertFalse(ed25519.verify(pk, b"data!", sig))
        bad = bytearray(sig)
        bad[10] ^= 1
        self.assertFalse(ed25519.verify(pk, b"data", bytes(bad)))
        self.assertFalse(ed25519.verify(_os.urandom(32), b"data", sig))
        self.assertFalse(ed25519.verify(pk, b"data", b"tooshort"))


class TestScopes(unittest.TestCase):
    def test_allow_deny(self):
        s = {"allow": ["form.*"], "deny": ["form.delete"]}
        self.assertTrue(scope_allows(s, "form.submit"))
        self.assertFalse(scope_allows(s, "form.delete"))
        self.assertFalse(scope_allows(s, "api.read"))

    def test_narrowing(self):
        parent = {"allow": ["form.submit", "form.read"],
                  "deny": ["form.delete"]}
        child = {"allow": ["form.submit"], "deny": ["form.delete", "x"]}
        ok, _ = scope_narrows(child, parent)
        self.assertTrue(ok)
        wide = {"allow": ["form.submit", "admin.*"]}
        ok, why = scope_narrows(wide, parent)
        self.assertFalse(ok)
        drop_deny = {"allow": ["form.submit"], "deny": []}
        ok, _ = scope_narrows(drop_deny, parent)
        self.assertFalse(ok)
        loose = {"allow": ["form.submit"],
                 "limits": {"form.submit": {"max_per_day": 100}}}
        tight = {"allow": ["form.submit", "form.read"],
                 "limits": {"form.submit": {"max_per_day": 10}}}
        ok, _ = scope_narrows(loose, tight)
        self.assertFalse(ok)


class TestCredentials(unittest.TestCase):
    def test_valid_chain(self):
        c = make_chain()
        ok, reasons = verify_credential(c["cred"], [c["p_pub"]])
        self.assertTrue(ok, reasons)

    def test_untrusted_issuer(self):
        c = make_chain()
        ok, reasons = verify_credential(c["cred"], ["00" * 32])
        self.assertFalse(ok)
        self.assertTrue(any("not trusted" in r for r in reasons))

    def test_tampered_link_scope(self):
        c = make_chain()
        c["cred"]["delegations"][0]["scope"]["allow"].append("admin.*")
        ok, reasons = verify_credential(c["cred"], [c["p_pub"]])
        self.assertFalse(ok)
        self.assertTrue(any("signature invalid" in r for r in reasons))

    def _resign(self, c):
        """Re-sign the credential body with the principal key after the
        test mutates the delegation links (keeps the tamper *inside* the
        chain so the walker — not the issuer-signature check — catches it)."""
        cred = c["cred"]
        cred["signature"] = ed25519.sign_hex(
            c["p_priv"], credentials.canonical(
                {k: v for k, v in cred.items() if k != "signature"}))
        return cred

    def test_broken_continuity(self):
        c = make_chain()
        # Rogue re-signs link 1 with its own key: signatures stay valid,
        # but the chain no longer connects link 0 -> link 1.
        rogue_priv, rogue_pub = generate_keypair()
        c["cred"]["delegations"][1] = issue_delegation(
            delegator_priv_hex=rogue_priv, delegator_pub_hex=rogue_pub,
            delegatee_pub_hex=c["s_pub"],
            scope={"allow": ["form.submit"]})
        cred = self._resign(c)
        ok, reasons = verify_credential(cred, [c["p_pub"]])
        self.assertFalse(ok)
        self.assertTrue(any("continuity" in r for r in reasons), reasons)

    def test_scope_widening_rejected(self):
        c = make_chain()
        # Agent re-delegates with a WIDER scope than it was granted, keeping
        # the chain connected: the narrowing rule must still catch it.
        c["cred"]["delegations"][1] = issue_delegation(
            delegator_priv_hex=c["a_priv"], delegator_pub_hex=c["a_pub"],
            delegatee_pub_hex=c["s_pub"],
            scope={"allow": ["form.submit", "admin.*"]})
        cred = self._resign(c)
        ok, reasons = verify_credential(cred, [c["p_pub"]])
        self.assertFalse(ok)
        self.assertTrue(any("widens" in r for r in reasons), reasons)

    def test_expired_credential(self):
        c = make_chain(ttl_s=-10)
        ok, reasons = verify_credential(c["cred"], [c["p_pub"]])
        self.assertFalse(ok)
        self.assertTrue(any("expired" in r for r in reasons))

    def test_forged_issuer_signature(self):
        c = make_chain()
        evil_priv, _ = generate_keypair()
        c["cred"]["scope"] = {"allow": ["*"]}
        c["cred"]["signature"] = ed25519.sign_hex(
            evil_priv, credentials.canonical(
                {k: v for k, v in c["cred"].items() if k != "signature"}))
        ok, reasons = verify_credential(c["cred"], [c["p_pub"]])
        self.assertFalse(ok)
        self.assertTrue(any("issuer signature" in r for r in reasons))


class TestActionRequests(unittest.TestCase):
    def test_valid_request(self):
        c = make_chain()
        req = make_request(c)
        ok, reasons = verify_action_request(req, [c["p_pub"]], usage={})
        self.assertTrue(ok, reasons)

    def test_wrong_key_signature(self):
        c = make_chain()
        evil_priv, _ = generate_keypair()
        req = make_request(c, priv=evil_priv)
        ok, reasons = verify_action_request(req, [c["p_pub"]], usage={})
        self.assertFalse(ok)
        self.assertTrue(any("agent signature" in r for r in reasons))

    def test_out_of_scope(self):
        c = make_chain()
        req = make_request(c, action_type="form.delete")
        ok, reasons = verify_action_request(req, [c["p_pub"]], usage={})
        self.assertFalse(ok)
        self.assertTrue(any("outside authorized scope" in r for r in reasons))

    def test_replay_nonce(self):
        c = make_chain()
        req = make_request(c, nonce="fixed-nonce-1")
        seen = set()
        ok, _ = verify_action_request(req, [c["p_pub"]], seen_nonces=seen)
        self.assertTrue(ok)
        seen.add("fixed-nonce-1")
        ok, reasons = verify_action_request(req, [c["p_pub"]],
                                            seen_nonces=seen)
        self.assertFalse(ok)
        self.assertTrue(any("replay" in r for r in reasons))

    def test_rate_limit(self):
        c = make_chain(scope_sub={"allow": ["form.submit"],
                                  "limits": {"form.submit":
                                             {"max_per_day": 2}}})
        day = time.strftime("%Y-%m-%d", time.gmtime())
        usage = {(c["s_pub"], "form.submit", day): 2}
        req = make_request(c)
        ok, reasons = verify_action_request(req, [c["p_pub"]], usage=usage)
        self.assertFalse(ok)
        self.assertTrue(any("rate limit" in r for r in reasons))

    def test_stale_timestamp(self):
        c = make_chain()
        req = make_request(c, ts=time.time() - 3600)
        ok, reasons = verify_action_request(req, [c["p_pub"]], usage={})
        self.assertFalse(ok)
        self.assertTrue(any("timestamp" in r for r in reasons))


# ---------------------------------------------------------------- service
def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class VerifierServiceCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="vouch-verifier-test-")
        tenants = os.path.join(cls.tmp, "tenants.json")
        with open(tenants, "w", encoding="utf-8") as f:
            json.dump({"tenants": {"smallville":
                                   {"created_at": 1,
                                    "keys": {"k1": "ab" * 32},
                                    "current_kid": "k1"}}}, f)
        os.environ["VERIFIER_TENANTS_PATH"] = tenants
        os.environ["VERIFIER_RECEIPTS_PATH"] = os.path.join(
            cls.tmp, "transparency.jsonl")
        os.environ["RECEIPT_SVC_URL"] = ""  # local file only in tests
        import services.verifier.app as appmod
        cls.app = appmod
        from gatekeeper.tenants import TenantRegistry
        from gatekeeper.receipts import ReceiptLog
        from gatekeeper.ingest import ReceiptEmitter
        registry = TenantRegistry(tenants)
        appmod.EMITTER = ReceiptEmitter(
            registry, ReceiptLog(os.path.join(cls.tmp, "transparency.jsonl"),
                                 registry), svc_url="")
        appmod.TRUSTED_ISSUERS = []  # per-test
        appmod.PRINCIPAL_DAILY_LIMIT = 1000
        cls.port = _free_port()
        cls.server = ThreadingHTTPServer(("127.0.0.1", cls.port),
                                         appmod.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        # fresh replay/usage state per test
        self.app.STATE = self.app.VerifierState()

    def post_verify(self, body):
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            self.base + "/v1/verify", data=data,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def test_health(self):
        with urllib.request.urlopen(self.base + "/v1/health",
                                    timeout=10) as r:
            body = json.loads(r.read().decode())
        self.assertTrue(body["ok"])

    def test_allow_verified_agent_lane(self):
        c = make_chain()
        self.app.TRUSTED_ISSUERS = [c["p_pub"]]
        req = make_request(c)
        code, body = self.post_verify(req)
        self.assertEqual(code, 200)
        self.assertEqual(body["decision"], "allow")
        self.assertEqual(body["lane"], "verified-agent")
        self.assertIsNotNone(body["receipt_seq"])
        # transparency log holds a signed, chained receipt for the decision
        from gatekeeper.tenants import TenantRegistry
        from gatekeeper.receipts import ReceiptLog
        log = ReceiptLog(os.path.join(self.tmp, "transparency.jsonl"),
                         TenantRegistry(os.environ["VERIFIER_TENANTS_PATH"]))
        ok, failures = log.verify()
        self.assertTrue(ok, failures)
        with open(os.path.join(self.tmp, "transparency.jsonl")) as f:
            last = json.loads(list(f)[-1])
        self.assertEqual(last["tool"], "agent.verify")
        self.assertEqual(last["decision"], "allow")

    def test_deny_forged_credential_unverified_lane(self):
        c = make_chain()
        self.app.TRUSTED_ISSUERS = [c["p_pub"]]
        evil_priv, _ = generate_keypair()
        c["cred"]["scope"] = {"allow": ["*"]}  # tamper, keep old signature
        req = make_request(c, priv=evil_priv)
        code, body = self.post_verify(req)
        self.assertEqual(code, 200)
        self.assertEqual(body["decision"], "deny")
        self.assertEqual(body["lane"], "unverified")
        self.assertIn("signature", body["reason"])

    def test_deny_missing_credential(self):
        self.app.TRUSTED_ISSUERS = []
        code, body = self.post_verify({
            "tenant_id": "smallville",
            "action": {"type": "form.submit", "target": "/", "args": {}},
            "nonce": "n1", "ts": time.time(), "agent_signature": "00"})
        self.assertEqual(code, 200)
        self.assertEqual(body["decision"], "deny")
        self.assertEqual(body["lane"], "unverified")

    def test_deny_replay(self):
        c = make_chain()
        self.app.TRUSTED_ISSUERS = [c["p_pub"]]
        req = make_request(c, nonce="replay-me")
        _, b1 = self.post_verify(req)
        self.assertEqual(b1["decision"], "allow")
        _, b2 = self.post_verify(req)
        self.assertEqual(b2["decision"], "deny")
        self.assertIn("replay", b2["reason"])

    def test_deny_out_of_scope(self):
        c = make_chain()
        self.app.TRUSTED_ISSUERS = [c["p_pub"]]
        req = make_request(c, action_type="admin.wipe")
        _, body = self.post_verify(req)
        self.assertEqual(body["decision"], "deny")
        self.assertIn("scope", body["reason"])

    def test_principal_daily_limit(self):
        c = make_chain()
        self.app.TRUSTED_ISSUERS = [c["p_pub"]]
        self.app.PRINCIPAL_DAILY_LIMIT = 2
        try:
            for i in range(2):
                _, body = self.post_verify(make_request(c))
                self.assertEqual(body["decision"], "allow", i)
            _, body = self.post_verify(make_request(c))
            self.assertEqual(body["decision"], "deny")
            self.assertIn("rate limit", body["reason"])
        finally:
            self.app.PRINCIPAL_DAILY_LIMIT = 1000

    def test_malformed_body(self):
        req = urllib.request.Request(
            self.base + "/v1/verify", data=b"not json",
            headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 400)


# ---------------------------------------------------------------- site lanes
class SiteLanesCase(unittest.TestCase):
    """The demo site's three-lane gateway, verifier + site in-process."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="vouch-site-test-")
        tenants = os.path.join(cls.tmp, "tenants.json")
        with open(tenants, "w", encoding="utf-8") as f:
            json.dump({"tenants": {"smallville":
                                   {"created_at": 1,
                                    "keys": {"k1": "cd" * 32},
                                    "current_kid": "k1"}}}, f)
        import services.verifier.app as appmod
        from gatekeeper.tenants import TenantRegistry
        from gatekeeper.receipts import ReceiptLog
        from gatekeeper.ingest import ReceiptEmitter
        registry = TenantRegistry(tenants)
        appmod.EMITTER = ReceiptEmitter(
            registry, ReceiptLog(os.path.join(cls.tmp, "t.jsonl"),
                                 registry), svc_url="")
        appmod.STATE = appmod.VerifierState()
        vport = _free_port()
        cls.vserver = ThreadingHTTPServer(("127.0.0.1", vport),
                                         appmod.Handler)
        threading.Thread(target=cls.vserver.serve_forever,
                         daemon=True).start()
        sys.path.insert(0, os.path.join(REPO, "demo", "agent_verification"))
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location(
            "demo_site",
            os.path.join(REPO, "demo", "agent_verification", "site.py"))
        sitemod = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(sitemod)
        sitemod.STATE = sitemod.GatewayState()
        sport = _free_port()
        cls.sserver = ThreadingHTTPServer(
            ("127.0.0.1", sport),
            sitemod.make_handler(f"http://127.0.0.1:{vport}"))
        threading.Thread(target=cls.sserver.serve_forever,
                         daemon=True).start()
        cls.appmod = appmod
        cls.site_base = f"http://127.0.0.1:{sport}"
        cls.chain = make_chain()
        appmod.TRUSTED_ISSUERS = [cls.chain["p_pub"]]

    @classmethod
    def tearDownClass(cls):
        cls.vserver.shutdown()
        cls.sserver.shutdown()

    def _post(self, path, data, ctype):
        req = urllib.request.Request(self.site_base + path, data=data,
                                     headers={"Content-Type": ctype})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_human_lane_unchanged(self):
        code, body = self._post(
            "/submit", b"name=Bob&permit=shed",
            "application/x-www-form-urlencoded")
        self.assertEqual(code, 200)
        self.assertIn(b"human lane", body)

    def test_verified_agent_lane(self):
        req = make_request(self.chain)
        code, body = self._post("/agent-submit", json.dumps(req).encode(),
                                "application/json")
        self.assertEqual(code, 200)
        body = json.loads(body.decode())
        self.assertEqual(body["lane"], "verified-agent")
        self.assertEqual(body["status"], "accepted")
        self.assertIsNotNone(body["receipt_seq"])

    def test_unverified_lane_no_credential(self):
        code, body = self._post("/agent-submit", b"{}",
                                "application/json")
        self.assertEqual(code, 429)
        body = json.loads(body.decode())
        self.assertEqual(body["lane"], "unverified")
        self.assertIn("challenge_url", body)

    def test_unverified_lane_garbage_credential(self):
        import copy
        chain = copy.deepcopy(self.chain)
        bad = make_request(chain)
        bad["credential"]["signature"] = "00" * 64
        code, body = self._post("/agent-submit", json.dumps(bad).encode(),
                                "application/json")
        self.assertEqual(code, 429)
        self.assertEqual(json.loads(body.decode())["lane"], "unverified")

    def test_challenge_roundtrip(self):
        code, body = self._post("/agent-submit", b"{}",
                                "application/json")
        token = json.loads(body.decode())["challenge_url"].rsplit("/", 1)[-1]
        code, _ = self._post(f"/challenge/{token}",
                             f"token={token}&human=1".encode(),
                             "application/x-www-form-urlencoded")
        self.assertEqual(code, 200)


class TestPatternLimitKeys(unittest.TestCase):
    """Regression tests for the pattern-keyed limits fail-open (audit MEDIUM).

    Limit keys must be literal action types. allow/deny use fnmatch, but
    limits are enforced with an exact dict lookup, so a pattern key like
    "form.*" would silently throttle nothing. Issuance must fail loudly;
    verification of a hand-minted credential must fail closed.
    """

    def test_issue_credential_rejects_pattern_limit_key(self):
        p_priv, p_pub = generate_keypair()
        _, a_pub = generate_keypair()
        with self.assertRaises(ValueError) as ctx:
            issue_credential(
                principal_id="p", principal_priv_hex=p_priv,
                principal_pub_hex=p_pub, agent_id="a", agent_pub_hex=a_pub,
                scope={"allow": ["form.*"],
                        "limits": {"form.*": {"max_per_day": 1}}})
        self.assertIn("form.*", str(ctx.exception))

    def test_issue_delegation_rejects_pattern_limit_key(self):
        p_priv, p_pub = generate_keypair()
        _, a_pub = generate_keypair()
        with self.assertRaises(ValueError):
            issue_delegation(
                delegator_priv_hex=p_priv, delegator_pub_hex=p_pub,
                delegatee_pub_hex=a_pub,
                scope={"allow": ["form.*"],
                       "limits": {"form.?": {"max_per_day": 1}}})

    def test_literal_limit_keys_still_enforced(self):
        # Sanity: literal keys keep working and actually throttle.
        c = make_chain(scope_sub={"allow": ["form.submit"],
                                  "limits": {"form.submit":
                                             {"max_per_day": 1}}})
        day = time.strftime("%Y-%m-%d", time.gmtime())
        req = make_request(c)
        ok, reasons = verify_action_request(req, [c["p_pub"]], usage={})
        self.assertTrue(ok, reasons)
        usage = {(c["s_pub"], "form.submit", day): 1}
        req2 = make_request(c)
        ok, reasons = verify_action_request(req2, [c["p_pub"]], usage=usage)
        self.assertFalse(ok)
        self.assertTrue(any("rate limit" in r for r in reasons))

    def test_verify_fails_closed_on_pattern_limit_key(self):
        # A credential minted outside issue_credential() — hand-signed with
        # pattern limit keys — must be refused, not verified with no limits.
        import copy
        c = make_chain()
        cred = copy.deepcopy(c["cred"])
        cred["scope"]["limits"] = {"form.*": {"max_per_day": 1}}
        unsigned = {k: v for k, v in cred.items() if k != "signature"}
        cred["signature"] = ed25519.sign_hex(
            c["p_priv"], credentials.canonical(unsigned))
        req = make_request({**c, "cred": cred})
        ok, reasons = verify_action_request(req, [c["p_pub"]], usage={})
        self.assertFalse(ok)
        self.assertTrue(any("literal action types" in r for r in reasons))


class TestNonceTableCap(unittest.TestCase):
    """The nonce table is reserved *before* verification, so it must be
    bounded (audit MEDIUM): flooding fresh nonces must not grow memory
    without limit."""

    def test_nonce_table_is_bounded(self):
        import services.verifier.app as appmod
        state = appmod.VerifierState()
        state.MAX_NONCES = 64  # shrink for test speed; semantics unchanged
        now = time.time()
        for i in range(200):
            self.assertTrue(state.check_and_reserve(f"cap-n-{i}", now))
        self.assertLessEqual(len(state._nonces), 64)

    def test_oldest_evicted_first_and_replay_still_detected(self):
        import services.verifier.app as appmod
        state = appmod.VerifierState()
        state.MAX_NONCES = 8
        now = time.time()
        for i in range(8):
            self.assertTrue(state.check_and_reserve(f"evict-n-{i}", now))
        # Table full: the 9th insert evicts the oldest ("evict-n-0").
        self.assertTrue(state.check_and_reserve("evict-n-8", now))
        self.assertNotIn("evict-n-0", state._nonces)
        self.assertIn("evict-n-8", state._nonces)
        # Nonces still resident are still replay-protected.
        self.assertFalse(state.check_and_reserve("evict-n-8", now))
        self.assertFalse(state.check_and_reserve("evict-n-7", now))


if __name__ == "__main__":
    unittest.main()
