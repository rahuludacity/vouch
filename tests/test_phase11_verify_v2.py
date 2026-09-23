"""Phase 11 tests: delegation issuance extensions + verification v2.

Covers:
  11a. issue_delegation / issue_credential — short-lived delegation
       defaults (ttl 3600), revocation_handle issuance, spending-ceiling
       limit validation at issuance.
  11b. verify_action_request_v2 — the PRD fail-closed check order, one
       test per position, plus the tier policy hook.
  11c. Receipt enrollment fields — evidence block contents on the happy
       path, and app.py wiring (manifest from file, corrupted manifest
       denies, v1 path untouched when VOUCH_MANIFEST_PATH is unset).
"""
import copy
import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from services.verifier import credentials  # noqa: E402
from services.verifier import enrollment  # noqa: E402
from services.verifier.credentials import (  # noqa: E402
    generate_keypair, issue_delegation, issue_credential,
    sign_action_request, verify_action_request_v2, default_tier_policy)
from services.verifier.enrollment import (  # noqa: E402
    TransparencyLog, build_manifest, jwk_thumbprint)

_RH_RE = re.compile(r"^rh-[0-9a-f]{12}$")


class World:
    """A complete enrolled world: operator, principal, agent, chain."""

    def __init__(self, tier="allowlist", scope=None, expires_in=90 * 86400,
                 n_links=1):
        self.op_priv, self.op_pub = generate_keypair()
        self.p_priv, self.p_pub = generate_keypair()
        self.a_priv, self.a_pub = generate_keypair()
        self.s_priv, self.s_pub = generate_keypair()
        self.tmp = tempfile.mkdtemp(prefix="vouch-p11-")
        self.log = TransparencyLog(os.path.join(self.tmp, "t.jsonl"))
        now = time.time()
        self.log.append(
            "enroll",
            {"principal_id": "p1", "tier": tier,
             "domain": "example.com" if tier == "domain-control" else None,
             "keys": [{"key_id": jwk_thumbprint(self.p_pub),
                       "pubkey": self.p_pub, "label": "prod"}],
             "enrolled_at": now, "expires_at": now + expires_in},
            self.op_priv)
        self.scope = scope or {
            "allow": ["pay.*"],
            "limits": {"pay.x": {"max_per_day": 100,
                                 "max_spend_per_day": 10000}},
        }
        links = []
        prev_priv, prev_pub = self.p_priv, self.p_pub
        for i in range(n_links):
            nxt_pub = self.a_pub if i == n_links - 1 else self.s_pub
            link = issue_delegation(
                delegator_priv_hex=prev_priv, delegator_pub_hex=prev_pub,
                delegatee_pub_hex=nxt_pub, scope={"allow": ["pay.*"]})
            links.append(link)
            prev_priv, prev_pub = ((self.a_priv, self.a_pub)
                                  if i == 0 else (self.s_priv, self.s_pub))
        self.link = links[0]
        agent_priv, agent_pub = ((self.a_priv, self.a_pub)
                                if n_links == 1
                                else (self.s_priv, self.s_pub))
        self.agent_priv, self.agent_pub = agent_priv, agent_pub
        self.cred = issue_credential(
            principal_id="p1", principal_priv_hex=self.p_priv,
            principal_pub_hex=self.p_pub, agent_id="bot",
            agent_pub_hex=agent_pub, scope=self.scope, delegations=links)

    def manifest(self, **kw):
        kw.setdefault("valid_for_s", 3600)
        return build_manifest(log=self.log,
                              operator_priv_hex=self.op_priv,
                              operator_pubkey=self.op_pub, **kw)

    def append_log(self, event_type, payload):
        self.log.append(event_type, payload, self.op_priv)

    def request(self, action_type="pay.x", amount_cents=None, nonce=None,
                ts=None, priv=None, tamper_cred=None):
        action = {"type": action_type, "target": "/x"}
        if amount_cents is not None:
            action["amount_cents"] = amount_cents
        env = sign_action_request(
            agent_priv_hex=priv or self.agent_priv,
            credential_id=self.cred["credential_id"],
            action=action, nonce=nonce, ts=ts)
        cred = copy.deepcopy(self.cred)
        if tamper_cred:
            tamper_cred(cred)
        return {"tenant_id": "t", "credential": cred,
                "action": env["action"], "nonce": env["nonce"],
                "ts": env["ts"], "agent_signature": env["agent_signature"]}

    def verify(self, req, **kw):
        kw.setdefault("manifest", self.manifest())
        kw.setdefault("operator_pubkeys", self.op_pub)
        kw.setdefault("nonces", set())
        kw.setdefault("usage", {})
        kw.setdefault("spending", {})
        return verify_action_request_v2(req, **kw)


def _day(now=None):
    return time.strftime("%Y-%m-%d", time.gmtime(now or time.time()))


# ------------------------------------------------------------------ 11a
class TestIssuanceExtensions(unittest.TestCase):
    def test_delegation_default_ttl_is_3600(self):
        p_priv, p_pub = generate_keypair()
        _, a_pub = generate_keypair()
        link = issue_delegation(delegator_priv_hex=p_priv,
                               delegator_pub_hex=p_pub,
                               delegatee_pub_hex=a_pub,
                               scope={"allow": ["pay.*"]})
        self.assertAlmostEqual(link["expires_at"] - link["issued_at"],
                               3600, places=2)

    def test_revocation_handle_default_format_and_unique(self):
        p_priv, p_pub = generate_keypair()
        _, a_pub = generate_keypair()
        kw = dict(delegator_priv_hex=p_priv, delegator_pub_hex=p_pub,
                  delegatee_pub_hex=a_pub, scope={"allow": ["pay.*"]})
        h1 = issue_delegation(**kw)["revocation_handle"]
        h2 = issue_delegation(**kw)["revocation_handle"]
        self.assertTrue(_RH_RE.match(h1), h1)
        self.assertTrue(_RH_RE.match(h2), h2)
        self.assertNotEqual(h1, h2)

    def test_revocation_handle_explicit_honored(self):
        p_priv, p_pub = generate_keypair()
        _, a_pub = generate_keypair()
        link = issue_delegation(
            delegator_priv_hex=p_priv, delegator_pub_hex=p_pub,
            delegatee_pub_hex=a_pub, scope={"allow": ["pay.*"]},
            revocation_handle="rh-deadbeefcafe")
        self.assertEqual(link["revocation_handle"], "rh-deadbeefcafe")

    def test_credential_default_ttl_unchanged(self):
        p_priv, p_pub = generate_keypair()
        _, a_pub = generate_keypair()
        link = issue_delegation(delegator_priv_hex=p_priv,
                               delegator_pub_hex=p_pub,
                               delegatee_pub_hex=a_pub,
                               scope={"allow": ["pay.*"]})
        cred = issue_credential(
            principal_id="p", principal_priv_hex=p_priv,
            principal_pub_hex=p_pub, agent_id="a", agent_pub_hex=a_pub,
            scope={"allow": ["pay.*"]}, delegations=[link])
        self.assertAlmostEqual(cred["expires_at"] - cred["issued_at"],
                               86400, places=2)
        self.assertTrue(_RH_RE.match(cred["revocation_handle"]))

    def test_credential_explicit_revocation_handle_honored(self):
        w = World()
        self.assertTrue(_RH_RE.match(w.cred["revocation_handle"]))
        # custom handle survives into the signed credential
        cred = issue_credential(
            principal_id="p1", principal_priv_hex=w.p_priv,
            principal_pub_hex=w.p_pub, agent_id="b", agent_pub_hex=w.a_pub,
            scope={"allow": ["pay.*"]}, delegations=[w.link],
            revocation_handle="rh-001122334455")
        self.assertEqual(cred["revocation_handle"], "rh-001122334455")

    def test_negative_limit_values_rejected_at_issuance(self):
        p_priv, p_pub = generate_keypair()
        _, a_pub = generate_keypair()
        for limits in ({"pay.x": {"max_per_day": -1}},
                       {"pay.x": {"max_spend_per_day": -5}}):
            with self.assertRaises(ValueError, msg=str(limits)):
                issue_delegation(
                    delegator_priv_hex=p_priv, delegator_pub_hex=p_pub,
                    delegatee_pub_hex=a_pub,
                    scope={"allow": ["pay.*"], "limits": limits})
            link = issue_delegation(
                delegator_priv_hex=p_priv, delegator_pub_hex=p_pub,
                delegatee_pub_hex=a_pub, scope={"allow": ["pay.*"]})
            with self.assertRaises(ValueError, msg=str(limits)):
                issue_credential(
                    principal_id="p", principal_priv_hex=p_priv,
                    principal_pub_hex=p_pub, agent_id="a",
                    agent_pub_hex=a_pub,
                    scope={"allow": ["pay.*"], "limits": limits},
                    delegations=[link])

    def test_nonint_limit_values_rejected_at_issuance(self):
        p_priv, p_pub = generate_keypair()
        _, a_pub = generate_keypair()
        for bad in (1.5, "10", True, None):
            limits = {"pay.x": {"max_spend_per_day": bad}}
            with self.assertRaises(ValueError, msg=repr(bad)):
                issue_delegation(
                    delegator_priv_hex=p_priv, delegator_pub_hex=p_pub,
                    delegatee_pub_hex=a_pub,
                    scope={"allow": ["pay.*"], "limits": limits})

    def test_zero_limit_values_allowed(self):
        p_priv, p_pub = generate_keypair()
        _, a_pub = generate_keypair()
        link = issue_delegation(
            delegator_priv_hex=p_priv, delegator_pub_hex=p_pub,
            delegatee_pub_hex=a_pub,
            scope={"allow": ["pay.*"],
                   "limits": {"pay.x": {"max_per_day": 0,
                                        "max_spend_per_day": 0}}})
        self.assertEqual(link["scope"]["limits"]["pay.x"]["max_per_day"], 0)


# ------------------------------------------------------- 11b check order
class TestVerifyV2CheckOrder(unittest.TestCase):
    # -- 1. manifest -------------------------------------------------
    def test_manifest_none_is_unavailable(self):
        w = World()
        ok, reasons, ev = w.verify(w.request(), manifest=None)
        self.assertFalse(ok)
        self.assertEqual(reasons, ["trust root unavailable"])
        self.assertEqual(ev, {})

    def test_stale_manifest_denies_even_with_perfect_credential(self):
        w = World()
        stale = w.manifest(valid_for_s=1, issued_at=time.time() - 3600)
        ok, reasons, _ = w.verify(w.request(), manifest=stale)
        self.assertFalse(ok)
        self.assertTrue(reasons[0].startswith("trust root stale:"),
                        reasons)
        self.assertIn("expired at", reasons[0])

    def test_manifest_bad_signature_denies(self):
        w = World()
        m = w.manifest()
        m["version"] = 999  # tamper after signing
        ok, reasons, _ = w.verify(w.request(), manifest=m)
        self.assertFalse(ok)
        self.assertTrue(reasons[0].startswith("trust root stale:"),
                        reasons)

    def test_check_order_stale_manifest_beats_revoked_key(self):
        w = World()
        kid = jwk_thumbprint(w.p_pub)
        w.append_log("revoke-key", {"principal_id": "p1", "key_id": kid,
                                   "revoked_at": time.time(),
                                   "reason": "order test"})
        stale = w.manifest(valid_for_s=1, issued_at=time.time() - 3600)
        ok, reasons, _ = w.verify(w.request(), manifest=stale)
        self.assertFalse(ok)
        self.assertTrue(reasons[0].startswith("trust root stale:"),
                        reasons)

    # -- 2. principal / key status -----------------------------------
    def test_unknown_principal(self):
        w = World()
        req = w.request(tamper_cred=lambda c: c.update(
            {"principal": {"id": "nobody", "pubkey": w.p_pub}}))
        # re-sign so the failure is genuinely the enrollment lookup, not
        # the signature check (check 2 runs before check 3)
        c0 = req["credential"]
        c0["signature"] = credentials.ed25519.sign_hex(
            w.p_priv, credentials.canonical(credentials._unsigned(c0)))
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok)
        self.assertEqual(reasons, ["principal not enrolled"])

    def test_revoked_key(self):
        w = World()
        w.append_log("revoke-key",
                     {"principal_id": "p1",
                      "key_id": jwk_thumbprint(w.p_pub),
                      "revoked_at": time.time(), "reason": "compromised"})
        ok, reasons, _ = w.verify(w.request())
        self.assertFalse(ok)
        self.assertEqual(reasons, ["key revoked"])

    def test_suspended_principal(self):
        w = World()
        w.append_log("suspend", {"principal_id": "p1",
                                "suspended_at": time.time(),
                                "reason": "fraud review"})
        ok, reasons, _ = w.verify(w.request())
        self.assertFalse(ok)
        self.assertEqual(reasons, ["principal suspended"])

    def test_expired_enrollment(self):
        w = World(expires_in=-10)  # enrollment already expired
        ok, reasons, _ = w.verify(w.request())
        self.assertFalse(ok)
        self.assertEqual(reasons, ["enrollment expired"])

    def test_revoked_credential_handle(self):
        w = World()
        w.append_log("revoke-credential",
                     {"revocation_handle": w.cred["revocation_handle"]})
        ok, reasons, _ = w.verify(w.request())
        self.assertFalse(ok)
        self.assertEqual(reasons, ["credential revoked"])

    # -- 3. credential signature --------------------------------------
    def test_bad_credential_signature(self):
        w = World()
        req = w.request(tamper_cred=lambda c: c.__setitem__(
            "scope", {"allow": ["*"], "deny": [], "limits": {}}))
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok)
        self.assertEqual(reasons, ["credential signature invalid"])

    # -- 4. delegation chain -------------------------------------------
    def test_chain_continuity_break_denies(self):
        w = World(n_links=2)
        # link0: p -> x ; link1: a -> s (signed fine, but a != x)
        x_priv, x_pub = generate_keypair()
        link0 = issue_delegation(
            delegator_priv_hex=w.p_priv, delegator_pub_hex=w.p_pub,
            delegatee_pub_hex=x_pub, scope={"allow": ["pay.*"]})
        link1 = issue_delegation(
            delegator_priv_hex=w.a_priv, delegator_pub_hex=w.a_pub,
            delegatee_pub_hex=w.s_pub, scope={"allow": ["pay.*"]})
        w.cred = issue_credential(
            principal_id="p1", principal_priv_hex=w.p_priv,
            principal_pub_hex=w.p_pub, agent_id="sub", agent_pub_hex=w.s_pub,
            scope={"allow": ["pay.*"]}, delegations=[link0, link1])
        ok, reasons, _ = w.verify(w.request(priv=w.s_priv))
        self.assertFalse(ok)
        self.assertTrue(any("chain continuity broken" in r
                            for r in reasons), reasons)

    # -- 5. scope + tier policy ----------------------------------------
    def test_scope_deny(self):
        w = World()
        ok, reasons, _ = w.verify(w.request(action_type="admin.wipe"))
        self.assertFalse(ok)
        self.assertEqual(reasons,
                         ["action 'admin.wipe' outside authorized scope"])

    def test_tier_policy_deny(self):
        w = World()
        hook = default_tier_policy({"pay.*": "domain-control"})
        ok, reasons, _ = w.verify(w.request(), policy_hook=hook)
        self.assertFalse(ok)
        self.assertEqual(
            reasons, ["action 'pay.x' requires domain-control enrollment"])

    def test_tier_policy_allows_when_met(self):
        w = World(tier="domain-control")
        hook = default_tier_policy({"pay.*": "domain-control"})
        ok, reasons, ev = w.verify(w.request(), policy_hook=hook)
        self.assertTrue(ok, reasons)
        self.assertEqual(ev["principal_tier"], "domain-control")
        self.assertEqual(ev["tier_policy"], {"pay.*": "domain-control"})

    def test_hook_exception_denies_never_allows(self):
        w = World()

        def boom(tier, action_type):
            raise RuntimeError("policy store down")

        ok, reasons, _ = w.verify(w.request(), policy_hook=boom)
        self.assertFalse(ok)
        self.assertTrue(reasons, "a hook error must deny, never allow")

    def test_unknown_tier_in_policy_config_denies(self):
        w = World()
        hook = default_tier_policy({"pay.*": "kyc"})
        ok, reasons, _ = w.verify(w.request(), policy_hook=hook)
        self.assertFalse(ok)
        self.assertIn("misconfigured", reasons[0])

    # -- 6. timestamp + replay ------------------------------------------
    def test_timestamp_skew(self):
        w = World()
        ok, reasons, _ = w.verify(w.request(ts=time.time() - 3600))
        self.assertFalse(ok)
        self.assertEqual(reasons, ["request timestamp outside tolerance"])

    def test_replay(self):
        w = World()
        req = w.request()
        ok, reasons, _ = w.verify(req, nonces={req["nonce"]})
        self.assertFalse(ok)
        self.assertEqual(reasons, ["replayed request"])

    # -- 7. proof of possession ------------------------------------------
    def test_bad_agent_signature(self):
        w = World()
        evil_priv, _ = generate_keypair()
        ok, reasons, _ = w.verify(w.request(priv=evil_priv))
        self.assertFalse(ok)
        self.assertEqual(
            reasons, ["agent signature invalid (not the credential holder?)"])

    # -- 8. limits --------------------------------------------------------
    def test_rate_limit_exceeded(self):
        w = World()
        day = _day()
        usage = {(w.agent_pub, "pay.x", day): 100}
        ok, reasons, _ = w.verify(w.request(), usage=usage)
        self.assertFalse(ok)
        self.assertEqual(
            reasons, ["rate limit exceeded: 100/100 pay.x/day"])

    def test_spending_under_ceiling_allows(self):
        w = World()
        day = _day()
        spending = {(w.cred["credential_id"], "pay.x", day): 9900}
        ok, reasons, _ = w.verify(
            w.request(amount_cents=100), spending=spending)
        self.assertTrue(ok, reasons)

    def test_spending_over_ceiling_denies(self):
        w = World()
        day = _day()
        spending = {(w.cred["credential_id"], "pay.x", day): 9900}
        ok, reasons, _ = w.verify(
            w.request(amount_cents=200), spending=spending)
        self.assertFalse(ok)
        self.assertEqual(len(reasons), 1)
        self.assertTrue(
            reasons[0].startswith("spending ceiling exceeded:"), reasons)

    def test_action_without_amount_consumes_no_spend(self):
        w = World()
        day = _day()
        # ceiling already fully used, but no amount_cents -> allowed
        spending = {(w.cred["credential_id"], "pay.x", day): 10000}
        ok, reasons, _ = w.verify(w.request(), spending=spending)
        self.assertTrue(ok, reasons)

    def test_negative_amount_denies(self):
        w = World()
        # hand-craft: sign_action_request would just sign the value, so
        # build the envelope manually with a negative amount
        req = w.request()
        action = dict(req["action"])
        action["amount_cents"] = -5
        env = sign_action_request(
            agent_priv_hex=w.agent_priv,
            credential_id=w.cred["credential_id"], action=action,
            nonce=req["nonce"], ts=req["ts"])
        req.update({"action": env["action"],
                    "agent_signature": env["agent_signature"]})
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok)
        self.assertIn("amount_cents", reasons[0])

    def test_malformed_credential_denies_closed(self):
        w = World()
        req = w.request(tamper_cred=lambda c: c.clear())
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok)
        self.assertTrue(reasons)

    # -- happy path + evidence ---------------------------------------------
    def test_happy_path_evidence_fields(self):
        w = World()
        manifest = w.manifest()
        hook = default_tier_policy({"pay.*": "allowlist"})
        ok, reasons, ev = w.verify(w.request(), manifest=manifest,
                                   policy_hook=hook)
        self.assertTrue(ok, reasons)
        self.assertEqual(ev["principal_id"], "p1")
        self.assertEqual(ev["principal_tier"], "allowlist")
        self.assertEqual(ev["key_id"], jwk_thumbprint(w.p_pub))
        self.assertEqual(ev["enrollment_log_seq"], 1)
        self.assertEqual(ev["manifest_version"], manifest["version"])
        self.assertEqual(ev["manifest_valid_until"],
                         manifest["valid_until"])
        self.assertEqual(ev["tier_policy"], {"pay.*": "allowlist"})

    def test_evidence_tier_policy_none_without_hook(self):
        w = World()
        ok, reasons, ev = w.verify(w.request(), policy_hook=None)
        self.assertTrue(ok, reasons)
        self.assertIsNone(ev["tier_policy"])


# ------------------------------------------------------------ app wiring
def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestVerifierAppV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="vouch-p11-app-")
        tenants = os.path.join(cls.tmp, "tenants.json")
        with open(tenants, "w", encoding="utf-8") as f:
            json.dump({"tenants": {"t":
                                   {"created_at": 1,
                                    "keys": {"k1": "ab" * 32},
                                    "current_kid": "k1"}}}, f)
        os.environ["VERIFIER_TENANTS_PATH"] = tenants
        os.environ["VERIFIER_RECEIPTS_PATH"] = os.path.join(
            cls.tmp, "transparency.jsonl")
        os.environ["RECEIPT_SVC_URL"] = ""
        import services.verifier.app as appmod
        cls.app = appmod
        from gatekeeper.tenants import TenantRegistry
        from gatekeeper.receipts import ReceiptLog
        from gatekeeper.ingest import ReceiptEmitter
        registry = TenantRegistry(tenants)
        appmod.EMITTER = ReceiptEmitter(
            registry, ReceiptLog(os.path.join(cls.tmp, "transparency.jsonl"),
                                 registry), svc_url="")
        # Spy on emit: receipts only store args_sha256 in the log file, so
        # capture the raw args here to assert the vouch_enrollment block.
        cls._orig_emitter = appmod.EMITTER
        cls.emitted = []
        orig_emit = appmod.EMITTER.emit

        def spy(**kw):
            cls.emitted.append(kw)
            return orig_emit(**kw)

        appmod.EMITTER.emit = spy
        # v2 wiring: manifest file + operator keys + tier policy
        cls.world = World()
        cls.manifest_path = os.path.join(cls.tmp, "manifest.json")
        with open(cls.manifest_path, "w", encoding="utf-8") as f:
            json.dump(cls.world.manifest(), f)
        cls._saved = (appmod.MANIFEST_PATH, appmod.OPERATOR_PUBKEYS,
                      appmod.MIN_TIERS, appmod.TRUSTED_ISSUERS,
                      appmod.PRINCIPAL_DAILY_LIMIT)
        appmod.MANIFEST_PATH = cls.manifest_path
        appmod.OPERATOR_PUBKEYS = [cls.world.op_pub]
        appmod.MIN_TIERS = {}
        appmod.TRUSTED_ISSUERS = []
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
        (cls.app.MANIFEST_PATH, cls.app.OPERATOR_PUBKEYS,
         cls.app.MIN_TIERS, cls.app.TRUSTED_ISSUERS,
         cls.app.PRINCIPAL_DAILY_LIMIT) = cls._saved
        cls.app.EMITTER = cls._orig_emitter

    def setUp(self):
        self.app.STATE = self.app.VerifierState()
        self.app.MANIFEST_PATH = self.manifest_path
        self.app.OPERATOR_PUBKEYS = [self.world.op_pub]
        self.app.MIN_TIERS = {}
        self.__class__.emitted.clear()

    def tearDown(self):
        self.app.MIN_TIERS = {}

    def post_verify(self, body):
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            self.base + "/v1/verify", data=data,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())

    def last_receipt_args(self):
        self.assertTrue(self.emitted, "expected at least one emitted receipt")
        return self.emitted[-1]["args"]

    def test_v2_allow_and_receipt_has_enrollment(self):
        req = self.world.request()
        code, body = self.post_verify(req)
        self.assertEqual(code, 200)
        self.assertEqual(body["decision"], "allow")
        self.assertEqual(body["lane"], "verified-agent")
        args = self.last_receipt_args()
        self.assertIn("vouch_enrollment", args)
        ev = args["vouch_enrollment"]
        for field in ("principal_id", "principal_tier", "key_id",
                      "enrollment_log_seq", "manifest_version",
                      "manifest_valid_until", "tier_policy"):
            self.assertIn(field, ev, field)
        self.assertEqual(ev["principal_id"], "p1")
        self.assertEqual(ev["principal_tier"], "allowlist")
        self.assertEqual(ev["key_id"], jwk_thumbprint(self.world.p_pub))

    def test_v2_corrupted_manifest_denies(self):
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            f.write("{not json")
        try:
            code, body = self.post_verify(self.world.request())
            self.assertEqual(code, 200)
            self.assertEqual(body["decision"], "deny")
            self.assertTrue(body["reason"].startswith("trust root stale"),
                            body["reason"])
        finally:
            with open(self.manifest_path, "w", encoding="utf-8") as f:
                json.dump(self.world.manifest(), f)

    def test_v2_replay_denied(self):
        req = self.world.request(nonce="p11-replay-1")
        _, b1 = self.post_verify(req)
        self.assertEqual(b1["decision"], "allow")
        _, b2 = self.post_verify(req)
        self.assertEqual(b2["decision"], "deny")
        self.assertIn("replayed request", b2["reason"])

    def test_v2_spending_ceiling_end_to_end(self):
        # ceiling is 10000 cents in the world scope
        _, b1 = self.post_verify(self.world.request(amount_cents=6000))
        self.assertEqual(b1["decision"], "allow")
        _, b2 = self.post_verify(self.world.request(amount_cents=5000))
        self.assertEqual(b2["decision"], "deny")
        self.assertIn("spending ceiling exceeded", b2["reason"])

    def test_v2_tier_policy_deny(self):
        self.app.MIN_TIERS = {"pay.*": "domain-control"}
        code, body = self.post_verify(self.world.request())
        self.assertEqual(code, 200)
        self.assertEqual(body["decision"], "deny")
        self.assertIn("requires domain-control", body["reason"])

    def test_v1_path_unchanged_without_manifest_path(self):
        # No MANIFEST_PATH -> the old v1 trusted-issuers path, and the
        # receipt carries no vouch_enrollment block.
        self.app.MANIFEST_PATH = ""
        self.app.TRUSTED_ISSUERS = [self.world.p_pub]
        code, body = self.post_verify(self.world.request())
        self.assertEqual(code, 200)
        self.assertEqual(body["decision"], "allow")
        args = self.last_receipt_args()
        self.assertNotIn("vouch_enrollment", args)


class TestCheckAndAddSpendingAtomic(unittest.TestCase):
    def test_atomic_check_and_add(self):
        import services.verifier.app as appmod
        state = appmod.VerifierState()
        day = _day()
        ok, used = state.check_and_add_spending("c1", "pay.x", day, 600, 1000)
        self.assertTrue(ok)
        self.assertEqual(used, 600)
        ok, used = state.check_and_add_spending("c1", "pay.x", day, 500, 1000)
        self.assertFalse(ok)  # 600 + 500 > 1000 -> nothing added
        self.assertEqual(used, 600)
        self.assertEqual(state.spending_used("c1", "pay.x", day), 600)

    def test_concurrent_adds_cannot_breach_ceiling(self):
        import services.verifier.app as appmod
        state = appmod.VerifierState()
        day = _day()
        results = []

        def worker():
            for _ in range(50):
                ok, _ = state.check_and_add_spending(
                    "c1", "pay.x", day, 10, 1000)
                results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        total = state.spending_used("c1", "pay.x", day)
        self.assertLessEqual(total, 1000,
                             "ceiling must hold under concurrency")


if __name__ == "__main__":
    unittest.main()
