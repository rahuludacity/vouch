"""H-3: delegation modes read/prepare/execute + signed principal approval
+ scope catalog.

Security-property tests hand-mint mode-carrying credentials with stable
pre-fix API (dict injection + re-sign), so `git stash` of the fix makes
them FAIL (the attack verifies) rather than error at import. Issuance
tests use the new kwargs and fail without the fix as errors.
"""
import copy
import os
import tempfile
import time
import unittest

from services.verifier import credentials as credmod
from services.verifier import ed25519
from services.verifier.credentials import (
    canonical, generate_keypair, issue_credential, issue_delegation,
    sign_action_request, verify_action_request, verify_action_request_v2)
from services.verifier.enrollment import (
    TransparencyLog, build_manifest, jwk_thumbprint)


def _resign_link(link, priv):
    link = dict(link)
    unsigned = {k: v for k, v in link.items() if k != "signature"}
    link["signature"] = ed25519.sign_hex(priv, canonical(unsigned))
    return link


def _resign_cred(cred, priv):
    cred = dict(cred)
    unsigned = {k: v for k, v in cred.items() if k != "signature"}
    cred["signature"] = ed25519.sign_hex(priv, canonical(unsigned))
    return cred


def _mint_approval(priv, credential_id, action, nonce="appr-nonce-1",
                   ttl_s=900, now=None):
    """Hand-minted principal approval (stable primitives only)."""
    now = round(time.time(), 3) if now is None else now
    appr = {"credential_id": credential_id,
            "action": copy.deepcopy(action),
            "nonce": nonce,
            "issued_at": now,
            "expires_at": round(now + ttl_s, 3)}
    unsigned = {k: v for k, v in appr.items() if k != "signature"}
    appr["signature"] = ed25519.sign_hex(priv, canonical(unsigned))
    return appr


class ModeWorld:
    """Minimal enrolled world for v2 mode tests (stable API only)."""

    def __init__(self):
        self.op_priv, self.op_pub = generate_keypair()
        self.p_priv, self.p_pub = generate_keypair()
        self.a_priv, self.a_pub = generate_keypair()
        self.tmp = tempfile.mkdtemp(prefix="vouch-h3-")
        self.log = TransparencyLog(os.path.join(self.tmp, "t.jsonl"))
        now = time.time()
        self.log.append(
            "enroll",
            {"principal_id": "p", "tier": "allowlist", "domain": None,
             "keys": [{"key_id": jwk_thumbprint(self.p_pub),
                       "pubkey": self.p_pub, "label": "t"}],
             "enrolled_at": now, "expires_at": now + 90 * 86400},
            self.op_priv)

    def manifest(self):
        return build_manifest(log=self.log,
                              operator_priv_hex=self.op_priv,
                              operator_pubkey=self.op_pub, valid_for_s=3600)

    def credential(self, mode, scope, link_mode=None):
        """Hand-minted mode-carrying credential (works with/without fix)."""
        link = issue_delegation(
            delegator_priv_hex=self.p_priv, delegator_pub_hex=self.p_pub,
            delegatee_pub_hex=self.a_pub, scope=scope)
        if link_mode != "SKIP":
            link = dict(link)
            link["mode"] = link_mode if link_mode is not None else mode
            link = _resign_link(link, self.p_priv)
        cred = issue_credential(
            principal_id="p", principal_priv_hex=self.p_priv,
            principal_pub_hex=self.p_pub, agent_id="a",
            agent_pub_hex=self.a_pub, scope=scope, delegations=[link])
        cred = dict(cred)
        cred["mode"] = mode
        return _resign_cred(cred, self.p_priv)

    def request(self, cred, action, approval=None):
        env = sign_action_request(agent_priv_hex=self.a_priv,
                                  credential_id=cred["credential_id"],
                                  action=action)
        req = {"credential": cred, "action": env["action"],
               "nonce": env["nonce"], "ts": env["ts"],
               "agent_signature": env["agent_signature"]}
        if approval is not None:
            req["principal_approval"] = approval
        return req

    def verify(self, req, **kw):
        kw.setdefault("manifest", self.manifest())
        kw.setdefault("operator_pubkeys", [self.op_pub])
        kw.setdefault("now", time.time())
        kw.setdefault("nonces", set())
        kw.setdefault("approval_nonces", set())
        return verify_action_request_v2(req, **kw)


MSG_SCOPE = {"allow": ["messaging.draft", "messaging.send"]}


class TestModeIssuance(unittest.TestCase):
    """Issuance-time validation (new kwargs; fail without fix as errors)."""

    def setUp(self):
        self.p_priv, self.p_pub = generate_keypair()
        _, self.a_pub = generate_keypair()

    def _link(self, **kw):
        kw.setdefault("scope", {"allow": ["payments.*"]})
        return issue_delegation(delegator_priv_hex=self.p_priv,
                                delegator_pub_hex=self.p_pub,
                                delegatee_pub_hex=self.a_pub, **kw)

    def test_unknown_mode_rejected_at_credential_issuance(self):
        with self.assertRaises(ValueError):
            issue_credential(
                principal_id="p", principal_priv_hex=self.p_priv,
                principal_pub_hex=self.p_pub, agent_id="a",
                agent_pub_hex=self.a_pub,
                scope={"allow": ["payments.execute"]},
                delegations=[self._link(mode="execute")], mode="turbo")

    def test_unknown_mode_rejected_at_delegation_issuance(self):
        with self.assertRaises(ValueError):
            self._link(mode="turbo")

    def test_unknown_scope_rejected_at_issuance(self):
        with self.assertRaises(ValueError) as ctx:
            issue_credential(
                principal_id="p", principal_priv_hex=self.p_priv,
                principal_pub_hex=self.p_pub, agent_id="a",
                agent_pub_hex=self.a_pub, scope={"allow": ["pay.*"]},
                delegations=[self._link()], mode="execute")
        self.assertIn("pay.*", str(ctx.exception))

    def test_unknown_scope_rejected_at_delegation_issuance(self):
        with self.assertRaises(ValueError):
            self._link(mode="execute",
                       scope={"allow": ["pay.*"]})

    def test_catalog_pattern_scope_accepted(self):
        link = self._link(mode="execute",
                          scope={"allow": ["payments.*"]})
        self.assertEqual(link["mode"], "execute")

    def test_delegation_escalation_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._link(mode="execute", parent_mode="read")
        self.assertIn("escalation", str(ctx.exception))

    def test_delegation_deescalation_accepted(self):
        link = self._link(mode="prepare", parent_mode="execute")
        self.assertEqual(link["mode"], "prepare")

    def test_credential_escalation_rejected(self):
        link = self._link(mode="read",
                          scope={"allow": ["payments.execute"]})
        with self.assertRaises(ValueError) as ctx:
            issue_credential(
                principal_id="p", principal_priv_hex=self.p_priv,
                principal_pub_hex=self.p_pub, agent_id="a",
                agent_pub_hex=self.a_pub,
                scope={"allow": ["payments.execute"]},
                delegations=[link], mode="execute")
        self.assertIn("exceeds", str(ctx.exception))

    def test_credential_mode_over_modeless_link_rejected(self):
        link = self._link(scope={"allow": ["payments.execute"]})
        with self.assertRaises(ValueError) as ctx:
            issue_credential(
                principal_id="p", principal_priv_hex=self.p_priv,
                principal_pub_hex=self.p_pub, agent_id="a",
                agent_pub_hex=self.a_pub,
                scope={"allow": ["payments.execute"]},
                delegations=[link], mode="read")
        self.assertIn("re-issue the chain", str(ctx.exception))

    def test_mode_deescalation_chain_accepted(self):
        link = self._link(mode="execute",
                          scope={"allow": ["payments.execute"]})
        cred = issue_credential(
            principal_id="p", principal_priv_hex=self.p_priv,
            principal_pub_hex=self.p_pub, agent_id="a",
            agent_pub_hex=self.a_pub,
            scope={"allow": ["payments.execute"]},
            delegations=[link], mode="prepare")
        self.assertEqual(cred["mode"], "prepare")

    def test_legacy_issuance_unchanged(self):
        # No mode anywhere: exactly the old behavior, catalog not consulted.
        link = self._link(scope={"allow": ["pay.*"]})
        cred = issue_credential(
            principal_id="p", principal_priv_hex=self.p_priv,
            principal_pub_hex=self.p_pub, agent_id="a",
            agent_pub_hex=self.a_pub, scope={"allow": ["pay.*"]},
            delegations=[link])
        self.assertIsNone(cred.get("mode"))


class TestModeVerification(unittest.TestCase):
    """v2 check-order mode enforcement (assertion failures without fix)."""

    def test_unknown_mode_denied(self):
        w = ModeWorld()
        cred = w.credential("turbo", MSG_SCOPE)
        req = w.request(cred, {"type": "messaging.draft"})
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok, "unknown mode verified: fail-closed broken")
        self.assertTrue(any("unknown delegation mode" in r
                            for r in reasons), reasons)

    def test_legacy_credential_unaffected(self):
        w = ModeWorld()
        cred = w.credential(None, {"allow": ["pay.*"]}, link_mode="SKIP")
        cred = dict(cred)
        cred.pop("mode", None)  # fully modeless (pop: works with/without fix)
        cred = _resign_cred(cred, w.p_priv)
        req = w.request(cred, {"type": "pay.x"})
        ok, reasons, _ = w.verify(req)
        self.assertTrue(ok, reasons)

    def test_read_mode_allows_read(self):
        w = ModeWorld()
        cred = w.credential("read", {"allow": ["inbox.read"]})
        req = w.request(cred, {"type": "inbox.read"})
        ok, reasons, _ = w.verify(req)
        self.assertTrue(ok, reasons)

    def test_read_mode_denies_send(self):
        w = ModeWorld()
        cred = w.credential("read", MSG_SCOPE)
        req = w.request(cred, {"type": "messaging.send"})
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok)
        self.assertTrue(any("does not authorize" in r for r in reasons),
                        reasons)

    def test_read_mode_denies_draft(self):
        w = ModeWorld()
        cred = w.credential("read", MSG_SCOPE)
        req = w.request(cred, {"type": "messaging.draft"})
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok)
        self.assertTrue(any("does not authorize" in r for r in reasons),
                        reasons)

    def test_prepare_draft_without_approval(self):
        w = ModeWorld()
        cred = w.credential("prepare", MSG_SCOPE)
        req = w.request(cred, {"type": "messaging.draft",
                               "body": "hello"})
        ok, reasons, _ = w.verify(req)
        self.assertTrue(ok, reasons)

    def test_prepare_effect_without_approval_denied(self):
        w = ModeWorld()
        cred = w.credential("prepare", MSG_SCOPE)
        req = w.request(cred, {"type": "messaging.send",
                               "to": "a@b.c"})
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok, "prepare+send without approval verified")
        self.assertTrue(any("requires a signed principal approval" in r
                            for r in reasons), reasons)

    def test_prepare_effect_with_valid_approval(self):
        w = ModeWorld()
        cred = w.credential("prepare", MSG_SCOPE)
        action = {"type": "messaging.send", "to": "a@b.c",
                  "body": "hello"}
        appr = _mint_approval(w.p_priv, cred["credential_id"], action)
        req = w.request(cred, action, approval=appr)
        ok, reasons, _ = w.verify(req)
        self.assertTrue(ok, reasons)

    def test_prepare_forged_approval_denied(self):
        w = ModeWorld()
        cred = w.credential("prepare", MSG_SCOPE)
        action = {"type": "messaging.send", "to": "a@b.c"}
        x_priv, _ = generate_keypair()  # attacker, not the principal
        appr = _mint_approval(x_priv, cred["credential_id"], action)
        req = w.request(cred, action, approval=appr)
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok, "forged principal approval verified")
        self.assertTrue(any("signature invalid" in r for r in reasons),
                        reasons)

    def test_prepare_tampered_action_denied(self):
        w = ModeWorld()
        cred = w.credential("prepare", MSG_SCOPE)
        appr = _mint_approval(w.p_priv, cred["credential_id"],
                              {"type": "messaging.send", "to": "a@b.c"})
        # Attacker swaps the action the approval was minted for.
        req = w.request(cred, {"type": "messaging.send",
                               "to": "evil@x.y"}, approval=appr)
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok)
        self.assertTrue(any("exact action" in r for r in reasons), reasons)

    def test_prepare_cross_credential_approval_denied(self):
        w = ModeWorld()
        cred_a = w.credential("prepare", MSG_SCOPE)
        cred_b = w.credential("prepare", MSG_SCOPE)
        action = {"type": "messaging.send", "to": "a@b.c"}
        appr = _mint_approval(w.p_priv, cred_a["credential_id"], action)
        req = w.request(cred_b, action, approval=appr)
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok)
        self.assertTrue(any("different credential" in r for r in reasons),
                        reasons)

    def test_prepare_replayed_approval_denied(self):
        w = ModeWorld()
        cred = w.credential("prepare", MSG_SCOPE)
        action = {"type": "messaging.send", "to": "a@b.c"}
        appr = _mint_approval(w.p_priv, cred["credential_id"], action)
        seen = set()
        req1 = w.request(cred, action, approval=appr)
        ok, reasons, _ = w.verify(req1, approval_nonces=seen)
        self.assertTrue(ok, reasons)
        seen.add(appr["nonce"])  # service reserves on allow
        req2 = w.request(cred, action, approval=appr)
        ok, reasons, _ = w.verify(req2, approval_nonces=seen)
        self.assertFalse(ok, "replayed approval verified")
        self.assertTrue(any("already used" in r for r in reasons), reasons)

    def test_prepare_expired_approval_denied(self):
        w = ModeWorld()
        cred = w.credential("prepare", MSG_SCOPE)
        action = {"type": "messaging.send", "to": "a@b.c"}
        appr = _mint_approval(w.p_priv, cred["credential_id"], action,
                              ttl_s=-10)
        req = w.request(cred, action, approval=appr)
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok)
        self.assertTrue(any("expired" in r for r in reasons), reasons)

    def test_prepare_approval_binds_exact_prepared_payload(self):
        # "execute requiring completed prepare": the approval authorizes
        # the exact prepared payload — a different amount does not verify.
        w = ModeWorld()
        scope = {"allow": ["payments.execute"]}
        cred = w.credential("prepare", scope)
        prepared = {"type": "payments.execute", "target": "/pay",
                    "amount_cents": 500}
        appr = _mint_approval(w.p_priv, cred["credential_id"], prepared)
        req = w.request(cred, dict(prepared), approval=appr)
        ok, reasons, _ = w.verify(req)
        self.assertTrue(ok, reasons)
        altered = {"type": "payments.execute", "target": "/pay",
                   "amount_cents": 501}
        req2 = w.request(cred, altered, approval=appr)
        ok, reasons, _ = w.verify(req2)
        self.assertFalse(ok, "approval honored for altered payload")

    def test_execute_mode_allows_effect(self):
        w = ModeWorld()
        scope = {"allow": ["payments.execute"]}
        cred = w.credential("execute", scope)
        req = w.request(cred, {"type": "payments.execute",
                               "amount_cents": 100})
        ok, reasons, _ = w.verify(req)
        self.assertTrue(ok, reasons)

    def test_unknown_scope_rejected_at_verification(self):
        w = ModeWorld()
        cred = w.credential("execute", {"allow": ["bogus.scope"]})
        req = w.request(cred, {"type": "bogus.scope"})
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok, "unknown scope verified")
        self.assertTrue(any("unknown scope" in r for r in reasons),
                        reasons)

    def test_mode_escalation_in_chain_denied(self):
        w = ModeWorld()
        cred = w.credential("execute", MSG_SCOPE, link_mode="read")
        req = w.request(cred, {"type": "messaging.draft"})
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok, "read->execute escalation verified")
        self.assertTrue(any("escalation" in r for r in reasons), reasons)

    def test_mixed_chain_denied(self):
        # Modeless link under a mode-carrying credential: fail closed.
        w = ModeWorld()
        cred = w.credential("read", {"allow": ["inbox.read"]},
                            link_mode="SKIP")
        req = w.request(cred, {"type": "inbox.read"})
        ok, reasons, _ = w.verify(req)
        self.assertFalse(ok)
        self.assertTrue(any("modeless" in r for r in reasons), reasons)

    def test_mode_deescalation_verifies(self):
        w = ModeWorld()
        cred = w.credential("prepare", MSG_SCOPE, link_mode="execute")
        action = {"type": "messaging.send", "to": "a@b.c"}
        appr = _mint_approval(w.p_priv, cred["credential_id"], action)
        req = w.request(cred, action, approval=appr)
        ok, reasons, _ = w.verify(req)
        self.assertTrue(ok, reasons)


class TestPrincipalApprovalHelpers(unittest.TestCase):
    def test_issue_verify_roundtrip(self):
        issue = getattr(credmod, "issue_principal_approval", None)
        verify = getattr(credmod, "verify_principal_approval", None)
        self.assertIsNotNone(issue, "issue_principal_approval missing")
        self.assertIsNotNone(verify, "verify_principal_approval missing")
        p_priv, p_pub = generate_keypair()
        action = {"type": "payments.execute", "amount_cents": 10}
        appr = issue(principal_priv_hex=p_priv,
                     credential_id="cred-1", action=action)
        self.assertEqual(appr["action"], action)
        self.assertIsNot(appr["action"], action)  # deep-copied
        ok, reasons = verify(appr, principal_pubkey=p_pub, action=action,
                             credential_id="cred-1")
        self.assertTrue(ok, reasons)

    def test_wrong_key_rejected(self):
        verify = getattr(credmod, "verify_principal_approval", None)
        self.assertIsNotNone(verify, "verify_principal_approval missing")
        p_priv, _ = generate_keypair()
        _, x_pub = generate_keypair()
        action = {"type": "payments.execute"}
        appr = _mint_approval(p_priv, "cred-1", action)
        ok, reasons = verify(appr, principal_pubkey=x_pub, action=action,
                             credential_id="cred-1")
        self.assertFalse(ok)
        self.assertTrue(any("signature invalid" in r for r in reasons))

    def test_replay_rejected(self):
        verify = getattr(credmod, "verify_principal_approval", None)
        self.assertIsNotNone(verify, "verify_principal_approval missing")
        p_priv, p_pub = generate_keypair()
        action = {"type": "payments.execute"}
        appr = _mint_approval(p_priv, "cred-1", action)
        ok, _ = verify(appr, principal_pubkey=p_pub, action=action,
                       credential_id="cred-1",
                       seen_nonces={appr["nonce"]})
        self.assertFalse(ok)

    def test_malformed_approval_denied_closed(self):
        verify = getattr(credmod, "verify_principal_approval", None)
        self.assertIsNotNone(verify, "verify_principal_approval missing")
        _, p_pub = generate_keypair()
        for bad in (None, "nope", {}, {"nonce": "x"}):
            ok, reasons = verify(bad, principal_pubkey=p_pub, action={},
                                 credential_id="c")
            self.assertFalse(ok, bad)
            self.assertTrue(reasons)


class TestV1ModeCheck(unittest.TestCase):
    def _v1_chain(self, mode, scope):
        p_priv, p_pub = generate_keypair()
        a_priv, a_pub = generate_keypair()
        link = issue_delegation(
            delegator_priv_hex=p_priv, delegator_pub_hex=p_pub,
            delegatee_pub_hex=a_pub, scope=scope)
        link = _resign_link({**link, "mode": mode}, p_priv)
        cred = issue_credential(
            principal_id="p", principal_priv_hex=p_priv,
            principal_pub_hex=p_pub, agent_id="a", agent_pub_hex=a_pub,
            scope=scope, delegations=[link])
        cred = _resign_cred({**cred, "mode": mode}, p_priv)
        return p_priv, p_pub, a_priv, cred

    def _v1_req(self, a_priv, cred, action, approval=None):
        env = sign_action_request(agent_priv_hex=a_priv,
                                  credential_id=cred["credential_id"],
                                  action=action)
        req = {"credential": cred, "action": env["action"],
               "nonce": env["nonce"], "ts": env["ts"],
               "agent_signature": env["agent_signature"]}
        if approval is not None:
            req["principal_approval"] = approval
        return req

    def test_v1_prepare_without_approval_denied(self):
        p_priv, p_pub, a_priv, cred = self._v1_chain("prepare", MSG_SCOPE)
        req = self._v1_req(a_priv, cred, {"type": "messaging.send"})
        ok, reasons = verify_action_request(req, [p_pub])
        self.assertFalse(ok)
        self.assertTrue(any("principal approval" in r for r in reasons),
                        reasons)

    def test_v1_prepare_with_approval_allows(self):
        p_priv, p_pub, a_priv, cred = self._v1_chain("prepare", MSG_SCOPE)
        action = {"type": "messaging.send", "to": "a@b.c"}
        appr = _mint_approval(p_priv, cred["credential_id"], action)
        req = self._v1_req(a_priv, cred, action, approval=appr)
        ok, reasons = verify_action_request(req, [p_pub])
        self.assertTrue(ok, reasons)

    def test_v1_unknown_mode_denied(self):
        p_priv, p_pub, a_priv, cred = self._v1_chain("turbo", MSG_SCOPE)
        req = self._v1_req(a_priv, cred, {"type": "messaging.draft"})
        ok, reasons = verify_action_request(req, [p_pub])
        self.assertFalse(ok)
        self.assertTrue(any("unknown delegation mode" in r
                            for r in reasons), reasons)


class TestApprovalNonceReservation(unittest.TestCase):
    def test_reserve_then_replay_denied(self):
        import services.verifier.app as appmod
        state = appmod.VerifierState()
        now = time.time()
        self.assertTrue(
            state.check_and_reserve_approval("n1", now + 900, now))
        self.assertTrue(state.approval_nonce_seen("n1"))
        self.assertFalse(
            state.check_and_reserve_approval("n1", now + 900, now))
        # Expired reservations are pruned: reusable after expiry.
        self.assertTrue(
            state.check_and_reserve_approval("n2", now - 1, now))
        self.assertTrue(
            state.check_and_reserve_approval("n2", now + 900, now + 3600))


class TestScopeCatalog(unittest.TestCase):
    def test_catalog_covers_prd_namespaces(self):
        catalog = getattr(credmod, "SCOPE_CATALOG", None)
        self.assertIsNotNone(catalog, "SCOPE_CATALOG missing")
        for scope in ("messaging.draft", "messaging.send", "inbox.read",
                      "calendar.read", "calendar.write", "publish.draft",
                      "payments.read", "payments.initiate",
                      "payments.execute", "research.web", "crm.read",
                      "crm.write", "travel.recommend"):
            self.assertIn(scope, catalog)
        effects = {s: e for s, (e, _) in catalog.items()}
        self.assertEqual(effects["payments.initiate"], "draft")
        self.assertEqual(effects["payments.execute"], "effect")
        self.assertEqual(effects["calendar.write"], "effect")
        self.assertEqual(effects["inbox.read"], "read")


if __name__ == "__main__":
    unittest.main()
