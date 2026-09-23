"""H-2 regression: delegation limits must be monotonic over missing keys.

Bug: scope_narrows() iterated only the child's limits, so a child scope
that OMITTED a parent limit (e.g. a spending cap) for an action it still
allowed passed as "narrower" — while enforcement treated an absent ceiling
as UNLIMITED. A compromised intermediate delegator could silently drop the
spending cap.

Fixed: (a) scope_narrows requires the child to carry every parent limit key
for actions it still allows (value <= parent's), checked at issuance
(issue_credential, full chain) and verification (_verify_chain); (b)
enforcement fails closed via check_chain_limits_present — absent is never
"unlimited".

Stash proof: these tests use only stable pre-fix API at module level, so
`git stash` of the fix makes the security assertions fail (the attack
verifies), not just error at import.
"""
import time
import unittest

from services.verifier import credentials as credmod
from services.verifier import ed25519
from services.verifier.credentials import (
    canonical, generate_keypair, issue_credential, issue_delegation,
    scope_narrows, sign_action_request, verify_credential,
    verify_action_request)

CAP = 100  # parent spend cap, cents


def _chain(child_scope):
    """principal -> agent (spend-capped) -> sub-agent (child_scope).

    Returns dict with key material, links, and (when issuance allows) cred.
    """
    p_priv, p_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()
    s_priv, s_pub = generate_keypair()
    parent_scope = {"allow": ["pay.*"],
                    "limits": {"pay.x": {"max_spend_per_day": CAP,
                                         "max_per_day": 10}}}
    link0 = issue_delegation(delegator_priv_hex=p_priv,
                             delegator_pub_hex=p_pub,
                             delegatee_pub_hex=a_pub, scope=parent_scope)
    link1 = issue_delegation(delegator_priv_hex=a_priv,
                             delegator_pub_hex=a_pub,
                             delegatee_pub_hex=s_pub, scope=child_scope)
    return {"p_priv": p_priv, "p_pub": p_pub, "a_priv": a_priv,
            "a_pub": a_pub, "s_priv": s_priv, "s_pub": s_pub,
            "link0": link0, "link1": link1}


def _hand_mint(c, scope):
    """Credential dict signed by the principal, bypassing issue_credential.

    Models an attacker- or legacy-minted credential: issuance-time checks
    don't run, so verification must still fail closed.
    """
    now = time.time()
    cred = {
        "credential_id": "cred-h2-hand",
        "principal": {"id": "p", "pubkey": c["p_pub"]},
        "agent_id": "sub",
        "agent_pubkey": c["s_pub"],
        "scope": scope,
        "issued_at": round(now, 3),
        "expires_at": round(now + 3600, 3),
        "delegations": [c["link0"], c["link1"]],
        "issuer_pubkey": c["p_pub"],
        "revocation_handle": "rh-" + "ab12cd34ef56",
    }
    unsigned = {k: v for k, v in cred.items() if k != "signature"}
    cred["signature"] = ed25519.sign_hex(c["p_priv"], canonical(unsigned))
    return cred


class TestScopeNarrowsMonotonic(unittest.TestCase):
    def setUp(self):
        self.parent = {"allow": ["pay.*"],
                       "limits": {"pay.x": {"max_spend_per_day": CAP}}}

    def test_dropped_spend_key_rejected(self):
        child = {"allow": ["pay.*"]}
        ok, why = scope_narrows(child, self.parent)
        self.assertFalse(ok, "omitted spend cap must not narrow")
        self.assertIn("max_spend_per_day", why)

    def test_tighter_spend_key_accepted(self):
        child = {"allow": ["pay.*"],
                 "limits": {"pay.x": {"max_spend_per_day": 50}}}
        ok, why = scope_narrows(child, self.parent)
        self.assertTrue(ok, why)

    def test_looser_spend_key_rejected(self):
        child = {"allow": ["pay.*"],
                 "limits": {"pay.x": {"max_spend_per_day": 150}}}
        ok, _ = scope_narrows(child, self.parent)
        self.assertFalse(ok)

    def test_partially_dropped_keys_rejected(self):
        # Parent caps two keys; child carries only one -> still widening.
        parent = {"allow": ["pay.*"],
                  "limits": {"pay.x": {"max_spend_per_day": 100,
                                       "max_per_day": 10}}}
        child = {"allow": ["pay.*"],
                 "limits": {"pay.x": {"max_per_day": 5}}}
        ok, why = scope_narrows(child, parent)
        self.assertFalse(ok)
        self.assertIn("max_spend_per_day", why)

    def test_dropped_action_needs_no_key(self):
        # The monotonicity rule covers actions the child *still allows*;
        # a child that denies the action outright carries no limit for it.
        child = {"allow": ["pay.*"], "deny": ["pay.x"]}
        ok, why = scope_narrows(child, self.parent)
        self.assertTrue(ok, why)

    def test_allow_containment_still_sound(self):
        ok, _ = scope_narrows({"allow": ["pay.*", "admin.*"]}, self.parent)
        self.assertFalse(ok)

    def test_deny_monotonicity_still_sound(self):
        parent = {"allow": ["pay.*"], "deny": ["pay.wipe"]}
        ok, _ = scope_narrows({"allow": ["pay.*"], "deny": []}, parent)
        self.assertFalse(ok)
        ok, _ = scope_narrows({"allow": ["pay.*"], "deny": ["pay.wipe"]},
                              parent)
        self.assertTrue(ok)


class TestIssuanceMonotonic(unittest.TestCase):
    def test_issuance_rejects_dropped_spend_key(self):
        c = _chain({"allow": ["pay.*"]})
        with self.assertRaises(ValueError) as ctx:
            issue_credential(
                principal_id="p", principal_priv_hex=c["p_priv"],
                principal_pub_hex=c["p_pub"], agent_id="sub",
                agent_pub_hex=c["s_pub"], scope={"allow": ["pay.*"]},
                delegations=[c["link0"], c["link1"]])
        self.assertIn("max_spend_per_day", str(ctx.exception))

    def test_issuance_accepts_tighter_spend_key(self):
        child = {"allow": ["pay.*"],
                 "limits": {"pay.x": {"max_spend_per_day": 50,
                                      "max_per_day": 10}}}
        c = _chain(child)
        cred = issue_credential(
            principal_id="p", principal_priv_hex=c["p_priv"],
            principal_pub_hex=c["p_pub"], agent_id="sub",
            agent_pub_hex=c["s_pub"], scope=child,
            delegations=[c["link0"], c["link1"]])
        ok, reasons = verify_credential(cred, [c["p_pub"]])
        self.assertTrue(ok, reasons)

    def test_issuance_rejects_looser_spend_key(self):
        child = {"allow": ["pay.*"],
                 "limits": {"pay.x": {"max_spend_per_day": 150}}}
        c = _chain(child)
        with self.assertRaises(ValueError):
            issue_credential(
                principal_id="p", principal_priv_hex=c["p_priv"],
                principal_pub_hex=c["p_pub"], agent_id="sub",
                agent_pub_hex=c["s_pub"], scope=child,
                delegations=[c["link0"], c["link1"]])


class TestVerificationMonotonic(unittest.TestCase):
    def test_verification_rejects_dropped_spend_key(self):
        # End-to-end: child credential omits the spend key -> MUST FAIL.
        c = _chain({"allow": ["pay.*"]})
        cred = _hand_mint(c, {"allow": ["pay.*"], "deny": [],
                              "limits": {}})
        ok, reasons = verify_credential(cred, [c["p_pub"]])
        self.assertFalse(ok, "dropped spend cap verified: H-2 still open")
        self.assertTrue(any("max_spend_per_day" in r for r in reasons),
                        reasons)

    def test_action_request_rejects_dropped_spend_key(self):
        # Same attack through the v1 action-request path (enforcement).
        c = _chain({"allow": ["pay.*"]})
        cred = _hand_mint(c, {"allow": ["pay.*"], "deny": [],
                              "limits": {}})
        env = sign_action_request(
            agent_priv_hex=c["s_priv"],
            credential_id=cred["credential_id"],
            action={"type": "pay.x", "target": "/x", "amount_cents": 10**9})
        req = {"credential": cred, "action": env["action"],
               "nonce": env["nonce"], "ts": env["ts"],
               "agent_signature": env["agent_signature"]}
        ok, reasons = verify_action_request(req, [c["p_pub"]], usage={})
        self.assertFalse(ok, "dropped spend cap enforced as unlimited: H-2")
        self.assertTrue(any("max_spend_per_day" in r for r in reasons),
                        reasons)

    def test_verification_rejects_looser_spend_key(self):
        child = {"allow": ["pay.*"],
                 "limits": {"pay.x": {"max_spend_per_day": 150}}}
        c = _chain(child)
        cred = _hand_mint(c, child)
        ok, _ = verify_credential(cred, [c["p_pub"]])
        self.assertFalse(ok)


class TestChainRequiredLimitsHelper(unittest.TestCase):
    """H-2b: enforcement-time fail-closed helpers."""

    def test_union_reports_minimum(self):
        helper = getattr(credmod, "chain_required_limits", None)
        self.assertIsNotNone(helper, "chain_required_limits missing")
        c = _chain({"allow": ["pay.*"],
                    "limits": {"pay.x": {"max_spend_per_day": 80}}})
        required = helper({"delegations": [c["link0"], c["link1"]]})
        self.assertEqual(required["pay.x"]["max_spend_per_day"], 80)
        # The credential's own scope is excluded: it is the thing checked.
        required2 = helper({"delegations": [c["link0"]],
                            "scope": {"limits": {}}})
        self.assertEqual(required2["pay.x"]["max_spend_per_day"], CAP)

    def test_missing_key_fails_closed(self):
        check = getattr(credmod, "check_chain_limits_present", None)
        self.assertIsNotNone(check, "check_chain_limits_present missing")
        c = _chain({"allow": ["pay.*"]})
        cred = _hand_mint(c, {"allow": ["pay.*"], "deny": [],
                              "limits": {}})
        ok, reasons = check(cred, "pay.x")
        self.assertFalse(ok)
        self.assertTrue(any("failing closed" in r for r in reasons))

    def test_present_key_passes(self):
        check = getattr(credmod, "check_chain_limits_present", None)
        self.assertIsNotNone(check, "check_chain_limits_present missing")
        child = {"allow": ["pay.*"],
                 "limits": {"pay.x": {"max_spend_per_day": 50,
                                      "max_per_day": 10}}}
        c = _chain(child)
        cred = _hand_mint(c, child)
        ok, reasons = check(cred, "pay.x")
        self.assertTrue(ok, reasons)


if __name__ == "__main__":
    unittest.main()
