"""Tests for per-link delegation revocation handles (CTO addendum, item 7).

Decision: ENFORCE (not remove). A delegation link's revocation_handle,
minted at issuance and signed into the link, is consulted at verify time:
any chain containing a revoked handle is denied, even when every
signature verifies. See docs/revocation-design.md.
"""
import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from services.operator import console  # noqa: E402
from services.verifier import ed25519  # noqa: E402
from services.verifier.credentials import (  # noqa: E402
    canonical, generate_keypair, issue_credential, issue_delegation,
    verify_credential, _unsigned, _verify_chain,
)
from services.verifier.enrollment import (  # noqa: E402
    TransparencyLog, build_manifest, verify_manifest,
)


# ------------------------------------------------------------------ world
class World:
    """Enrolled principal + 2-link chain (principal -> mid -> agent)."""

    def __init__(self):
        from services.verifier.enrollment import jwk_thumbprint
        self.op_priv, self.op_pub = generate_keypair()
        self.p_priv, self.p_pub = generate_keypair()
        self.m_priv, self.m_pub = generate_keypair()   # intermediate
        self.a_priv, self.a_pub = generate_keypair()    # terminal agent
        self.tmp = tempfile.mkdtemp(prefix="vouch-linkrev-")
        self.log = TransparencyLog(os.path.join(self.tmp, "t.jsonl"))
        now = time.time()
        self.log.append(
            "enroll",
            {"principal_id": "p1", "tier": "allowlist", "domain": None,
             "keys": [{"key_id": jwk_thumbprint(self.p_pub),
                       "pubkey": self.p_pub, "label": "prod"}],
             "enrolled_at": now, "expires_at": now + 90 * 86400},
            self.op_priv)
        scope = {"allow": ["pay.*"]}
        self.link0 = issue_delegation(
            delegator_priv_hex=self.p_priv, delegator_pub_hex=self.p_pub,
            delegatee_pub_hex=self.m_pub, scope=scope)
        self.link1 = issue_delegation(
            delegator_priv_hex=self.m_priv, delegator_pub_hex=self.m_pub,
            delegatee_pub_hex=self.a_pub, scope=scope)
        self.cred = issue_credential(
            principal_id="p1", principal_priv_hex=self.p_priv,
            principal_pub_hex=self.p_pub, agent_id="bot",
            agent_pub_hex=self.a_pub, scope=scope,
            delegations=[self.link0, self.link1])

    def manifest(self, **kw):
        kw.setdefault("valid_for_s", 3600)
        return build_manifest(log=self.log, operator_priv_hex=self.op_priv,
                              operator_pubkey=self.op_pub, **kw)

    def revoke_link(self, handle):
        now = round(time.time(), 3)
        self.log.append("revoke-delegation-link",
                        {"principal_id": "p1", "revocation_handle": handle,
                         "revoked_at": now, "reason": "compromised"},
                        self.op_priv)


def _v2_request(world):
    from services.verifier.credentials import sign_action_request
    env = sign_action_request(agent_priv_hex=world.a_priv,
                              credential_id=world.cred["credential_id"],
                              action={"type": "pay.x", "target": "/x"})
    return {"tenant_id": "t", "credential": copy.deepcopy(world.cred),
            "action": env["action"], "nonce": env["nonce"],
            "ts": env["ts"], "agent_signature": env["agent_signature"]}


def _v2_verify(world, req, manifest):
    from services.verifier.credentials import verify_action_request_v2
    return verify_action_request_v2(
        req, manifest=manifest, operator_pubkeys=world.op_pub,
        nonces=set(), usage={}, spending={})


class TestLinkRevocationEnforced(unittest.TestCase):
    def test_unrevoked_chain_verifies(self):
        w = World()
        ok, reasons, _ev = _v2_verify(w, _v2_request(w), w.manifest())
        self.assertTrue(ok, reasons)

    def test_revoked_middle_link_denies(self):
        w = World()
        w.revoke_link(w.link1["revocation_handle"])
        ok, reasons, _ev = _v2_verify(w, _v2_request(w), w.manifest())
        self.assertFalse(ok)
        self.assertTrue(any("delegation link revoked" in r for r in reasons),
                        reasons)

    def test_revoked_first_link_denies(self):
        w = World()
        w.revoke_link(w.link0["revocation_handle"])
        ok, reasons, _ev = _v2_verify(w, _v2_request(w), w.manifest())
        self.assertFalse(ok)
        self.assertTrue(any("delegation link revoked" in r for r in reasons),
                        reasons)

    def test_revoking_one_link_leaves_other_chains_working(self):
        # A second credential sharing link0 but not the revoked link1
        # still verifies: revocation is surgical, not credential-wide.
        w = World()
        w.revoke_link(w.link1["revocation_handle"])
        from services.verifier.credentials import sign_action_request
        a2_priv, a2_pub = generate_keypair()
        link1b = issue_delegation(
            delegator_priv_hex=w.m_priv, delegator_pub_hex=w.m_pub,
            delegatee_pub_hex=a2_pub, scope={"allow": ["pay.*"]})
        cred2 = issue_credential(
            principal_id="p1", principal_priv_hex=w.p_priv,
            principal_pub_hex=w.p_pub, agent_id="bot2",
            agent_pub_hex=a2_pub, scope={"allow": ["pay.*"]},
            delegations=[w.link0, link1b])
        env = sign_action_request(agent_priv_hex=a2_priv,
                                  credential_id=cred2["credential_id"],
                                  action={"type": "pay.x"})
        req = {"credential": cred2, "action": env["action"],
               "nonce": env["nonce"], "ts": env["ts"],
               "agent_signature": env["agent_signature"]}
        ok, reasons, _ev = _v2_verify(w, req, w.manifest())
        self.assertTrue(ok, reasons)

    def test_credential_revocation_still_enforced(self):
        # The pre-existing credential-level handle keeps working.
        w = World()
        now = round(time.time(), 3)
        w.log.append("revoke-credential",
                     {"principal_id": "p1",
                      "revocation_handle": w.cred["revocation_handle"],
                      "revoked_at": now, "reason": "x"},
                     w.op_priv)
        ok, reasons, _ev = _v2_verify(w, _v2_request(w), w.manifest())
        self.assertFalse(ok)
        self.assertIn("credential revoked", reasons)

    def test_verify_credential_direct_with_revoked_set(self):
        w = World()
        ok, _ = verify_credential(w.cred, [w.p_pub])
        self.assertTrue(ok)
        ok, reasons = verify_credential(
            w.cred, [w.p_pub],
            revoked_link_handles={w.link1["revocation_handle"]})
        self.assertFalse(ok)
        self.assertTrue(any("delegation link revoked" in r for r in reasons),
                        reasons)

    def test_link_without_handle_is_not_denied(self):
        # Documented edge: a handle-less link cannot be revoked by handle
        # (nothing to match) — it verifies rather than failing closed.
        w = World()
        link = copy.deepcopy(w.link1)
        del link["revocation_handle"]
        link["signature"] = ed25519.sign_hex(
            w.m_priv, canonical(_unsigned(link)))
        cred = copy.deepcopy(w.cred)
        cred["delegations"] = [w.link0, link]
        cred["signature"] = ed25519.sign_hex(
            w.p_priv, canonical(_unsigned(cred)))
        ok, reasons = verify_credential(
            cred, [w.p_pub], revoked_link_handles={"rh-ffffffffffff"})
        self.assertTrue(ok, reasons)

    def test_manifest_carries_revoked_link_handles(self):
        w = World()
        h = w.link1["revocation_handle"]
        w.revoke_link(h)
        m = w.manifest()
        self.assertIn(h, m["revoked_delegation_handles"])
        ok, _ = verify_manifest(m, w.op_pub)
        self.assertTrue(ok)

    def test_manifest_missing_field_fails_closed(self):
        w = World()
        m = w.manifest()
        del m["revoked_delegation_handles"]
        # Re-sign so the failure is the missing field, not the signature.
        m["signature"] = ed25519.sign_hex(
            w.op_priv, canonical(_unsigned(m)))
        ok, reasons = verify_manifest(m, w.op_pub)
        self.assertFalse(ok)
        self.assertTrue(any("revoked_delegation_handles" in r
                            for r in reasons), reasons)

    def test_duplicate_revoke_events_dedupe(self):
        w = World()
        h = w.link0["revocation_handle"]
        w.revoke_link(h)
        w.revoke_link(h)
        m = w.manifest()
        self.assertEqual(m["revoked_delegation_handles"].count(h), 1)


# ------------------------------------------------------------------ console
def _run(argv, store):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = console.main(["--store", store] + argv)
    return rc, out.getvalue(), err.getvalue()


class TestRevokeDelegationLinkConsole(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = os.path.join(self.tmp.name, "store")
        rc, _out, err = _run(["init-operator"], self.store)
        self.assertEqual(rc, 0, err)
        _, pub = generate_keypair()
        rc, _out, err = _run(
            ["new-principal", "--principal", "acme", "--pubkey", pub,
             "--label", "prod"], self.store)
        self.assertEqual(rc, 0, err)

    def tearDown(self):
        self.tmp.cleanup()

    def _manifest(self):
        rc, _out, err = _run(["manifest"], self.store)
        self.assertEqual(rc, 0, err)
        with open(os.path.join(self.store, "manifest.json")) as f:
            return json.load(f)

    def test_revoke_delegation_link_command(self):
        handle = "rh-abc123def456"
        rc, out, err = _run(
            ["revoke-delegation-link", "--principal", "acme",
             "--revocation-handle", handle, "--reason", "key leaked",
             "--yes"], self.store)
        self.assertEqual(rc, 0, err)
        self.assertIn(handle, out)
        m = self._manifest()
        self.assertIn(handle, m["revoked_delegation_handles"])
        # ... and the credential list is untouched.
        self.assertEqual(m["revoked_credentials"], [])

    def test_requires_yes(self):
        rc, _out, err = _run(
            ["revoke-delegation-link", "--principal", "acme",
             "--revocation-handle", "rh-abc123def456",
             "--reason", "x"], self.store)
        self.assertNotEqual(rc, 0)
        self.assertEqual(self._manifest()["revoked_delegation_handles"], [])

    def test_unknown_principal_rejected(self):
        rc, _out, err = _run(
            ["revoke-delegation-link", "--principal", "nobody",
             "--revocation-handle", "rh-abc123def456",
             "--reason", "x", "--yes"], self.store)
        self.assertNotEqual(rc, 0, err)

    def test_empty_handle_rejected(self):
        rc, _out, err = _run(
            ["revoke-delegation-link", "--principal", "acme",
             "--revocation-handle", "",
             "--reason", "x", "--yes"], self.store)
        self.assertNotEqual(rc, 0, err)


if __name__ == "__main__":
    unittest.main()


class TestRevocationDiagnostics(unittest.TestCase):
    """Revoking link 0 must not make link 1 emit a false "scope widens".

    The deny is correct (link 0 revoked); the diagnostics must say why,
    not invent a second reason. Fails on the pre-fix _verify_chain, which
    skipped the prev_scope assignment on the revoked link's `continue`,
    leaving link 1 compared against None.
    """

    def test_revoked_first_link_diagnostic_is_truthful(self):
        w = World()
        w.revoke_link(w.link0["revocation_handle"])
        ok, reasons, _ev = _v2_verify(w, _v2_request(w), w.manifest())
        self.assertFalse(ok)
        self.assertTrue(
            any("link 0" in r and "delegation link revoked" in r
                for r in reasons),
            reasons)
        # link 1 genuinely narrows link 0 (identical scopes): no widening
        # reason may be emitted.
        self.assertFalse(
            any("link 1" in r and "scope widens" in r for r in reasons),
            f"misleading diagnostic emitted: {reasons}")
