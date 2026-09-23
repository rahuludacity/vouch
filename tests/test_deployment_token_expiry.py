"""Tests for M-2: deployment tokens expire (max_age enforced at verify).

Lifetime: DEPLOYMENT_TOKEN_TTL_S (7 days), documented in
gatekeeper/controlplane.py. The gatekeeper's DeploymentTokenVerifier
fails closed on expired (or future-issued) tokens even with a valid HMAC;
the control plane's get_deployment_token() transparently re-mints expired
tokens on read so running deployments keep working (revoked tokens are
never resurrected).
"""
import hashlib
import hmac
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from gatekeeper.controlplane import (  # noqa: E402
    DEPLOYMENT_TOKEN_TTL_S, DeploymentTokenVerifier, parse_deployment_token,
)
from services.controlplane.models import ControlPlaneDB  # noqa: E402

_DEP_ID = "dep_" + "ab12" * 4
def _craft_token(dep_id, tenant_id, issued, key_hex):
    mac = hmac.new(
        bytes.fromhex(key_hex),
        f"{dep_id}.{tenant_id}.{issued}".encode("utf-8"),
        hashlib.sha256).hexdigest()[:32]
    return f"vouch_dep_{dep_id}_{tenant_id}_{issued}_{mac}"


class TokenExpiryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = ControlPlaneDB(os.path.join(self.tmp.name, "cp.db"))
        self.key_hex = self.db.get_deployment_signing_key()
        self.tid = self.db.create_tenant("Acme")["tenant_id"]
        # Hermetic verifier: seed the signing-key and binding caches
        # directly (no network).
        self.v = DeploymentTokenVerifier("http://127.0.0.1:9", "tok")
        self.v._key = {"key": bytes.fromhex(self.key_hex),
                       "fetched_at": time.time()}
        self.v._bindings[_DEP_ID] = {"tenant_id": self.tid,
                                     "status": "running", "at": time.time()}

    def tearDown(self):
        self.tmp.cleanup()

    def test_lifetime_is_documented_7_days(self):
        self.assertEqual(DEPLOYMENT_TOKEN_TTL_S, 7 * 24 * 3600)

    def test_fresh_token_accepted(self):
        token = _craft_token(_DEP_ID, self.tid, int(time.time()), self.key_hex)
        self.assertEqual(self.v.verify(token), self.tid)

    def test_expired_token_rejected(self):
        # Valid HMAC, but issued before the TTL window: still rejected.
        old = int(time.time()) - DEPLOYMENT_TOKEN_TTL_S - 1
        token = _craft_token(_DEP_ID, self.tid, old, self.key_hex)
        self.assertIsNotNone(parse_deployment_token(token))  # well-formed
        self.assertIsNone(self.v.verify(token))

    def test_max_age_boundary(self):
        # Deterministic via the max_age_s override (no sleeping).
        now = time.time()
        fresh = _craft_token(_DEP_ID, self.tid, int(now) - 59, self.key_hex)
        stale = _craft_token(_DEP_ID, self.tid, int(now) - 61, self.key_hex)
        self.assertEqual(self.v.verify(fresh, max_age_s=60, now=now), self.tid)
        self.assertIsNone(self.v.verify(stale, max_age_s=60, now=now))

    def test_future_issued_token_rejected(self):
        token = _craft_token(_DEP_ID, self.tid, int(time.time()) + 3600,
                             self.key_hex)
        self.assertIsNone(self.v.verify(token))

    def test_forged_sig_still_rejected(self):
        token = _craft_token(_DEP_ID, self.tid, int(time.time()), self.key_hex)
        bad = token[:-1] + ("0" if token[-1] != "0" else "1")
        self.assertIsNone(self.v.verify(bad))

    def test_minted_token_carries_issued_and_verifies(self):
        d = self.db.create_deployment(self.tid, "task-x", "img:1")
        dep_id = d["deployment_id"]
        token = d["deployment_token"]
        parsed = parse_deployment_token(token)
        self.assertIsNotNone(parsed)
        _d, tid, issued, _sig = parsed
        self.assertEqual((_d, tid), (dep_id, self.tid))
        self.assertLess(abs(time.time() - issued), 60)
        self.v._bindings[dep_id] = {"tenant_id": self.tid, "status": "running",
                                    "at": time.time()}
        self.assertEqual(self.v.verify(token), self.tid)

    def test_get_deployment_token_refreshes_expired(self):
        d = self.db.create_deployment(self.tid, "task-y", "img:1")
        dep_id = d["deployment_id"]
        old_token = d["deployment_token"]
        # Age the stored token past the TTL (valid HMAC, old issued).
        old_issued = int(time.time()) - DEPLOYMENT_TOKEN_TTL_S - 100
        aged = _craft_token(dep_id, self.tid, old_issued, self.key_hex)
        self.db._write(
            "UPDATE deployment_tokens SET token = ?, token_hash = ?"
            " WHERE deployment_id = ?",
            (aged, hashlib.sha256(aged.encode()).hexdigest(), dep_id))
        fresh = self.db.get_deployment_token(dep_id)
        self.assertIsNotNone(fresh)
        self.assertNotEqual(fresh, aged)
        _d, _t, issued, _s = parse_deployment_token(fresh)
        self.assertLess(abs(time.time() - issued), 60)
        # ... and the refreshed token verifies.
        self.v._bindings[dep_id] = {"tenant_id": self.tid, "status": "running",
                                    "at": time.time()}
        self.assertEqual(self.v.verify(fresh), self.tid)

    def test_revoked_token_not_resurrected_by_refresh(self):
        d = self.db.create_deployment(self.tid, "task-z", "img:1")
        dep_id = d["deployment_id"]
        self.db.revoke_deployment_token(dep_id)
        self.assertIsNone(self.db.get_deployment_token(dep_id))


if __name__ == "__main__":
    unittest.main()
