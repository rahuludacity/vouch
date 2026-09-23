"""Tests for per-tenant signing keys: registry, rotation, and
tenant-scoped receipt signing/verification (incl. cross-tenant forgery)."""
import json
import contextlib
import io
import logging
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from gatekeeper.tenants import TenantRegistry  # noqa: E402
from gatekeeper.receipts import ReceiptLog  # noqa: E402
from gatekeeper.controlplane import parse_deployment_token  # noqa: E402
import hashlib as _hashlib  # noqa: E402
import hmac as _hmac  # noqa: E402


def _mac(key_hex, dep_id, tenant_id, issued):
    return _hmac.new(bytes.fromhex(key_hex),
                     f"{dep_id}.{tenant_id}.{issued}".encode("utf-8"),
                     _hashlib.sha256).hexdigest()[:32]


class DeploymentTokenParserTest(unittest.TestCase):
    """H-1: the deployment credential parser accepts only well-formed tokens,
    and the MAC binds deployment_id + tenant_id + issued epoch."""

    def test_round_trip(self):
        dep_id = "dep_" + "ab" * 8
        key = "00" * 32
        sig = _mac(key, dep_id, "acme", 1700000000)
        tok = f"vouch_dep_{dep_id}_acme_1700000000_{sig}"
        parsed = parse_deployment_token(tok)
        self.assertEqual(parsed, (dep_id, "acme", 1700000000, sig))

    def test_malformed_rejected(self):
        for bad in ("", "not-a-token", "vouch_dep_short",
                    "vouch_dep_dep_abababababababab_acme_notanepoch_" + "cd" * 16,
                    "vouch_dep_dep_ABABABABABABABAB_acme_1700000000_" + "cd" * 16,
                    "vouch_dep_dep_abababababababab_acme_1700000000_cdcd"):
            self.assertIsNone(parse_deployment_token(bad), bad)

    def test_mac_binds_all_three_fields(self):
        dep_id = "dep_" + "ab" * 8
        key = "00" * 32
        sig = _mac(key, dep_id, "acme", 1700000000)
        # any change to tenant/epoch/dep must change the MAC: a token cut
        # from another deployment cannot be replayed here.
        self.assertNotEqual(sig, _mac(key, dep_id, "evil", 1700000000))
        self.assertNotEqual(sig, _mac(key, dep_id, "acme", 1700000001))
        self.assertNotEqual(sig, _mac(key, "dep_" + "ff" * 8, "acme",
                                      1700000000))


class TenantRegistryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vouch-tenants-")
        self.reg = TenantRegistry(os.path.join(self.tmp, "tenants.json"))

    def test_create_and_signing_key(self):
        kid, key_hex = self.reg.create("acme")
        self.assertEqual(kid, "k1")
        self.assertEqual(len(bytes.fromhex(key_hex)), 32)  # 256-bit
        rkid, rkey = self.reg.signing_key("acme")
        self.assertEqual((rkid, rkey), ("k1", bytes.fromhex(key_hex)))

    def test_create_duplicate_raises(self):
        self.reg.create("acme")
        with self.assertRaises(KeyError):
            self.reg.create("acme")

    def test_ensure_is_idempotent(self):
        k1 = self.reg.ensure("acme")
        k2 = self.reg.ensure("acme")
        self.assertEqual(k1, k2)

    def test_unknown_tenant_raises(self):
        with self.assertRaises(KeyError):
            self.reg.signing_key("ghost")

    def test_persists_across_instances(self):
        self.reg.create("acme")
        reg2 = TenantRegistry(os.path.join(self.tmp, "tenants.json"))
        self.assertEqual(reg2.signing_key("acme"), self.reg.signing_key("acme"))

    def test_rotate_mints_new_key(self):
        kid1, _ = self.reg.create("acme")
        kid2, key2 = self.reg.rotate("acme")
        self.assertNotEqual(kid1, kid2)
        self.assertEqual(self.reg.signing_key("acme")[0], kid2)
        keys = self.reg.verification_keys("acme")
        self.assertIn(kid1, keys)
        self.assertIn(kid2, keys)
        self.assertEqual(keys[kid2], bytes.fromhex(key2))

    def test_list_tenants(self):
        self.reg.create("acme")
        self.reg.create("globex")
        info = self.reg.list_tenants()
        self.assertEqual(set(info), {"acme", "globex"})
        self.assertEqual(info["acme"]["current_kid"], "k1")


class TenantReceiptsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vouch-receipts-")
        self.reg = TenantRegistry(os.path.join(self.tmp, "tenants.json"))
        self.reg.create("acme")
        self.reg.create("globex")
        self.path = os.path.join(self.tmp, "receipts.jsonl")
        self.log = ReceiptLog(self.path, self.reg)

    def record(self, tenant, tool="read_file", decision="allow"):
        return self.log.record(task_id="t1", agent_id="a1", tool=tool,
                               args={"x": 1}, decision=decision,
                               tenant_id=tenant)

    def test_receipt_carries_tenant_and_kid(self):
        r = self.record("acme")
        self.assertEqual(r["tenant_id"], "acme")
        self.assertEqual(r["kid"], "k1")
        ok, failures = self.log.verify()
        self.assertTrue(ok, failures)

    def test_tenants_get_independent_chains(self):
        ra = self.record("acme")
        rg = self.record("globex")
        self.assertNotEqual(ra["sig"], rg["sig"])  # different keys
        ok, failures = self.log.verify()
        self.assertTrue(ok, failures)

    def test_cross_tenant_forgery_detected(self):
        self.record("acme")  # signed with acme's key
        # attacker rewrites the receipt to look like globex's
        lines = open(self.path).read().strip().split("\n")
        r = json.loads(lines[0])
        r["tenant_id"] = "globex"
        with open(self.path, "w") as f:
            f.write(json.dumps(r) + "\n")
        ok, failures = ReceiptLog(self.path, self.reg).verify()
        self.assertFalse(ok)
        self.assertTrue(any("bad signature" in f for f in failures),
                        failures)

    def test_body_tamper_detected(self):
        self.record("acme", decision="deny")
        lines = open(self.path).read().strip().split("\n")
        r = json.loads(lines[0])
        r["decision"] = "allow"  # rewrite history
        with open(self.path, "w") as f:
            f.write(json.dumps(r) + "\n")
        ok, failures = ReceiptLog(self.path, self.reg).verify()
        self.assertFalse(ok)
        self.assertTrue(any("hash mismatch" in f for f in failures), failures)

    def test_chain_reorder_detected(self):
        self.record("acme")
        self.record("acme")
        lines = open(self.path).read().strip().split("\n")
        with open(self.path, "w") as f:
            f.write(lines[1] + "\n" + lines[0] + "\n")
        ok, failures = ReceiptLog(self.path, self.reg).verify()
        self.assertFalse(ok)
        self.assertTrue(any("seq break" in f or "chain break" in f
                            for f in failures), failures)

    def test_old_receipts_verify_after_rotation(self):
        before = self.record("acme")
        self.reg.rotate("acme")
        after = self.record("acme")
        self.assertNotEqual(before["kid"], after["kid"])
        self.assertNotEqual(before["sig"], after["sig"])
        ok, failures = ReceiptLog(self.path, self.reg).verify()
        self.assertTrue(ok, failures)

    def test_receipt_for_unknown_tenant_fails_verify(self):
        self.record("acme")
        lines = open(self.path).read().strip().split("\n")
        r = json.loads(lines[0])
        r["tenant_id"] = "ghost"
        with open(self.path, "w") as f:
            f.write(json.dumps(r) + "\n")
        ok, failures = ReceiptLog(self.path, self.reg).verify()
        self.assertFalse(ok)
        self.assertTrue(any("unknown tenant" in f for f in failures), failures)

    def test_legacy_static_key_still_works(self):
        # v0 behavior: plain string key, no tenant involved
        path = os.path.join(self.tmp, "legacy.jsonl")
        log = ReceiptLog(path, "dev-only-change-me")
        log.record(task_id="t", agent_id="a", tool="read_file",
                   args={}, decision="allow")
        ok, failures = ReceiptLog(path, "dev-only-change-me").verify()
        self.assertTrue(ok, failures)


class TenantCliKeyHygieneTest(unittest.TestCase):
    """H-5: tenant create/rotate must never print key material.

    secrets.token_hex is patched to deterministic key material so the
    test knows the exact hex to hunt for. stdout, stderr, and logging
    are all captured; the key hex must appear in NONE of them. The
    key id stays visible, the registry holds the exact key, the
    registry file is 0600, and no side-channel key files are created.
    """

    KEY1 = "aa" * 32  # deterministic stand-in for secrets.token_hex(32)
    KEY2 = "bb" * 32

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vouch-tenants-cli-")
        self.reg_path = os.path.join(self.tmp, "tenants.json")
        self._env = mock.patch.dict(
            os.environ, {"GATEKEEPER_TENANTS_PATH": self.reg_path})
        self._env.start()
        # deterministic key material: create -> KEY1, rotate -> KEY2
        self._token_hex = mock.patch("gatekeeper.tenants.secrets.token_hex",
                                     side_effect=[self.KEY1, self.KEY2])
        self._token_hex.start()
        from gatekeeper import tenants as tenants_mod  # noqa: E402
        self.tenants_mod = tenants_mod
        self._log_records = []
        handler = logging.Handler()
        handler.emit = self._log_records.append
        self._log_handler = handler
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)

    def tearDown(self):
        self._token_hex.stop()
        self._env.stop()

    def _run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        self._log_records.clear()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = self.tenants_mod.main(["tenants", *argv])
        logs = "\n".join(r.getMessage() for r in self._log_records)
        return rc, out.getvalue(), err.getvalue(), logs

    def _assert_no_key_material(self, *channels):
        for key_hex in (self.KEY1, self.KEY2):
            for i, text in enumerate(channels):
                self.assertNotIn(
                    key_hex, text,
                    f"key material leaked into channel {i}: {text!r}")

    def _assert_no_capture_files(self):
        leftovers = [f for f in os.listdir(self.tmp)
                     if f.endswith(".key")]
        self.assertEqual(leftovers, [],
                         f"side-channel key files created: {leftovers}")

    def test_create_prints_kid_not_key(self):
        rc, out, err, logs = self._run("create", "acme")
        self.assertEqual(rc, 0)
        self._assert_no_key_material(out, err, logs)
        self._assert_no_capture_files()
        self.assertIn("k1", out)  # the key id is fine to print
        self.assertIn("acme", out)
        # the registry holds the exact deterministic key, owner-only
        reg = TenantRegistry(self.reg_path)
        kid, key = reg.signing_key("acme")
        self.assertEqual((kid, key.hex()), ("k1", self.KEY1))
        self.assertEqual(stat.S_IMODE(os.stat(self.reg_path).st_mode), 0o600)

    def test_rotate_prints_kid_not_key(self):
        self._run("create", "acme")
        rc, out, err, logs = self._run("rotate", "acme")
        self.assertEqual(rc, 0)
        self._assert_no_key_material(out, err, logs)
        self._assert_no_capture_files()
        self.assertIn("k2", out)
        self.assertIn("acme", out)
        reg = TenantRegistry(self.reg_path)
        kid, key = reg.signing_key("acme")
        self.assertEqual((kid, key.hex()), ("k2", self.KEY2))
        # the retired key is still there and still verifiable
        self.assertEqual(reg.verification_keys("acme")["k1"].hex(), self.KEY1)
        self.assertEqual(stat.S_IMODE(os.stat(self.reg_path).st_mode), 0o600)

    def test_list_prints_no_key_material(self):
        self._run("create", "acme")
        self._run("rotate", "acme")
        rc, out, err, logs = self._run("list")
        self.assertEqual(rc, 0)
        self._assert_no_key_material(out, err, logs)
        self._assert_no_capture_files()

    def test_registry_file_is_0600(self):
        self._run("create", "acme")
        self.assertEqual(stat.S_IMODE(os.stat(self.reg_path).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
