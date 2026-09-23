"""Tests for Phase 13: minimal operator console CLI (services/operator/console.py).

main(argv) is driven in-process with --store pointed at a temp dir, so no
real HOME is touched. DNS/HTTPS fetchers are stubbed by monkeypatching
console.fetch_txt / console.fetch_https — no network anywhere.
"""
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from services.operator import console  # noqa: E402
from services.verifier import ed25519  # noqa: E402
from services.verifier import enrollment  # noqa: E402

# Fixed labeled test keypairs (not secret — generated for tests).
T_PRIV, T_PUB = ed25519.keypair_hex(
    seed=bytes.fromhex("aa" * 32))
T2_PRIV, T2_PUB = ed25519.keypair_hex(
    seed=bytes.fromhex("bb" * 32))
T3_PRIV, T3_PUB = ed25519.keypair_hex(
    seed=bytes.fromhex("cc" * 32))


def _run(argv, store):
    """Run main() capturing stdout/stderr; return (rc, out, err)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = console.main(["--store", store] + argv)
    return rc, out.getvalue(), err.getvalue()


class ConsoleBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = os.path.join(self.tmp.name, "store")
        rc, _out, err = _run(["init-operator"], self.store)
        self.assertEqual(rc, 0, err)
        # Read the operator private key from the store file (the test's
        # own store, never printed) for the no-leak assertion.
        with open(os.path.join(self.store, "operator.key")) as f:
            self.op_priv = json.load(f)["privkey_hex"]

    def tearDown(self):
        self.tmp.cleanup()

    def new_principal(self, pid="acme", pub=T_PUB, label="prod"):
        rc, out, err = _run(
            ["new-principal", "--principal", pid, "--pubkey", pub,
             "--label", label], self.store)
        self.assertEqual(rc, 0, err)
        return out

    def rebuild(self):
        rc, out, err = _run(["manifest"], self.store)
        self.assertEqual(rc, 0, err)
        with open(os.path.join(self.store, "manifest.json")) as f:
            return json.load(f)


class TestInitOperator(unittest.TestCase):
    def test_init_creates_0600_key_files(self):
        with tempfile.TemporaryDirectory() as d:
            store = os.path.join(d, "s")
            rc, out, err = _run(["init-operator"], store)
            self.assertEqual(rc, 0, err)
            key_path = os.path.join(store, "operator.key")
            self.assertTrue(os.path.exists(key_path))
            mode = stat.S_IMODE(os.stat(key_path).st_mode)
            self.assertEqual(mode, 0o600,
                             f"operator.key mode is {oct(mode)}, want 0600")
            self.assertTrue(os.path.exists(
                os.path.join(store, "operator.pub")))
            self.assertTrue(os.path.exists(
                os.path.join(store, "log.jsonl")))
            # Pubkey printed; the private key never is.
            with open(key_path) as f:
                blob = json.load(f)
            self.assertIn(blob["pubkey_hex"], out)
            self.assertNotIn(blob["privkey_hex"], out)
            self.assertNotIn(blob["privkey_hex"], err)

    def test_double_init_fails_without_force(self):
        with tempfile.TemporaryDirectory() as d:
            store = os.path.join(d, "s")
            self.assertEqual(_run(["init-operator"], store)[0], 0)
            rc, out, err = _run(["init-operator"], store)
            self.assertNotEqual(rc, 0)
            self.assertIn("already exists", err)
            # --force replaces the key.
            rc, out, err = _run(["init-operator", "--force"], store)
            self.assertEqual(rc, 0, err)
            mode = stat.S_IMODE(
                os.stat(os.path.join(store, "operator.key")).st_mode)
            self.assertEqual(mode, 0o600)

    def test_refuses_world_readable_key(self):
        with tempfile.TemporaryDirectory() as d:
            store = os.path.join(d, "s")
            self.assertEqual(_run(["init-operator"], store)[0], 0)
            key_path = os.path.join(store, "operator.key")
            os.chmod(key_path, 0o644)
            rc, out, err = _run(
                ["new-principal", "--principal", "x", "--pubkey", T_PUB,
                 "--label", "l"], store)
            self.assertNotEqual(rc, 0)
            self.assertIn("group/world-readable", err)


class TestLifecycle(ConsoleBase):
    def test_new_principal_enrolls_tier0(self):
        out = self.new_principal()
        self.assertIn("enrolled acme tier allowlist", out)
        m = self.rebuild()
        self.assertEqual(len(m["principals"]), 1)
        pe = m["principals"][0]
        self.assertEqual(pe["principal_id"], "acme")
        self.assertEqual(pe["tier"], "allowlist")
        self.assertEqual(pe["status"], "active")
        self.assertEqual(pe["keys"][0]["pubkey"], T_PUB)

    def test_manifest_verify_roundtrip(self):
        self.new_principal()
        self.rebuild()
        rc, out, err = _run(["verify-manifest"], self.store)
        self.assertEqual(rc, 0, err)
        self.assertIn("manifest OK", out)

    def test_verify_manifest_rejects_tampered(self):
        self.new_principal()
        self.rebuild()
        mpath = os.path.join(self.store, "manifest.json")
        with open(mpath) as f:
            m = json.load(f)
        m["principals"][0]["status"] = "suspended"
        with open(mpath, "w") as f:
            json.dump(m, f)
        rc, out, err = _run(["verify-manifest"], self.store)
        self.assertNotEqual(rc, 0)

    def test_full_lifecycle_reflected_in_manifest(self):
        self.new_principal()
        # rotate: old key superseded, new key active
        rc, out, err = _run(
            ["rotate-key", "--principal", "acme", "--old-pubkey", T_PUB,
             "--new-pubkey", T2_PUB, "--label", "prod-2"], self.store)
        self.assertEqual(rc, 0, err)
        m = self.rebuild()
        keys = {k["pubkey"]: k["status"]
                for k in m["principals"][0]["keys"]}
        self.assertEqual(keys[T_PUB], "superseded")
        self.assertEqual(keys[T2_PUB], "active")
        # revoke the new key
        rc, out, err = _run(
            ["revoke-key", "--principal", "acme", "--pubkey", T2_PUB,
             "--reason", "lost laptop", "--yes"], self.store)
        self.assertEqual(rc, 0, err)
        m = self.rebuild()
        keys = {k["pubkey"]: k["status"]
                for k in m["principals"][0]["keys"]}
        self.assertEqual(keys[T2_PUB], "revoked")
        # suspend then unsuspend the principal
        rc, out, err = _run(
            ["suspend", "--principal", "acme", "--reason", "incident",
             "--yes"], self.store)
        self.assertEqual(rc, 0, err)
        m = self.rebuild()
        self.assertEqual(m["principals"][0]["status"], "suspended")
        rc, out, err = _run(["unsuspend", "--principal", "acme"], self.store)
        self.assertEqual(rc, 0, err)
        m = self.rebuild()
        self.assertEqual(m["principals"][0]["status"], "active")
        # The revoked key stays revoked after unsuspend.
        keys = {k["pubkey"]: k["status"]
                for k in m["principals"][0]["keys"]}
        self.assertEqual(keys[T2_PUB], "revoked")
        # Manifest still verifies at the end.
        rc, out, err = _run(["verify-manifest"], self.store)
        self.assertEqual(rc, 0, err)

    def test_destructive_ops_need_yes(self):
        self.new_principal()
        for argv in (
                ["revoke-key", "--principal", "acme", "--pubkey", T_PUB,
                 "--reason", "x"],
                ["revoke-credential", "--principal", "acme",
                 "--revocation-handle", "rh-1", "--reason", "x"],
                ["suspend", "--principal", "acme", "--reason", "x"]):
            rc, out, err = _run(argv, self.store)
            self.assertNotEqual(rc, 0)
            self.assertIn("--yes", err)

    def test_revoke_credential_end_to_end(self):
        self.new_principal()
        handle = "rh-deadbeef1234"
        rc, out, err = _run(
            ["revoke-credential", "--principal", "acme",
             "--revocation-handle", handle, "--reason", "compromised",
             "--yes"], self.store)
        self.assertEqual(rc, 0, err)
        self.assertIn(handle, out)
        m = self.rebuild()
        self.assertIn(handle, m["revoked_credentials"])
        rc, out, err = _run(["verify-manifest"], self.store)
        self.assertEqual(rc, 0, err)
        # The frozen fold payload is exactly the four fields.
        log = enrollment.TransparencyLog(
            os.path.join(self.store, "log.jsonl"))
        rev = [e for e in log.entries() if e["type"] == "revoke-credential"]
        self.assertEqual(len(rev), 1)
        self.assertEqual(
            set(rev[0]["payload"].keys()),
            {"principal_id", "revocation_handle", "revoked_at", "reason"})

    def test_revoke_credential_unknown_principal_fails(self):
        rc, out, err = _run(
            ["revoke-credential", "--principal", "ghost",
             "--revocation-handle", "rh-x", "--reason", "x", "--yes"],
            self.store)
        self.assertNotEqual(rc, 0)
        self.assertIn("unknown principal", err)


class TestEnrollTier1(ConsoleBase):
    def setUp(self):
        super().setUp()
        self._old_txt, self._old_https = console.fetch_txt, console.fetch_https
        self.records = {}
        self.jwks = {}
        console.fetch_txt = lambda name: self.records.get(name, [])
        console.fetch_https = lambda url: self.jwks[url]

    def tearDown(self):
        console.fetch_txt = self._old_txt
        console.fetch_https = self._old_https
        super().tearDown()

    def _jwks_for(self, pub):
        from services.verifier.enrollment import _b64url_nopad
        return {"keys": [{"kty": "OKP", "crv": "Ed25519",
                          "x": _b64url_nopad(bytes.fromhex(pub))}]}

    def test_enroll_tier1_needs_txt_first_then_succeeds(self):
        domain = "example.com"
        token = "tok-" + "ab" * 16
        # First attempt: no token published -> exit 2, "publish TXT then re-run".
        rc, out, err = _run(
            ["enroll-tier1", "--principal", "site", "--domain", domain,
             "--pubkey", T3_PUB, "--label", "web",
             "--challenge-token", token], self.store)
        self.assertEqual(rc, 2)
        self.assertIn("publish TXT then re-run", err)
        # dns-challenge mints the record the operator must publish.
        rc, out, err = _run(["dns-challenge", "--domain", domain], self.store)
        self.assertEqual(rc, 0, err)
        # Publish the token (stubbed DNS) and serve the JWKS (stubbed HTTPS).
        self.records["_vouch-challenge." + domain] = [token]
        self.jwks["https://" + domain + "/.well-known/vouch-keys"] = \
            self._jwks_for(T3_PUB)
        rc, out, err = _run(
            ["enroll-tier1", "--principal", "site", "--domain", domain,
             "--pubkey", T3_PUB, "--label", "web",
             "--challenge-token", token], self.store)
        self.assertEqual(rc, 0, err)
        self.assertIn("tier domain-control", out)
        m = self.rebuild()
        pe = next(p for p in m["principals"]
                  if p["principal_id"] == "site")
        self.assertEqual(pe["tier"], "domain-control")
        self.assertEqual(pe["domain"], domain)

    def test_enroll_tier1_rejects_key_missing_from_jwks(self):
        domain = "example.org"
        token = "tok-" + "cd" * 16
        self.records["_vouch-challenge." + domain] = [token]
        self.jwks["https://" + domain + "/.well-known/vouch-keys"] = \
            self._jwks_for(T2_PUB)  # wrong key
        rc, out, err = _run(
            ["enroll-tier1", "--principal", "site", "--domain", domain,
             "--pubkey", T3_PUB, "--label", "web",
             "--challenge-token", token], self.store)
        self.assertNotEqual(rc, 0)
        self.assertIn("key directory", err)

    def test_enroll_tier1_without_token_prints_txt_and_exits_2(self):
        rc, out, err = _run(
            ["enroll-tier1", "--principal", "site", "--domain", "example.net",
             "--pubkey", T3_PUB, "--label", "web"], self.store)
        self.assertEqual(rc, 2)
        self.assertIn("_vouch-challenge.example.net", out)
        self.assertIn("publish TXT then re-run", err)


class TestServeManifest(ConsoleBase):
    def test_serve_refuses_without_manifest(self):
        rc, out, err = _run(["serve-manifest", "--port", "8471"], self.store)
        self.assertNotEqual(rc, 0)
        self.assertIn("no manifest.json", err)

    def test_serve_defaults_to_loopback_and_serves_json(self):
        self.new_principal()
        self.rebuild()
        body = open(os.path.join(self.store, "manifest.json"), "rb").read()
        handler = console._manifest_handler(body)
        from http.server import HTTPServer
        server = HTTPServer(("127.0.0.1", 0), handler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/manifest.json")
            with urllib.request.urlopen(req, timeout=5) as resp:
                self.assertEqual(
                    resp.headers.get("Content-Type"), "application/json")
                got = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(got, json.loads(body.decode("utf-8")))
        finally:
            server.shutdown()
            server.server_close()
            t.join(timeout=5)


class TestExitCodesAndLeakAudit(unittest.TestCase):
    def test_bad_args_exit_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            store = os.path.join(d, "s")
            # argparse errors raise SystemExit(2); treat as nonzero.
            for argv in ([], ["bogus-command"], ["new-principal"],
                         ["manifest", "--valid-for-s", "abc"]):
                with self.assertRaises(SystemExit) as cm:
                    console.main(["--store", store] + argv)
                self.assertNotEqual(cm.exception.code, 0,
                                    f"{argv} should fail")

    def test_privkey_never_in_any_output(self):
        """Every command's stdout/stderr must be free of the privkey hex."""
        with tempfile.TemporaryDirectory() as d:
            store = os.path.join(d, "s")
            transcripts = []
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                self.assertEqual(console.main(
                    ["--store", store, "init-operator"]), 0)
            transcripts += [out.getvalue(), err.getvalue()]
            with open(os.path.join(store, "operator.key")) as f:
                priv = json.load(f)["privkey_hex"]
            # Stub the tier1 fetchers so the whole flow runs offline.
            old_txt, old_https = console.fetch_txt, console.fetch_https
            console.fetch_txt = lambda name: ["tok"]
            console.fetch_https = lambda url: {"keys": []}
            try:
                flows = [
                    ["new-principal", "--principal", "p1",
                     "--pubkey", T_PUB, "--label", "l"],
                    ["dns-challenge", "--domain", "example.com"],
                    ["enroll-tier1", "--principal", "p2",
                     "--domain", "example.com", "--pubkey", T2_PUB,
                     "--label", "w", "--challenge-token", "tok"],
                    ["rotate-key", "--principal", "p1", "--old-pubkey", T_PUB,
                     "--new-pubkey", T2_PUB, "--label", "l2"],
                    ["revoke-key", "--principal", "p1", "--pubkey", T2_PUB,
                     "--reason", "r", "--yes"],
                    ["revoke-credential", "--principal", "p1",
                     "--revocation-handle", "rh-9", "--reason", "r",
                     "--yes"],
                    ["suspend", "--principal", "p1", "--reason", "r",
                     "--yes"],
                    ["unsuspend", "--principal", "p1"],
                    ["manifest"],
                    ["verify-manifest"],
                    ["revoke-key", "--principal", "ghost",
                     "--pubkey", T_PUB, "--reason", "r", "--yes"],
                    ["new-principal", "--principal", "bad",
                     "--pubkey", "zz", "--label", "l"],
                ]
                for argv in flows:
                    o, e = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(o), \
                            contextlib.redirect_stderr(e):
                        try:
                            console.main(["--store", store] + argv)
                        except SystemExit:
                            pass
                    transcripts += [o.getvalue(), e.getvalue()]
            finally:
                console.fetch_txt, console.fetch_https = old_txt, old_https
            for i, text in enumerate(transcripts):
                self.assertNotIn(priv, text,
                                 f"privkey hex leaked in transcript {i}")


if __name__ == "__main__":
    unittest.main()
