"""Tests for M-3: DNS challenges expire and are single-use.

- create_dns_challenge mints a challenge_id; verify_dns_challenge fails
  closed on expired / future-dated / id-less / already-consumed
  challenges (it never mutates).
- consume_dns_challenge records single use; enroll_principal_tier1
  consumes exactly once, AFTER the enroll event is appended.
- The operator console persists minted challenges and keeps a
  store-backed consumed-challenge registry, so single-use holds across
  processes; enroll-tier1 no longer rebuilds challenges on the fly
  (which would reset the expiry clock).

All keys are throwaway test keys. No network: fetchers are stubbed.
"""
import base64
import io
import contextlib
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from services.verifier import ed25519  # noqa: E402
from services.verifier.enrollment import (  # noqa: E402
    CHALLENGE_TTL_S, TransparencyLog, consume_dns_challenge,
    create_dns_challenge, enroll_principal_tier1, jwk_thumbprint,
    verify_dns_challenge)
from services.operator import console  # noqa: E402

OP_PRIV, OP_PUB = ed25519.keypair_hex()
DOMAIN = "example.com"


def _rmtree(d):
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def _tmp_log(testcase):
    d = tempfile.mkdtemp(prefix="vouch-m3-")
    testcase.addCleanup(_rmtree, d)
    return TransparencyLog(os.path.join(d, "transparency.jsonl"))


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwks_for(pub_hex):
    return {"keys": [{"kty": "OKP", "crv": "Ed25519",
                      "kid": jwk_thumbprint(pub_hex),
                      "x": _b64u(bytes.fromhex(pub_hex))}]}


def _enroll(log, principal_id, pub_hex, challenge, consumed, domain=DOMAIN,
            fetch_txt=None):
    if fetch_txt is None:
        fetch_txt = lambda name: ['"%s"' % challenge["token"]]  # noqa: E731
    return enroll_principal_tier1(
        log=log, principal_id=principal_id, domain=domain,
        pubkey_hex=pub_hex, label="prod", challenge=challenge,
        fetch_txt=fetch_txt, fetch_https=lambda url: _jwks_for(pub_hex),
        operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB,
        consumed_challenges=consumed)


class ChallengeShapeTest(unittest.TestCase):
    def test_challenge_carries_unique_id(self):
        a = create_dns_challenge(DOMAIN)
        b = create_dns_challenge(DOMAIN)
        for ch in (a, b):
            self.assertIsInstance(ch["challenge_id"], str)
            self.assertTrue(ch["challenge_id"].startswith("chc-"))
        self.assertNotEqual(a["challenge_id"], b["challenge_id"])

    def test_id_less_challenge_fails_closed(self):
        # The pre-M-3 challenge shape (no challenge_id) is rejected.
        ch = create_dns_challenge(DOMAIN)
        del ch["challenge_id"]
        ok, reason = verify_dns_challenge(ch, lambda n: [])
        self.assertFalse(ok)
        self.assertIn("challenge_id", reason)

    def test_bad_created_at_fails_closed(self):
        ch = create_dns_challenge(DOMAIN)
        for bad in (None, "yesterday", True):
            ch2 = dict(ch, created_at=bad)
            ok, _ = verify_dns_challenge(ch2, lambda n: [])
            self.assertFalse(ok, bad)


class ChallengeExpiryTest(unittest.TestCase):
    def _fresh(self):
        ch = create_dns_challenge(DOMAIN)
        fetch = lambda name: ['"%s"' % ch["token"]]  # noqa: E731
        return ch, fetch

    def test_fresh_challenge_verifies(self):
        ch, fetch = self._fresh()
        ok, _ = verify_dns_challenge(ch, fetch)
        self.assertTrue(ok)

    def test_expired_challenge_rejected(self):
        ch, fetch = self._fresh()
        now = time.time()
        ok, reason = verify_dns_challenge(ch, fetch, now=now + 1)
        self.assertTrue(ok)  # sanity: barely inside
        ok, reason = verify_dns_challenge(
            ch, fetch, now=ch["created_at"] + CHALLENGE_TTL_S + 1)
        self.assertFalse(ok)
        self.assertIn("expired", reason)

    def test_expiry_boundary(self):
        ch, fetch = self._fresh()
        at_ttl = ch["created_at"] + CHALLENGE_TTL_S
        ok, _ = verify_dns_challenge(ch, fetch, now=at_ttl)
        self.assertTrue(ok)  # exactly at TTL: still valid
        ok, reason = verify_dns_challenge(ch, fetch, now=at_ttl + 0.001)
        self.assertFalse(ok)
        self.assertIn("expired", reason)

    def test_future_created_at_rejected(self):
        ch, fetch = self._fresh()
        ch = dict(ch, created_at=time.time() + 3600)
        ok, reason = verify_dns_challenge(ch, fetch)
        self.assertFalse(ok)
        self.assertIn("future", reason)

    def test_enroll_with_expired_challenge_raises(self):
        log = _tmp_log(self)
        _, pub = ed25519.keypair_hex()
        ch = create_dns_challenge(DOMAIN)
        ch = dict(ch, created_at=time.time() - CHALLENGE_TTL_S - 10)
        with self.assertRaisesRegex(ValueError, "expired"):
            _enroll(log, "acme", pub, ch, consumed=set())


class SingleUseTest(unittest.TestCase):
    def test_verify_is_read_only(self):
        ch = create_dns_challenge(DOMAIN)
        consumed = set()
        ok, _ = verify_dns_challenge(
            ch, lambda n: ['"%s"' % ch["token"]], consumed=consumed)
        self.assertTrue(ok)
        self.assertEqual(consumed, set())  # verify() never mutates

    def test_verify_rejects_consumed_challenge(self):
        ch = create_dns_challenge(DOMAIN)
        ok, reason = verify_dns_challenge(
            ch, lambda n: ['"%s"' % ch["token"]],
            consumed={ch["challenge_id"]})
        self.assertFalse(ok)
        self.assertIn("already consumed", reason)

    def test_consume_then_double_consume_raises(self):
        ch = create_dns_challenge(DOMAIN)
        consumed = set()
        self.assertEqual(consume_dns_challenge(consumed, ch),
                         ch["challenge_id"])
        self.assertIn(ch["challenge_id"], consumed)
        with self.assertRaisesRegex(ValueError, "already consumed"):
            consume_dns_challenge(consumed, ch)

    def test_consume_malformed_raises(self):
        with self.assertRaises(ValueError):
            consume_dns_challenge(set(), {"token": "x"})  # no challenge_id
        with self.assertRaises(ValueError):
            consume_dns_challenge(set(), "not-a-dict")

    def test_enroll_consumes_exactly_once(self):
        log = _tmp_log(self)
        _, pub = ed25519.keypair_hex()
        ch = create_dns_challenge(DOMAIN)
        consumed = set()
        _enroll(log, "acme", pub, ch, consumed)
        self.assertEqual(consumed, {ch["challenge_id"]})
        # Replay of the same challenge: rejected, no second enrollment.
        with self.assertRaisesRegex(ValueError, "already consumed"):
            _enroll(log, "acme2", pub, ch, consumed)
        self.assertEqual(len(log.entries()), 1)

    def test_failed_enroll_does_not_consume(self):
        # Enrollment that fails AFTER the challenge check (key missing
        # from the JWKS) leaves the challenge reusable — the DNS record
        # is still published, so the operator can retry.
        log = _tmp_log(self)
        _, pub = ed25519.keypair_hex()
        _, other = ed25519.keypair_hex()
        ch = create_dns_challenge(DOMAIN)
        consumed = set()
        with self.assertRaisesRegex(ValueError, "key directory"):
            enroll_principal_tier1(
                log=log, principal_id="acme", domain=DOMAIN,
                pubkey_hex=pub, label="prod", challenge=ch,
                fetch_txt=lambda n: ['"%s"' % ch["token"]],
                fetch_https=lambda url: _jwks_for(other),  # wrong key
                operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB,
                consumed_challenges=consumed)
        self.assertEqual(consumed, set())
        # ... and the challenge still verifies.
        ok, _ = verify_dns_challenge(
            ch, lambda n: ['"%s"' % ch["token"]], consumed=consumed)
        self.assertTrue(ok)

    def test_no_consumed_set_means_no_enforcement(self):
        log = _tmp_log(self)
        _, pub = ed25519.keypair_hex()
        ch = create_dns_challenge(DOMAIN)
        _enroll(log, "acme", pub, ch, None)
        _enroll(log, "acme2", pub, ch, None)  # library opt-out: allowed
        self.assertEqual(len(log.entries()), 2)


def _run(argv, store):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = console.main(["--store", store] + argv)
    return rc, out.getvalue(), err.getvalue()


class ConsoleChallengeLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = os.path.join(self.tmp.name, "store")
        rc, _out, err = _run(["init-operator"], self.store)
        self.assertEqual(rc, 0, err)
        self._old_txt, self._old_https = console.fetch_txt, console.fetch_https
        self.records = {}
        self.jwks = {}
        console.fetch_txt = lambda name: self.records.get(name, [])
        console.fetch_https = lambda url: self.jwks[url]
        _, self.pub = ed25519.keypair_hex()

    def tearDown(self):
        console.fetch_txt = self._old_txt
        console.fetch_https = self._old_https
        self.tmp.cleanup()

    def _mint(self, domain=DOMAIN):
        rc, out, err = _run(["dns-challenge", "--domain", domain],
                            self.store)
        self.assertEqual(rc, 0, err)
        import re
        m = re.search(r"--challenge-token ([0-9a-f]{64})", out)
        self.assertIsNotNone(m, out)
        self.assertIn("single-use", out)
        return m.group(1)

    def _enroll_args(self, pid, domain, pub, token):
        return ["enroll-tier1", "--principal", pid, "--domain", domain,
                "--pubkey", pub, "--label", "web",
                "--challenge-token", token]

    def test_dns_challenge_persists(self):
        token = self._mint()
        chdir = os.path.join(self.store, "challenges")
        files = os.listdir(chdir)
        self.assertEqual(len(files), 1)
        with open(os.path.join(chdir, files[0])) as f:
            stored = json.load(f)
        self.assertEqual(stored["token"], token)
        self.assertTrue(stored["challenge_id"].startswith("chc-"))
        # 0600: no wider access.
        self.assertEqual(
            os.stat(os.path.join(chdir, files[0])).st_mode & 0o777, 0o600)

    def test_enroll_unknown_token_fails_closed(self):
        rc, _out, err = _run(
            self._enroll_args("s", DOMAIN, self.pub, "tok-" + "ab" * 16),
            self.store)
        self.assertEqual(rc, 2)
        self.assertIn("unknown challenge token", err)

    def test_full_flow_then_replay_rejected(self):
        token = self._mint()
        self.records["_vouch-challenge." + DOMAIN] = [token]
        self.jwks["https://" + DOMAIN + "/.well-known/vouch-keys"] = \
            _jwks_for(self.pub)
        rc, out, err = _run(
            self._enroll_args("site", DOMAIN, self.pub, token), self.store)
        self.assertEqual(rc, 0, err)
        self.assertIn("tier domain-control", out)
        # The consumed registry is persisted (cross-process single-use).
        with open(os.path.join(self.store, "consumed_challenges.json")) as f:
            consumed = json.load(f)
        self.assertEqual(len(consumed), 1)
        # Replay of the same token: rejected, no second principal.
        _, other = ed25519.keypair_hex()
        rc, _out, err = _run(
            self._enroll_args("site2", DOMAIN, other, token), self.store)
        self.assertEqual(rc, 2)
        self.assertIn("already consumed", err)

    def test_expired_stored_challenge_rejected(self):
        token = self._mint()
        # Age the stored challenge past the TTL.
        chdir = os.path.join(self.store, "challenges")
        path = os.path.join(chdir, os.listdir(chdir)[0])
        with open(path) as f:
            stored = json.load(f)
        stored["created_at"] = time.time() - CHALLENGE_TTL_S - 60
        with open(path, "w") as f:
            json.dump(stored, f)
        self.records["_vouch-challenge." + DOMAIN] = [token]
        self.jwks["https://" + DOMAIN + "/.well-known/vouch-keys"] = \
            _jwks_for(self.pub)
        rc, _out, err = _run(
            self._enroll_args("site", DOMAIN, self.pub, token), self.store)
        self.assertEqual(rc, 2)
        self.assertIn("expired", err)

    def test_txt_name_mismatch_fails_closed(self):
        token = self._mint()
        rc, _out, err = _run(
            self._enroll_args("s", DOMAIN, self.pub, token)
            + ["--txt-name", "_other." + DOMAIN], self.store)
        self.assertNotEqual(rc, 0)
        self.assertIn("--txt-name", err)


if __name__ == "__main__":
    unittest.main()
