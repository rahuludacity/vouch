"""Tests for Phase 10: Tier 1 DNS-challenge enrollment, key rotation, revoke/suspend.

All keys below are throwaway test keys generated at module load — never
real operator material. No network calls: fetch_txt and fetch_https are
stubbed everywhere; the only live-network code (fetch_txt_via_dig /
fetch_https_json) is exercised only for its fail-closed behavior on
inputs that never leave the box.
"""
import base64
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from services.verifier import ed25519  # noqa: E402
from services.verifier import enrollment  # noqa: E402
from services.verifier.enrollment import (  # noqa: E402
    TransparencyLog, build_manifest, create_dns_challenge,
    enroll_principal_tier0, enroll_principal_tier1,
    fetch_txt_via_dig, jwk_thumbprint, lookup_principal,
    principal_key_status, revoke_key, rotate_key, suspend_principal,
    unsuspend_principal, verify_dns_challenge,
    verify_enrollment_certificate, verify_manifest,
    ROTATION_OVERLAP_S, TIER_DOMAIN_CONTROL)


def _keys():
    return ed25519.keypair_hex()


OP_PRIV, OP_PUB = _keys()


def _tmp_log(testcase):
    d = tempfile.mkdtemp(prefix="vouch-phase10-")
    testcase.addCleanup(_rmtree, d)
    return TransparencyLog(os.path.join(d, "transparency.jsonl"))


def _rmtree(d):
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwks_for(pub_hex, *, by_kid=True, by_x=True):
    keys = []
    entry = {"kty": "OKP", "crv": "Ed25519"}
    if by_kid:
        entry["kid"] = jwk_thumbprint(pub_hex)
    if by_x:
        entry["x"] = _b64u(bytes.fromhex(pub_hex))
    keys.append(entry)
    return {"keys": keys}


DOMAIN = "example.com"


def _enroll_tier1(log, pub_hex, domain=DOMAIN, issued_at=None):
    challenge = create_dns_challenge(domain)
    fetch_txt = lambda name: ['"%s"' % challenge["token"]]  # noqa: E731
    fetch_https = lambda url: _jwks_for(pub_hex)  # noqa: E731
    return enroll_principal_tier1(
        log=log, principal_id="acme", domain=domain,
        pubkey_hex=pub_hex, label="prod",
        challenge=challenge, fetch_txt=fetch_txt, fetch_https=fetch_https,
        operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB,
        issued_at=issued_at)


class ChallengeCreateTest(unittest.TestCase):
    def test_token_is_256_bit_hex(self):
        c = create_dns_challenge(DOMAIN)
        self.assertRegex(c["token"], r"^[0-9a-f]{64}$")

    def test_txt_name(self):
        c = create_dns_challenge(DOMAIN)
        self.assertEqual(c["domain"], DOMAIN)
        self.assertEqual(c["txt_name"], "_vouch-challenge." + DOMAIN)
        self.assertIn("created_at", c)

    def test_tokens_unique(self):
        a = create_dns_challenge(DOMAIN)
        b = create_dns_challenge(DOMAIN)
        self.assertNotEqual(a["token"], b["token"])

    def test_bad_domain_rejected(self):
        for bad in ("", "http://example.com", "exa mple.com",
                    "example.com/", "-bad.com", "a" * 64 + ".com"):
            with self.assertRaises(ValueError, msg=bad):
                create_dns_challenge(bad)

    def test_domain_normalized_lowercase(self):
        c = create_dns_challenge("Example.COM")
        self.assertEqual(c["domain"], "example.com")
        self.assertEqual(c["txt_name"], "_vouch-challenge.example.com")


class VerifyChallengeTest(unittest.TestCase):
    def test_success(self):
        c = create_dns_challenge(DOMAIN)
        ok, reason = verify_dns_challenge(
            c, lambda name: ['"%s"' % c["token"]])
        self.assertTrue(ok, reason)
        # The TXT name passed to the fetcher must be the challenge name.
        seen = []
        verify_dns_challenge(c, lambda name: seen.append(name) or [])
        self.assertEqual(seen, [c["txt_name"]])

    def test_token_among_other_records(self):
        c = create_dns_challenge(DOMAIN)
        ok, _ = verify_dns_challenge(
            c, lambda name: ['"unrelated"', c["token"], '"more"'])
        self.assertTrue(ok)

    def test_wrong_token(self):
        c = create_dns_challenge(DOMAIN)
        ok, reason = verify_dns_challenge(c, lambda name: ['"nope"'])
        self.assertFalse(ok)
        self.assertIn("token", reason)

    def test_empty_records(self):
        c = create_dns_challenge(DOMAIN)
        ok, reason = verify_dns_challenge(c, lambda name: [])
        self.assertFalse(ok)
        self.assertIn("no TXT records", reason)

    def test_fetch_raises_fails_closed(self):
        c = create_dns_challenge(DOMAIN)

        def boom(name):
            raise RuntimeError("dns exploded")

        ok, reason = verify_dns_challenge(c, boom)
        self.assertFalse(ok)
        self.assertIn("TXT lookup failed", reason)

    def test_malformed_challenge_fails_closed(self):
        c = create_dns_challenge(DOMAIN)
        bad = dict(c)
        bad["token"] = "other"
        ok, _ = verify_dns_challenge(bad, lambda name: [c["token"]])
        self.assertFalse(ok)
        ok, _ = verify_dns_challenge({"nope": 1}, lambda name: [])
        self.assertFalse(ok)
        ok, _ = verify_dns_challenge(None, lambda name: [])
        self.assertFalse(ok)

    def test_noncallable_fetch_fails_closed(self):
        c = create_dns_challenge(DOMAIN)
        ok, _ = verify_dns_challenge(c, None)
        self.assertFalse(ok)


class EnrollTier1Test(unittest.TestCase):
    def test_end_to_end(self):
        log = _tmp_log(self)
        _, pub = _keys()
        t0 = 1_789_000_000.0
        cert, entry = _enroll_tier1(log, pub, issued_at=t0)

        self.assertEqual(cert["tier"], TIER_DOMAIN_CONTROL)
        self.assertEqual(cert["domain"], DOMAIN)
        ok, reasons = verify_enrollment_certificate(cert, OP_PUB, now=t0)
        self.assertTrue(ok, reasons)

        self.assertEqual(entry["tier"], TIER_DOMAIN_CONTROL)
        self.assertEqual(entry["domain"], DOMAIN)
        self.assertEqual(entry["status"], "active")
        self.assertEqual(entry["keys"][0]["status"], "active")
        self.assertEqual(entry["keys"][0]["pubkey"], pub)

        manifest = build_manifest(
            log=log, operator_priv_hex=OP_PRIV, operator_pubkey=OP_PUB,
            issued_at=t0)
        ok, reasons = verify_manifest(manifest, OP_PUB, now=t0)
        self.assertTrue(ok, reasons)
        got = lookup_principal(manifest, "acme")
        self.assertEqual(got["domain"], DOMAIN)
        self.assertEqual(
            principal_key_status(got, pub, now=t0), "active")

    def test_kid_only_match(self):
        # JWKS entry carrying only the kid (no x) still binds the key.
        log = _tmp_log(self)
        _, pub = _keys()
        challenge = create_dns_challenge(DOMAIN)
        cert, _ = enroll_principal_tier1(
            log=log, principal_id="acme", domain=DOMAIN,
            pubkey_hex=pub, label="prod", challenge=challenge,
            fetch_txt=lambda name: [challenge["token"]],
            fetch_https=lambda url: _jwks_for(pub, by_x=False),
            operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB)
        self.assertEqual(cert["tier"], TIER_DOMAIN_CONTROL)

    def test_bad_challenge_raises(self):
        log = _tmp_log(self)
        _, pub = _keys()
        challenge = create_dns_challenge(DOMAIN)
        with self.assertRaises(ValueError):
            enroll_principal_tier1(
                log=log, principal_id="acme", domain=DOMAIN,
                pubkey_hex=pub, label="prod", challenge=challenge,
                fetch_txt=lambda name: ['"wrong-token"'],
                fetch_https=lambda url: _jwks_for(pub),
                operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB)

    def test_challenge_for_other_domain_raises(self):
        log = _tmp_log(self)
        _, pub = _keys()
        challenge = create_dns_challenge("other.example")
        with self.assertRaises(ValueError):
            enroll_principal_tier1(
                log=log, principal_id="acme", domain=DOMAIN,
                pubkey_hex=pub, label="prod", challenge=challenge,
                fetch_txt=lambda name: [challenge["token"]],
                fetch_https=lambda url: _jwks_for(pub),
                operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB)

    def test_pubkey_not_in_jwks_raises(self):
        log = _tmp_log(self)
        _, pub = _keys()
        _, other = _keys()
        challenge = create_dns_challenge(DOMAIN)
        with self.assertRaises(ValueError):
            enroll_principal_tier1(
                log=log, principal_id="acme", domain=DOMAIN,
                pubkey_hex=pub, label="prod", challenge=challenge,
                fetch_txt=lambda name: [challenge["token"]],
                fetch_https=lambda url: _jwks_for(other),
                operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB)

    def test_https_fetch_failure_raises(self):
        log = _tmp_log(self)
        _, pub = _keys()
        challenge = create_dns_challenge(DOMAIN)

        def boom(url):
            raise OSError("network down")

        with self.assertRaises(ValueError):
            enroll_principal_tier1(
                log=log, principal_id="acme", domain=DOMAIN,
                pubkey_hex=pub, label="prod", challenge=challenge,
                fetch_txt=lambda name: [challenge["token"]],
                fetch_https=boom,
                operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB)

    def test_malformed_jwks_raises(self):
        log = _tmp_log(self)
        _, pub = _keys()
        challenge = create_dns_challenge(DOMAIN)
        for bad in ({"nope": 1}, {"keys": "notalist"}, ["keys"]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                enroll_principal_tier1(
                    log=log, principal_id="acme", domain=DOMAIN,
                    pubkey_hex=pub, label="prod", challenge=challenge,
                    fetch_txt=lambda name: [challenge["token"]],
                    fetch_https=lambda url: bad,
                    operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB)


class RotateKeyTest(unittest.TestCase):
    def _enroll(self, log, t0):
        _, pub = _keys()
        enroll_principal_tier0(
            log=log, principal_id="acme", pubkey_hex=pub, label="prod",
            operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB,
            issued_at=t0)
        return pub

    def test_rotate_overlap_then_expire(self):
        log = _tmp_log(self)
        t0 = 1_789_000_000.0
        old_priv, old_pub = _keys()
        enroll_principal_tier0(
            log=log, principal_id="acme", pubkey_hex=old_pub, label="prod",
            operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB,
            issued_at=t0)
        _, new_pub = _keys()
        t1 = t0 + 3600
        entry = rotate_key(
            log=log, principal_id="acme",
            old_pubkey_hex=old_pub, new_pubkey_hex=new_pub, label="prod-2",
            operator_priv_hex=OP_PRIV, issued_at=t1)
        self.assertEqual(entry["type"], "rotate")
        p = entry["payload"]
        self.assertEqual(p["principal_id"], "acme")
        self.assertEqual(p["old_key_id"], jwk_thumbprint(old_pub))
        self.assertEqual(p["new_key"]["pubkey"], new_pub)
        self.assertEqual(p["new_key"]["key_id"], jwk_thumbprint(new_pub))
        self.assertEqual(p["rotated_at"], t1)
        self.assertEqual(p["overlap_s"], ROTATION_OVERLAP_S)

        manifest = build_manifest(
            log=log, operator_priv_hex=OP_PRIV, operator_pubkey=OP_PUB,
            issued_at=t1)
        ok, reasons = verify_manifest(manifest, OP_PUB, now=t1)
        self.assertTrue(ok, reasons)
        got = lookup_principal(manifest, "acme")
        # Within the 72h overlap the old key still verifies.
        self.assertEqual(
            principal_key_status(got, old_pub, now=t1 + 3600),
            "superseded-valid")
        self.assertEqual(
            principal_key_status(got, new_pub, now=t1 + 3600), "active")
        # Past the overlap the old key is dead.
        self.assertEqual(
            principal_key_status(
                got, old_pub, now=t1 + ROTATION_OVERLAP_S + 1),
            "superseded-expired")
        self.assertEqual(
            principal_key_status(
                got, new_pub, now=t1 + ROTATION_OVERLAP_S + 1), "active")

    def test_rotate_rejects_bad_input(self):
        log = _tmp_log(self)
        t0 = 1_789_000_000.0
        old_pub = self._enroll(log, t0)
        _, new_pub = _keys()
        _, other_pub = _keys()

        with self.assertRaises(ValueError):  # unknown principal
            rotate_key(log=log, principal_id="nobody",
                       old_pubkey_hex=old_pub, new_pubkey_hex=new_pub,
                       label="x", operator_priv_hex=OP_PRIV)
        with self.assertRaises(ValueError):  # old key not enrolled
            rotate_key(log=log, principal_id="acme",
                       old_pubkey_hex=other_pub, new_pubkey_hex=new_pub,
                       label="x", operator_priv_hex=OP_PRIV)
        with self.assertRaises(ValueError):  # new == old
            rotate_key(log=log, principal_id="acme",
                       old_pubkey_hex=old_pub, new_pubkey_hex=old_pub,
                       label="x", operator_priv_hex=OP_PRIV)
        with self.assertRaises(ValueError):  # bad new key
            rotate_key(log=log, principal_id="acme",
                       old_pubkey_hex=old_pub, new_pubkey_hex="zz",
                       label="x", operator_priv_hex=OP_PRIV)
        with self.assertRaises(ValueError):  # bad overlap
            rotate_key(log=log, principal_id="acme",
                       old_pubkey_hex=old_pub, new_pubkey_hex=new_pub,
                       label="x", operator_priv_hex=OP_PRIV, overlap_s=0)

        rotate_key(log=log, principal_id="acme",
                   old_pubkey_hex=old_pub, new_pubkey_hex=new_pub,
                   label="prod-2", operator_priv_hex=OP_PRIV,
                   issued_at=t0 + 10)
        _, newer_pub = _keys()
        with self.assertRaises(ValueError):  # old key no longer active
            rotate_key(log=log, principal_id="acme",
                       old_pubkey_hex=old_pub, new_pubkey_hex=newer_pub,
                       label="x", operator_priv_hex=OP_PRIV)
        with self.assertRaises(ValueError):  # new key already enrolled
            rotate_key(log=log, principal_id="acme",
                       old_pubkey_hex=new_pub, new_pubkey_hex=new_pub,
                       label="x", operator_priv_hex=OP_PRIV)


class RevokeSuspendTest(unittest.TestCase):
    def _enroll(self, t0):
        log = _tmp_log(self)
        _, pub = _keys()
        enroll_principal_tier0(
            log=log, principal_id="acme", pubkey_hex=pub, label="prod",
            operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB,
            issued_at=t0)
        return log, pub

    def _manifest(self, log, now):
        m = build_manifest(
            log=log, operator_priv_hex=OP_PRIV, operator_pubkey=OP_PUB,
            issued_at=now)
        ok, reasons = verify_manifest(m, OP_PUB, now=now)
        self.assertTrue(ok, reasons)
        return lookup_principal(m, "acme")

    def test_revoke_key(self):
        t0 = 1_789_000_000.0
        log, pub = self._enroll(t0)
        entry = revoke_key(
            log=log, principal_id="acme", pubkey_hex=pub,
            reason="key suspected compromised",
            operator_priv_hex=OP_PRIV, issued_at=t0 + 5)
        self.assertEqual(entry["type"], "revoke-key")
        self.assertEqual(entry["payload"]["key_id"], jwk_thumbprint(pub))
        got = self._manifest(log, t0 + 10)
        self.assertEqual(principal_key_status(got, pub, now=t0 + 10),
                         "revoked")
        with self.assertRaises(ValueError):  # double revoke
            revoke_key(log=log, principal_id="acme", pubkey_hex=pub,
                       reason="again", operator_priv_hex=OP_PRIV)
        with self.assertRaises(ValueError):  # unknown key
            revoke_key(log=log, principal_id="acme",
                       pubkey_hex=_keys()[1], reason="x",
                       operator_priv_hex=OP_PRIV)

    def test_suspend_unsuspend(self):
        t0 = 1_789_000_000.0
        log, pub = self._enroll(t0)
        entry = suspend_principal(
            log=log, principal_id="acme", reason="abuse report",
            operator_priv_hex=OP_PRIV, issued_at=t0 + 5)
        self.assertEqual(entry["type"], "suspend")
        got = self._manifest(log, t0 + 10)
        self.assertEqual(got["status"], "suspended")
        self.assertEqual(principal_key_status(got, pub, now=t0 + 10),
                         "suspended")
        with self.assertRaises(ValueError):  # double suspend
            suspend_principal(log=log, principal_id="acme", reason="x",
                              operator_priv_hex=OP_PRIV)

        unsuspend_principal(log=log, principal_id="acme",
                            operator_priv_hex=OP_PRIV, issued_at=t0 + 20)
        got = self._manifest(log, t0 + 30)
        self.assertEqual(got["status"], "active")
        self.assertEqual(principal_key_status(got, pub, now=t0 + 30),
                         "active")
        with self.assertRaises(ValueError):  # not suspended
            unsuspend_principal(log=log, principal_id="acme",
                                operator_priv_hex=OP_PRIV)

    def test_suspend_unknown_principal(self):
        log = _tmp_log(self)
        with self.assertRaises(ValueError):
            suspend_principal(log=log, principal_id="ghost", reason="x",
                              operator_priv_hex=OP_PRIV)


class FetcherHardeningTest(unittest.TestCase):
    def test_dig_fetcher_never_raises_on_bad_input(self):
        self.assertEqual(fetch_txt_via_dig(""), [])
        self.assertEqual(fetch_txt_via_dig("not a domain!!"), [])
        self.assertEqual(fetch_txt_via_dig(None), [])
        # A well-formed name may or may not resolve here, but the
        # fetcher must answer (a list) rather than raise.
        out = fetch_txt_via_dig("_vouch-challenge.invalid", timeout_s=2)
        self.assertIsInstance(out, list)

    def test_https_json_rejects_bad_urls(self):
        for bad in ("http://example.com/k", "ftp://x/y",
                    "https://user@example.com/k", "not a url", ""):
            with self.assertRaises(ValueError, msg=bad):
                enrollment.fetch_https_json(bad)


if __name__ == "__main__":
    unittest.main()
