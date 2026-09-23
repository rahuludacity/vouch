"""Tests for Phase 9 enrollment: transparency log, enrollment certificates,
trust-root manifest, Tier 0 enrollment, and key statuses.

All keys below are throwaway test keys generated at module load — never
real operator material.
"""
import base64
import copy
import hashlib
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
from services.verifier import enrollment  # noqa: E402
from services.verifier.enrollment import (  # noqa: E402
    TransparencyLog, build_manifest, enroll_principal_tier0,
    issue_enrollment_certificate, jwk_thumbprint, lookup_principal,
    principal_key_status, verify_enrollment_certificate, verify_manifest,
    ENROLLMENT_TTL_S, ROTATION_OVERLAP_S)


def _keys():
    return ed25519.keypair_hex()


OP_PRIV, OP_PUB = _keys()


def _tmp_log(testcase):
    d = tempfile.mkdtemp(prefix="vouch-phase9-")
    testcase.addCleanup(_rmtree, d)
    return TransparencyLog(os.path.join(d, "transparency.jsonl"))


def _rmtree(d):
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def _enroll(log, pid="maya", issued_at=None, **kw):
    priv, pub = _keys()
    cert, entry = enroll_principal_tier0(
        log=log, principal_id=pid, pubkey_hex=pub, label="prod",
        operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB,
        issued_at=issued_at, **kw)
    return cert, entry, priv, pub


class ThumbprintTest(unittest.TestCase):
    def test_deterministic(self):
        _, pub = _keys()
        self.assertEqual(jwk_thumbprint(pub), jwk_thumbprint(pub))

    def test_format_43char_base64url(self):
        _, pub = _keys()
        kid = jwk_thumbprint(pub)
        self.assertEqual(len(kid), 43)  # 32 bytes -> 43 base64url chars, no pad
        self.assertRegex(kid, r"^[A-Za-z0-9_-]{43}$")
        self.assertNotIn("=", kid)

    def test_known_answer(self):
        # Independent construction of the RFC 7638 thumbprint for the
        # all-zero pubkey: x = base64url(32 zero bytes), then
        # sha256('{"crv":"Ed25519","kty":"OKP","x":"<x>"}').
        pub = "00" * 32
        x = base64.urlsafe_b64encode(bytes(32)).rstrip(b"=").decode("ascii")
        jwk = '{"crv":"Ed25519","kty":"OKP","x":"%s"}' % x
        want = base64.urlsafe_b64encode(
            hashlib.sha256(jwk.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        self.assertEqual(jwk_thumbprint(pub), want)

    def test_rejects_bad_pubkey(self):
        with self.assertRaises(ValueError):
            jwk_thumbprint("zz")
        with self.assertRaises(ValueError):
            jwk_thumbprint("ab" * 16)  # 16 bytes, not 32


class TransparencyLogTest(unittest.TestCase):
    def test_append_verify_roundtrip(self):
        log = _tmp_log(self)
        e1 = log.append("enroll", {"a": 1}, OP_PRIV)
        e2 = log.append("enroll", {"a": 2}, OP_PRIV)
        self.assertEqual(e1["seq"], 1)
        self.assertEqual(e2["seq"], 2)
        self.assertEqual(e2["prev_hash"], e1["hash"])
        ok, reasons = log.verify()
        self.assertTrue(ok, reasons)
        self.assertEqual(log.seq(), 2)
        self.assertEqual(len(log.entries()), 2)

    def test_entries_are_copies(self):
        log = _tmp_log(self)
        log.append("enroll", {"a": 1}, OP_PRIV)
        ents = log.entries()
        ents[0]["payload"]["a"] = 999
        self.assertEqual(log.entries()[0]["payload"]["a"], 1)

    def test_tamper_one_entry_fails_verify(self):
        log = _tmp_log(self)
        log.append("enroll", {"principal_id": "maya"}, OP_PRIV)
        log.append("enroll", {"principal_id": "leo"}, OP_PRIV)
        # Tamper with the first entry's payload on disk.
        with open(log.path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        e = json.loads(lines[0])
        e["payload"]["principal_id"] = "mallory"
        lines[0] = json.dumps(e, sort_keys=True) + "\n"
        with open(log.path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        ok, reasons = TransparencyLog(log.path).verify()
        self.assertFalse(ok)
        self.assertTrue(any("hash mismatch" in r for r in reasons), reasons)

    def test_tamper_signature_fails_verify(self):
        log = _tmp_log(self)
        log.append("enroll", {"a": 1}, OP_PRIV)
        with open(log.path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        e = json.loads(lines[0])
        e["signature"] = "00" * 64
        lines[0] = json.dumps(e, sort_keys=True) + "\n"
        with open(log.path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        ok, reasons = TransparencyLog(log.path).verify()
        self.assertFalse(ok)
        self.assertTrue(any("bad signature" in r for r in reasons), reasons)

    def test_verify_with_untrusted_operator_fails(self):
        log = _tmp_log(self)
        log.append("enroll", {"a": 1}, OP_PRIV)
        other_priv, other_pub = _keys()
        ok, reasons = TransparencyLog(log.path).verify(
            operator_pubkeys=[other_pub])
        self.assertFalse(ok)
        self.assertTrue(any("not trusted" in r for r in reasons), reasons)

    def test_rejects_unknown_event_type(self):
        log = _tmp_log(self)
        with self.assertRaises(ValueError):
            log.append("bogus-type", {}, OP_PRIV)

    def test_rejects_non_dict_payload(self):
        log = _tmp_log(self)
        with self.assertRaises(ValueError):
            log.append("enroll", ["not", "a", "dict"], OP_PRIV)


class CertificateTest(unittest.TestCase):
    def test_issue_verify_roundtrip(self):
        log = _tmp_log(self)
        cert, entry, _, pub = _enroll(log)
        ok, reasons = verify_enrollment_certificate(cert, OP_PUB)
        self.assertTrue(ok, reasons)
        self.assertEqual(cert["tier"], "allowlist")
        self.assertEqual(cert["enrollment_log_seq"], 1)
        self.assertEqual(cert["key_ids"][0]["pubkey"], pub)
        self.assertEqual(cert["key_ids"][0]["key_id"], jwk_thumbprint(pub))
        # enrollment_log_seq points at the log entry that enrolled it
        self.assertEqual(log.entries()[0]["seq"], cert["enrollment_log_seq"])

    def test_tamper_principal_fails(self):
        log = _tmp_log(self)
        cert, _, _, _ = _enroll(log)
        cert = copy.deepcopy(cert)
        cert["principal_id"] = "mallory"
        ok, _ = verify_enrollment_certificate(cert, OP_PUB)
        self.assertFalse(ok)

    def test_tamper_key_binding_fails(self):
        log = _tmp_log(self)
        cert, _, _, _ = _enroll(log)
        cert = copy.deepcopy(cert)
        _, other_pub = _keys()
        cert["key_ids"][0]["pubkey"] = other_pub  # key_id now mismatched
        ok, reasons = verify_enrollment_certificate(cert, OP_PUB)
        self.assertFalse(ok)
        self.assertTrue(any("does not match" in r for r in reasons), reasons)

    def test_wrong_operator_fails(self):
        log = _tmp_log(self)
        cert, _, _, _ = _enroll(log)
        _, other_pub = _keys()
        ok, reasons = verify_enrollment_certificate(cert, other_pub)
        self.assertFalse(ok)
        self.assertTrue(any("expected operator" in r for r in reasons), reasons)

    def test_expired_cert_fails(self):
        _, pub = _keys()
        cert = issue_enrollment_certificate(
            principal_id="old", tier="allowlist", domain=None,
            key_ids=[{"key_id": jwk_thumbprint(pub), "pubkey": pub,
                      "label": "prod", "status": "active"}],
            operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB,
            log_seq=7, ttl_s=60, issued_at=time.time() - 3600)
        ok, reasons = verify_enrollment_certificate(cert, OP_PUB)
        self.assertFalse(ok)
        self.assertTrue(any("expired" in r for r in reasons), reasons)

    def test_issue_rejects_key_id_mismatch(self):
        _, pub = _keys()
        _, other_pub = _keys()
        with self.assertRaises(ValueError):
            issue_enrollment_certificate(
                principal_id="x", tier="allowlist", domain=None,
                key_ids=[{"key_id": jwk_thumbprint(other_pub),
                          "pubkey": pub, "label": "prod",
                          "status": "active"}],
                operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB,
                log_seq=1)

    def test_issue_rejects_bad_tier(self):
        _, pub = _keys()
        with self.assertRaises(ValueError):
            issue_enrollment_certificate(
                principal_id="x", tier="gold", domain=None,
                key_ids=[{"key_id": jwk_thumbprint(pub), "pubkey": pub,
                          "label": "prod", "status": "active"}],
                operator_priv_hex=OP_PRIV, operator_pub_hex=OP_PUB,
                log_seq=1)

    def test_verify_never_raises_on_garbage(self):
        for bad in (None, "nope", {"tier": "allowlist"}, []):
            ok, _ = verify_enrollment_certificate(bad, OP_PUB)
            self.assertFalse(ok)


class ManifestTest(unittest.TestCase):
    def test_build_verify_roundtrip(self):
        log = _tmp_log(self)
        _enroll(log, pid="maya")
        _enroll(log, pid="leo")
        m = build_manifest(log=log, operator_priv_hex=OP_PRIV,
                           operator_pubkey=OP_PUB)
        ok, reasons = verify_manifest(m, OP_PUB)
        self.assertTrue(ok, reasons)
        self.assertEqual(m["version"], 1)
        self.assertEqual(m["valid_until"] - m["issued_at"], 300)
        self.assertEqual([p["principal_id"] for p in m["principals"]],
                         ["leo", "maya"])  # sorted

    def test_version_strictly_increasing(self):
        log = _tmp_log(self)
        _enroll(log, pid="maya")
        m1 = build_manifest(log=log, operator_priv_hex=OP_PRIV,
                            operator_pubkey=OP_PUB)
        m2 = build_manifest(log=log, operator_priv_hex=OP_PRIV,
                            operator_pubkey=OP_PUB)
        self.assertEqual(m2["version"], m1["version"] + 1)

    def test_stale_manifest_fails(self):
        log = _tmp_log(self)
        _enroll(log, pid="maya")
        m = build_manifest(log=log, operator_priv_hex=OP_PRIV,
                           operator_pubkey=OP_PUB, valid_for_s=60,
                           issued_at=time.time() - 3600)
        ok, reasons = verify_manifest(m, OP_PUB)
        self.assertFalse(ok)
        self.assertTrue(any("stale" in r for r in reasons), reasons)

    def test_tampered_manifest_fails(self):
        log = _tmp_log(self)
        _enroll(log, pid="maya")
        m = build_manifest(log=log, operator_priv_hex=OP_PRIV,
                           operator_pubkey=OP_PUB)
        m = copy.deepcopy(m)
        m["principals"][0]["status"] = "suspended"
        ok, reasons = verify_manifest(m, OP_PUB)
        self.assertFalse(ok)
        self.assertTrue(any("signature invalid" in r for r in reasons), reasons)

    def test_wrong_operator_key_fails(self):
        log = _tmp_log(self)
        _enroll(log, pid="maya")
        m = build_manifest(log=log, operator_priv_hex=OP_PRIV,
                           operator_pubkey=OP_PUB)
        _, other_pub = _keys()
        ok, _ = verify_manifest(m, other_pub)
        self.assertFalse(ok)

    def test_verify_never_raises_on_garbage(self):
        for bad in (None, "nope", {}, {"version": "x"}):
            ok, _ = verify_manifest(bad, OP_PUB)
            self.assertFalse(ok)

    def test_refuses_broken_log(self):
        log = _tmp_log(self)
        log.append("enroll", {"a": 1}, OP_PRIV)
        with open(log.path, "w", encoding="utf-8") as f:
            f.write("{not json}\n")
        with self.assertRaises(ValueError):
            build_manifest(log=log, operator_priv_hex=OP_PRIV,
                           operator_pubkey=OP_PUB)


class Tier0EndToEndTest(unittest.TestCase):
    def test_enroll_cert_manifest_key_status(self):
        log = _tmp_log(self)
        cert, entry, _, pub = _enroll(log, pid="maya")
        # cert verifies
        ok, reasons = verify_enrollment_certificate(cert, OP_PUB)
        self.assertTrue(ok, reasons)
        # manifest contains the principal
        m = build_manifest(log=log, operator_priv_hex=OP_PRIV,
                           operator_pubkey=OP_PUB)
        ok, reasons = verify_manifest(m, [OP_PUB])
        self.assertTrue(ok, reasons)
        found = lookup_principal(m, "maya")
        self.assertIsNotNone(found)
        self.assertEqual(found["tier"], "allowlist")
        self.assertEqual(found["status"], "active")
        self.assertEqual(found["enrollment_log_seq"], 1)
        self.assertEqual(found["keys"][0]["status"], "active")
        # key status active
        self.assertEqual(principal_key_status(found, pub), "active")
        # cert and manifest entry agree
        self.assertEqual(entry["principal_id"], cert["principal_id"])
        self.assertEqual(entry["enrollment_log_seq"],
                         cert["enrollment_log_seq"])

    def test_unknown_principal(self):
        log = _tmp_log(self)
        _enroll(log, pid="maya")
        m = build_manifest(log=log, operator_priv_hex=OP_PRIV,
                           operator_pubkey=OP_PUB)
        self.assertIsNone(lookup_principal(m, "nobody"))
        self.assertEqual(principal_key_status(None, "00" * 32), "unknown")

    def test_unknown_key_for_known_principal(self):
        log = _tmp_log(self)
        _enroll(log, pid="maya")
        m = build_manifest(log=log, operator_priv_hex=OP_PRIV,
                           operator_pubkey=OP_PUB)
        found = lookup_principal(m, "maya")
        _, other_pub = _keys()
        self.assertEqual(principal_key_status(found, other_pub), "unknown")

    def test_lookup_returns_copy(self):
        log = _tmp_log(self)
        _enroll(log, pid="maya")
        m = build_manifest(log=log, operator_priv_hex=OP_PRIV,
                           operator_pubkey=OP_PUB)
        found = lookup_principal(m, "maya")
        found["status"] = "suspended"
        self.assertEqual(lookup_principal(m, "maya")["status"], "active")


class KeyStatusTest(unittest.TestCase):
    """principal_key_status understands every status, including the
    Phase 10 rotation/revoke/suspend states (folded from raw log events)."""

    def _entry(self, key_status="active", principal_status="active",
               valid_until=None, expires_at=None):
        _, pub = _keys()
        now = time.time()
        return ({
            "principal_id": "p",
            "tier": "allowlist",
            "domain": None,
            "keys": [{
                "key_id": jwk_thumbprint(pub),
                "pubkey": pub,
                "label": "prod",
                "status": key_status,
                "valid_until": (valid_until if valid_until is not None
                                else now + 3600),
            }],
            "status": principal_status,
            "enrollment_log_seq": 1,
            "enrolled_at": now - 10,
            "expires_at": expires_at if expires_at is not None else now + 3600,
        }, pub)

    def test_active(self):
        e, pub = self._entry()
        self.assertEqual(principal_key_status(e, pub), "active")

    def test_revoked(self):
        e, pub = self._entry(key_status="revoked")
        self.assertEqual(principal_key_status(e, pub), "revoked")

    def test_suspended_principal(self):
        e, pub = self._entry(principal_status="suspended")
        self.assertEqual(principal_key_status(e, pub), "suspended")

    def test_suspended_key(self):
        e, pub = self._entry(key_status="suspended")
        self.assertEqual(principal_key_status(e, pub), "suspended")

    def test_superseded_valid_within_overlap(self):
        e, pub = self._entry(key_status="superseded",
                             valid_until=time.time() + ROTATION_OVERLAP_S)
        self.assertEqual(principal_key_status(e, pub), "superseded-valid")

    def test_superseded_expired_after_overlap(self):
        e, pub = self._entry(key_status="superseded",
                             valid_until=time.time() - 1)
        self.assertEqual(principal_key_status(e, pub), "superseded-expired")

    def test_expired_enrollment(self):
        e, pub = self._entry(expires_at=time.time() - 1)
        self.assertEqual(principal_key_status(e, pub), "expired")

    def test_unknown_on_garbage(self):
        _, pub = _keys()
        for bad in (None, {}, {"keys": "nope"}, {"keys": []}):
            self.assertEqual(principal_key_status(bad, pub), "unknown")
        e, _ = self._entry()
        self.assertEqual(principal_key_status(e, "zz"), "unknown")

    def test_rotation_fold_marks_superseded_with_overlap(self):
        # Phase 10's rotate event, folded by the Phase 9 manifest builder.
        log = _tmp_log(self)
        _, old_pub = _keys()
        _, new_pub = _keys()
        now = time.time()
        log.append("enroll", {
            "principal_id": "maya", "tier": "allowlist", "domain": None,
            "keys": [{"key_id": jwk_thumbprint(old_pub),
                      "pubkey": old_pub, "label": "prod"}],
            "enrolled_at": now, "expires_at": now + ENROLLMENT_TTL_S,
        }, OP_PRIV, ts=now)
        log.append("rotate", {
            "principal_id": "maya",
            "old_key_id": jwk_thumbprint(old_pub),
            "new_key": {"key_id": jwk_thumbprint(new_pub),
                        "pubkey": new_pub, "label": "prod"},
            "rotated_at": now,
            "overlap_s": ROTATION_OVERLAP_S,
        }, OP_PRIV, ts=now)
        m = build_manifest(log=log, operator_priv_hex=OP_PRIV,
                           operator_pubkey=OP_PUB)
        ok, reasons = verify_manifest(m, OP_PUB)
        self.assertTrue(ok, reasons)
        found = lookup_principal(m, "maya")
        self.assertEqual(principal_key_status(found, old_pub),
                         "superseded-valid")
        self.assertEqual(principal_key_status(found, new_pub), "active")
        # After the overlap window the old key is dead.
        self.assertEqual(
            principal_key_status(found, old_pub,
                                 now=now + ROTATION_OVERLAP_S + 1),
            "superseded-expired")

    def test_revoke_fold(self):
        log = _tmp_log(self)
        _, pub = _keys()
        now = time.time()
        log.append("enroll", {
            "principal_id": "maya", "tier": "allowlist", "domain": None,
            "keys": [{"key_id": jwk_thumbprint(pub),
                      "pubkey": pub, "label": "prod"}],
            "enrolled_at": now, "expires_at": now + ENROLLMENT_TTL_S,
        }, OP_PRIV, ts=now)
        log.append("revoke-key", {
            "principal_id": "maya", "key_id": jwk_thumbprint(pub),
            "revoked_at": now, "reason": "compromised",
        }, OP_PRIV, ts=now)
        m = build_manifest(log=log, operator_priv_hex=OP_PRIV,
                           operator_pubkey=OP_PUB)
        found = lookup_principal(m, "maya")
        self.assertEqual(principal_key_status(found, pub), "revoked")

    def test_suspend_fold(self):
        log = _tmp_log(self)
        _, pub = _keys()
        now = time.time()
        log.append("enroll", {
            "principal_id": "maya", "tier": "allowlist", "domain": None,
            "keys": [{"key_id": jwk_thumbprint(pub),
                      "pubkey": pub, "label": "prod"}],
            "enrolled_at": now, "expires_at": now + ENROLLMENT_TTL_S,
        }, OP_PRIV, ts=now)
        log.append("suspend", {
            "principal_id": "maya", "suspended_at": now, "reason": "abuse",
        }, OP_PRIV, ts=now)
        m = build_manifest(log=log, operator_priv_hex=OP_PRIV,
                           operator_pubkey=OP_PUB)
        found = lookup_principal(m, "maya")
        self.assertEqual(found["status"], "suspended")
        self.assertEqual(principal_key_status(found, pub), "suspended")
        log.append("unsuspend", {
            "principal_id": "maya", "unsuspended_at": now,
        }, OP_PRIV, ts=now)
        m2 = build_manifest(log=log, operator_priv_hex=OP_PRIV,
                            operator_pubkey=OP_PUB)
        found2 = lookup_principal(m2, "maya")
        self.assertEqual(principal_key_status(found2, pub), "active")


if __name__ == "__main__":
    unittest.main()
