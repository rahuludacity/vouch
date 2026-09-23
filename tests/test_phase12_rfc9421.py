"""Tests for Phase 12: RFC 9421 HTTP Message Signatures + /.well-known/vouch-keys.

Covers services/verifier/rfc9421.py:
  sign_http_request / verify_http_request round-trip and all fail-closed
  rejection paths (tamper, wrong key, expired, alg confusion, tag
  mismatch, keyid mismatch, missing minimum covered set), the JWKS key
  directory shape (build_key_directory), and the verifier app's
  GET /.well-known/vouch-keys endpoint (200 with the Web Bot Auth
  content-type, 404 when no manifest is configured).
"""
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from services.verifier import ed25519  # noqa: E402
from services.verifier import rfc9421  # noqa: E402
from services.verifier.rfc9421 import (  # noqa: E402
    _jwk_thumbprint, sign_http_request, verify_http_request,
    build_key_directory)

# Fixed test keypair (labeled; not secret — generated for tests).
T_PRIV = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
T_PUB = ed25519.pubkey_from_priv(bytes.fromhex(T_PRIV)).hex()
T_KID = _jwk_thumbprint(T_PUB)
OTHER_PRIV = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
OTHER_PUB = ed25519.pubkey_from_priv(bytes.fromhex(OTHER_PRIV)).hex()


def sign(**kw):
    args = {"priv_hex": T_PRIV, "keyid": T_KID, "method": "POST",
            "authority": "example.com", "path": "/v1/verify",
            "headers": {"content-type": "application/json"},
            "body": b'{"a":1}'}
    args.update(kw)
    return sign_http_request(**args)


def merge_headers(signed, extra):
    h = dict(extra or {})
    h["Signature-Input"] = signed["Signature-Input"]
    h["Signature"] = signed["Signature"]
    return h


class ThumbprintCase(unittest.TestCase):
    def test_shape_43_chars_base64url(self):
        self.assertEqual(len(T_KID), 43)
        self.assertRegex(T_KID, r"^[A-Za-z0-9_-]{43}$")

    def test_deterministic(self):
        self.assertEqual(_jwk_thumbprint(T_PUB), _jwk_thumbprint(T_PUB))

    def test_rfc7638_vector_shape(self):
        # Independent recompute of the RFC 7638 construction for the
        # test key — proves byte-identical behavior, not self-consistency.
        x = base64.urlsafe_b64encode(
            bytes.fromhex(T_PUB)).rstrip(b"=").decode("ascii")
        want = base64.urlsafe_b64encode(
            hashlib.sha256(
                ('{"crv":"Ed25519","kty":"OKP","x":"' + x + '"}'
                 ).encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        self.assertEqual(T_KID, want)

    def test_bad_key_rejected(self):
        with self.assertRaises(ValueError):
            _jwk_thumbprint("zz")
        with self.assertRaises(ValueError):
            _jwk_thumbprint("ab" * 16)


class SignVerifyCase(unittest.TestCase):
    def test_round_trip_post_with_body(self):
        signed = sign()
        self.assertIn("sig1=", signed["Signature-Input"])
        self.assertIn("sig1=:", signed["Signature"])
        ok, reason = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers=merge_headers(signed, {"content-type":
                                           "application/json"}),
            body=b'{"a":1}', pubkey_hex=T_PUB)
        self.assertTrue(ok, reason)

    def test_round_trip_get_no_body(self):
        signed = sign(method="GET", path="/v1/health?q=1", body=b"",
                      headers={})
        ok, reason = verify_http_request(
            method="GET", authority="example.com", path="/v1/health?q=1",
            headers=merge_headers(signed, {}), body=b"", pubkey_hex=T_PUB)
        self.assertTrue(ok, reason)

    def test_tampered_body_fails(self):
        signed = sign()
        ok, reason = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers=merge_headers(signed, {"content-type":
                                           "application/json"}),
            body=b'{"a":2}', pubkey_hex=T_PUB)
        self.assertFalse(ok)
        self.assertIn("does not verify", reason)

    def test_tampered_path_fails(self):
        signed = sign()
        ok, _r = verify_http_request(
            method="POST", authority="example.com", path="/v1/other",
            headers=merge_headers(signed, {"content-type":
                                           "application/json"}),
            body=b'{"a":1}', pubkey_hex=T_PUB)
        self.assertFalse(ok)

    def test_wrong_pubkey_fails(self):
        signed = sign(keyid=_jwk_thumbprint(OTHER_PUB), priv_hex=OTHER_PRIV)
        ok, _r = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers=merge_headers(signed, {"content-type":
                                           "application/json"}),
            body=b'{"a":1}', pubkey_hex=T_PUB)
        # keyid binds to the signing key, so this fails at the keyid
        # check before even reaching signature verification.
        self.assertFalse(ok)

    def test_wrong_pubkey_bad_signature_fails(self):
        signed = sign()  # signed by T_PRIV, keyid T_KID
        ok, reason = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers=merge_headers(signed, {"content-type":
                                           "application/json"}),
            body=b'{"a":1}', pubkey_hex=OTHER_PUB)
        self.assertFalse(ok)

    def test_expired_signature_fails(self):
        past = int(time.time()) - 1000
        signed = sign(created=past, expires_s=300)
        ok, reason = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers=merge_headers(signed, {"content-type":
                                           "application/json"}),
            body=b'{"a":1}', pubkey_hex=T_PUB)
        self.assertFalse(ok)
        self.assertIn("validity window", reason)

    def test_future_created_fails(self):
        signed = sign(created=int(time.time()) + 10000, expires_s=30000)
        ok, _r = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers=merge_headers(signed, {"content-type":
                                           "application/json"}),
            body=b'{"a":1}', pubkey_hex=T_PUB)
        self.assertFalse(ok)

    def test_alg_confusion_rejected(self):
        # Algorithm confusion: a tampered alg must be rejected even
        # though the signature over the tampered base no longer verifies.
        signed = sign()
        tampered = dict(signed)
        tampered["Signature-Input"] = signed["Signature-Input"].replace(
            'alg="ed25519"', 'alg="hmac-sha256"')
        ok, reason = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers=merge_headers(tampered, {"content-type":
                                             "application/json"}),
            body=b'{"a":1}', pubkey_hex=T_PUB)
        self.assertFalse(ok)
        self.assertIn("unsupported signature algorithm", reason)

    def test_tag_mismatch_rejected(self):
        signed = sign()
        tampered = dict(signed)
        tampered["Signature-Input"] = signed["Signature-Input"].replace(
            'tag="vouch"', 'tag="web-bot-auth"')
        ok, reason = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers=merge_headers(tampered, {"content-type":
                                             "application/json"}),
            body=b'{"a":1}', pubkey_hex=T_PUB)
        self.assertFalse(ok)
        self.assertIn("tag mismatch", reason)

    def test_missing_content_digest_rejected(self):
        # POST with a non-empty body but content-digest not covered.
        signed = sign(covered=("@method", "@authority"))
        ok, reason = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers=merge_headers(signed, {}),
            body=b'{"a":1}', pubkey_hex=T_PUB)
        self.assertFalse(ok)
        self.assertIn("content-digest", reason)

    def test_missing_method_or_authority_rejected(self):
        signed = sign(covered=("@path", "content-digest"))
        ok, reason = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers=merge_headers(signed, {}),
            body=b'{"a":1}', pubkey_hex=T_PUB)
        self.assertFalse(ok)
        self.assertIn("@method", reason)

    def test_missing_signature_headers_fails(self):
        ok, reason = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers={"content-type": "application/json"},
            body=b'{"a":1}', pubkey_hex=T_PUB)
        self.assertFalse(ok)
        self.assertIn("missing", reason)

    def test_garbage_signature_input_fails_closed(self):
        ok, reason = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers={"Signature-Input": "not-a-valid-inner-list!!!",
                     "Signature": "sig1=:AAAA:"},
            body=b'{"a":1}', pubkey_hex=T_PUB)
        self.assertFalse(ok)

    def test_named_header_covered(self):
        signed = sign(covered=("@method", "@authority", "content-type",
                               "content-digest"))
        headers = merge_headers(signed, {"content-type": "application/json"})
        ok, reason = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers=headers, body=b'{"a":1}', pubkey_hex=T_PUB)
        self.assertTrue(ok, reason)
        # tampering the covered header breaks verification
        headers2 = dict(headers)
        headers2["Content-Type"] = "text/plain"
        ok2, _r = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers=headers2, body=b'{"a":1}', pubkey_hex=T_PUB)
        self.assertFalse(ok2)

    def test_crlf_in_header_value_neutralized(self):
        # A CR/LF injection in a header value must not forge a valid
        # signature — the signer strips it, and the verifier recomputes
        # from the same stripped value.
        evil = {"x-evil": "a\r\n\"@method\": GET"}
        signed = sign(headers=evil,
                      covered=("@method", "@authority", "x-evil",
                               "content-digest"))
        ok, reason = verify_http_request(
            method="POST", authority="example.com", path="/v1/verify",
            headers=merge_headers(signed, evil),
            body=b'{"a":1}', pubkey_hex=T_PUB)
        self.assertTrue(ok, reason)


class KeyDirectoryCase(unittest.TestCase):
    def _manifest(self):
        return {
            "version": 3,
            "principals": [
                {"principal_id": "alice", "tier": "allowlist",
                 "domain": None, "status": "active",
                 "enrolled_at": 1700000000.0, "expires_at": 1800000000.0,
                 "enrollment_log_seq": 7,
                 "keys": [
                     {"key_id": T_KID, "pubkey": T_PUB, "label": "prod",
                      "status": "active", "valid_until": 1750000000.0},
                     {"key_id": "dead", "pubkey": OTHER_PUB, "label": "old",
                      "status": "revoked", "valid_until": 1700000001.0},
                 ]},
                {"principal_id": "bob", "tier": "domain-control",
                 "domain": "bob.example", "status": "suspended",
                 "enrolled_at": 1700000000.0, "expires_at": 1800000000.0,
                 "enrollment_log_seq": 9,
                 "keys": [
                     {"key_id": None, "pubkey": OTHER_PUB, "label": "web",
                      "status": "active", "valid_until": None},
                 ]},
            ],
        }

    def test_shape(self):
        d = build_key_directory(self._manifest())
        self.assertEqual(set(d.keys()), {"keys"})
        self.assertEqual(len(d["keys"]), 2)  # revoked key excluded
        alice = d["keys"][0]
        self.assertEqual(alice["kty"], "OKP")
        self.assertEqual(alice["crv"], "Ed25519")
        self.assertEqual(alice["use"], "sig")
        self.assertEqual(alice["kid"], T_KID)
        self.assertEqual(alice["kid"], _jwk_thumbprint(T_PUB))
        self.assertEqual(
            alice["x"],
            base64.urlsafe_b64encode(bytes.fromhex(T_PUB)).rstrip(
                b"=").decode("ascii"))
        # nbf/exp are epoch milliseconds
        self.assertEqual(alice["nbf"], 1700000000 * 1000)
        self.assertEqual(alice["exp"], 1750000000 * 1000)
        # bob's key: kid derived from pubkey, exp falls back to
        # the enrollment expires_at
        bob = d["keys"][1]
        self.assertEqual(bob["kid"], _jwk_thumbprint(OTHER_PUB))
        self.assertEqual(bob["exp"], 1800000000 * 1000)

    def test_empty_manifest(self):
        self.assertEqual(build_key_directory({}), {"keys": []})
        self.assertEqual(build_key_directory(None), {"keys": []})


def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class KeyDirectoryEndpointCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="vouch-phase12-test-")
        cls.manifest_path = os.path.join(cls.tmp, "manifest.json")
        manifest = {
            "version": 1,
            "principals": [
                {"principal_id": "alice", "tier": "allowlist",
                 "domain": None, "status": "active",
                 "enrolled_at": 1700000000.0, "expires_at": 1800000000.0,
                 "enrollment_log_seq": 1,
                 "keys": [
                     {"key_id": T_KID, "pubkey": T_PUB, "label": "prod",
                      "status": "active", "valid_until": 1750000000.0},
                 ]},
            ],
        }
        with open(cls.manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f)
        os.environ["VOUCH_MANIFEST_PATH"] = cls.manifest_path
        import services.verifier.app as appmod
        cls.app = appmod
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
        os.environ.pop("VOUCH_MANIFEST_PATH", None)

    def _get(self, path):
        try:
            with urllib.request.urlopen(
                    self.base + path, timeout=10) as r:
                return r.status, r.headers.get("Content-Type"), r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Content-Type"), e.read()

    def test_endpoint_200_shape_and_content_type(self):
        status, ctype, body = self._get("/.well-known/vouch-keys")
        self.assertEqual(status, 200)
        self.assertEqual(
            ctype, "application/http-message-signatures-directory+json")
        d = json.loads(body.decode("utf-8"))
        self.assertEqual(len(d["keys"]), 1)
        key = d["keys"][0]
        self.assertEqual(key["kid"], T_KID)
        self.assertEqual(key["kty"], "OKP")
        self.assertEqual(key["crv"], "Ed25519")
        self.assertEqual(key["use"], "sig")
        self.assertIn("nbf", key)
        self.assertIn("exp", key)

    def test_endpoint_404_when_env_unset(self):
        os.environ.pop("VOUCH_MANIFEST_PATH", None)
        try:
            status, _ctype, body = self._get("/.well-known/vouch-keys")
            self.assertEqual(status, 404)
            self.assertEqual(json.loads(body.decode("utf-8")),
                             {"error": "no_manifest"})
        finally:
            os.environ["VOUCH_MANIFEST_PATH"] = self.manifest_path

    def test_endpoint_404_when_manifest_unreadable(self):
        os.environ["VOUCH_MANIFEST_PATH"] = os.path.join(
            self.tmp, "does-not-exist.json")
        try:
            status, _ctype, body = self._get("/.well-known/vouch-keys")
            self.assertEqual(status, 404)
            self.assertEqual(json.loads(body.decode("utf-8")),
                             {"error": "no_manifest"})
        finally:
            os.environ["VOUCH_MANIFEST_PATH"] = self.manifest_path


if __name__ == "__main__":
    unittest.main()
