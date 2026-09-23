"""Principal enrollment: transparency log, enrollment certificates, trust-root manifest.

Phase 9 — enrollment core. A principal (person/org an agent acts for) gets
enrolled by the operator into a signed, hash-chained transparency log, gets
a signed enrollment certificate binding principal_id -> key_ids, and shows
up in the operator-signed trust-root manifest that verifiers sync.

Tier literals (PRD language rule — never overclaim):
    "allowlist"       — Tier 0: manually added after a human conversation.
    "domain-control"  — Tier 1: proved control of a domain (DNS-01 style).

The strings "allowlist"/"domain-control" are the only tier strings in MVP.
A DNS check proves domain control, never identity — the code and all
user-facing strings say exactly that.

Crypto: Ed25519 (vendored, services/verifier/ed25519.py). Canonical
encoding for everything signed: JSON, sorted keys, no whitespace
(reuses credentials.canonical). key_id is the RFC 7638 JWK thumbprint
of the Ed25519 public key — the same value is the JWKS `kid` in Phase 12.

No network calls anywhere in this phase. No private key material ever
appears in exceptions, logs, or return values.
"""
import base64
import copy
import hashlib
import json
import os
import re
import secrets
import subprocess
import threading
import time
import urllib.parse
import urllib.request

from . import ed25519
from .credentials import canonical

# Frozen tier literals. Nothing else may appear as a tier in MVP.
TIER_ALLOWLIST = "allowlist"          # Tier 0: manual allowlist
TIER_DOMAIN_CONTROL = "domain-control"  # Tier 1: proved domain control
TIERS = frozenset({TIER_ALLOWLIST, TIER_DOMAIN_CONTROL})

# Enrollment certificate lifetime: 90 days. Tier 1/2 re-validation runs on
# the same clock (design doc §4); expired enrollment -> "expired" status.
ENROLLMENT_TTL_S = 90 * 24 * 3600

# Key rotation overlap: a superseded key stays acceptable for 72h after
# rotation so in-flight credentials keep working (design doc §2).
ROTATION_OVERLAP_S = 72 * 3600

# Transparency-log event types (frozen). Append helpers for rotate /
# suspend / revoke land in Phase 10; the manifest fold below already
# understands every type so statuses stay consistent across phases.
LOG_EVENT_TYPES = frozenset({
    "enroll", "rotate", "suspend", "unsuspend",
    "revoke-key", "revoke-credential", "revoke-delegation-link",
    "operator-key",
})

# Size caps: the log is untrusted input on read (it may be synced from
# elsewhere). Refuse absurd entries rather than choking on them.
_MAX_LOG_LINE_BYTES = 1 << 20        # 1 MiB per JSONL line
_MAX_LOG_FILE_BYTES = 256 << 20     # 256 MiB total file
_MAX_PAYLOAD_BYTES = 64 << 10       # 64 KiB canonical payload per event
_MAX_ID_LEN = 128                   # principal_id / label caps
_MAX_LABEL_LEN = 64

_KEY_STATUSES = frozenset({"active", "revoked", "suspended", "superseded"})
_PRINCIPAL_STATUSES = frozenset({"active", "suspended"})


def _ts(ts=None):
    return round(time.time(), 3) if ts is None else round(float(ts), 3)


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------- key ids
def jwk_thumbprint(pubkey_hex):
    """RFC 7638 JWK thumbprint of an Ed25519 public key.

    key_id = base64url_nopad(sha256('{"crv":"Ed25519","kty":"OKP",
                                    "x":"<b64url-pubkey>"}'))
    where x is the base64url of the 32 raw public-key bytes. The object
    members are already in lexicographic order (crv < kty < x), as the
    RFC requires. This same value is the JWKS `kid` (Phase 12 imports
    this function — no duplication).
    """
    try:
        pub = bytes.fromhex(pubkey_hex)
    except (ValueError, TypeError):
        raise ValueError("pubkey_hex is not valid hex")
    if len(pub) != 32:
        raise ValueError("pubkey must be 32 bytes (Ed25519)")
    jwk = '{"crv":"Ed25519","kty":"OKP","x":"%s"}' % _b64url_nopad(pub)
    return _b64url_nopad(hashlib.sha256(jwk.encode("ascii")).digest())


# ---------------------------------------------------------------- validation helpers
def _check_hex32(value, what):
    """Return raw bytes for a 32-byte hex string; raise ValueError if bad.

    Never includes the value itself in the error — key material stays out
    of exceptions.
    """
    try:
        raw = bytes.fromhex(value)
    except (ValueError, TypeError, AttributeError):
        raise ValueError(f"{what} is not valid hex")
    if len(raw) != 32:
        raise ValueError(f"{what} must be 32 bytes (Ed25519)")
    return raw


def _check_id(value, what, max_len):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{what} must be a non-empty string")
    if len(value) > max_len:
        raise ValueError(f"{what} exceeds {max_len} characters")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ValueError(f"{what} contains control characters")
    return value


def _operator_pubkey_from_priv(operator_priv_hex):
    """Derive the operator pubkey from its private key (never logged)."""
    priv = _check_hex32(operator_priv_hex, "operator_priv_hex")
    return ed25519.pubkey_from_priv(priv).hex()


# ---------------------------------------------------------------- transparency log
class TransparencyLog:
    """Append-only, hash-chained, operator-signed enrollment log (JSONL).

    Entry: {"seq","ts","type","payload","prev_hash","hash",
            "operator_pubkey","signature"}

    hash      = sha256(canonical(entry minus hash/signature))
    signature = Ed25519(operator key) over canonical(entry minus signature)
                — i.e. the hash is covered by the signature too.

    verify() replays the chain: seq continuity, prev_hash linkage, hash
    recomputation, and signature check per entry. Any failure -> (False,
    [reasons]); verify never raises on malformed input (fail-closed).
    """

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._entries = []
        self._load()

    # -- persistence -------------------------------------------------
    def _load(self):
        self.seq_num = 0
        self.prev_hash = "GENESIS"
        if not os.path.exists(self.path):
            return
        size = os.path.getsize(self.path)
        if size > _MAX_LOG_FILE_BYTES:
            raise ValueError("transparency log exceeds size cap")
        with open(self.path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                if len(line.encode("utf-8")) > _MAX_LOG_LINE_BYTES:
                    raise ValueError(
                        f"log line {lineno} exceeds size cap")
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    raise ValueError(f"log line {lineno}: invalid JSON")
                if not isinstance(entry, dict):
                    raise ValueError(f"log line {lineno}: not an object")
                self._entries.append(entry)
                self.seq_num = entry.get("seq", self.seq_num)
                self.prev_hash = entry.get("hash", self.prev_hash)

    # -- reads --------------------------------------------------------
    def seq(self):
        """Highest sequence number in the log (0 when empty)."""
        with self._lock:
            return self.seq_num

    def entries(self):
        """Deep copies of all entries, oldest first."""
        with self._lock:
            return copy.deepcopy(self._entries)

    # -- append --------------------------------------------------------
    def append(self, event_type, payload, operator_priv_hex, ts=None):
        """Append one signed event. Returns the entry dict.

        Raises ValueError on bad event_type/payload/keys (operator-side:
        loud failure beats a silently malformed log).
        """
        if event_type not in LOG_EVENT_TYPES:
            raise ValueError(f"unknown log event type: {event_type!r}")
        if not isinstance(payload, dict):
            raise ValueError("payload must be a dict")
        if len(canonical(payload)) > _MAX_PAYLOAD_BYTES:
            raise ValueError("payload exceeds size cap")
        _check_id(str(event_type), "event_type", 32)
        operator_pubkey = _operator_pubkey_from_priv(operator_priv_hex)
        with self._lock:
            entry = {
                "seq": self.seq_num + 1,
                "ts": _ts(ts),
                "type": event_type,
                "payload": copy.deepcopy(payload),
                "prev_hash": self.prev_hash,
                "operator_pubkey": operator_pubkey,
            }
            entry["hash"] = hashlib.sha256(canonical(_unsigned(entry))).hexdigest()
            entry["signature"] = ed25519.sign_hex(
                operator_priv_hex, canonical(_unsigned_sig(entry)))
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
            self._entries.append(copy.deepcopy(entry))
            self.seq_num = entry["seq"]
            self.prev_hash = entry["hash"]
            return copy.deepcopy(entry)

    # -- verify ---------------------------------------------------------
    def verify(self, operator_pubkeys=None):
        """Replay the whole chain. Returns (ok, reasons).

        operator_pubkeys: optional trusted set (str or list). When given,
        an entry whose operator_pubkey is not in the set fails; when None,
        each entry's signature is checked against its own stated
        operator_pubkey (chain self-consistency).
        """
        reasons = []
        trusted = None
        if operator_pubkeys is not None:
            if isinstance(operator_pubkeys, str):
                trusted = {operator_pubkeys}
            else:
                try:
                    trusted = set(operator_pubkeys)
                except TypeError:
                    return False, ["operator_pubkeys is not a usable set"]
        try:
            if not os.path.exists(self.path):
                return True, []
            size = os.path.getsize(self.path)
            if size > _MAX_LOG_FILE_BYTES:
                return False, ["log file exceeds size cap"]
            want_seq = 0
            prev = "GENESIS"
            with open(self.path, "r", encoding="utf-8") as f:
                for lineno, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    if len(line.encode("utf-8")) > _MAX_LOG_LINE_BYTES:
                        reasons.append(f"line {lineno}: exceeds size cap")
                        continue
                    try:
                        e = json.loads(line)
                    except json.JSONDecodeError:
                        reasons.append(f"line {lineno}: invalid JSON")
                        continue
                    if not isinstance(e, dict):
                        reasons.append(f"line {lineno}: not an object")
                        continue
                    want_seq += 1
                    if e.get("seq") != want_seq:
                        reasons.append(
                            f"line {lineno}: seq break (want {want_seq}, "
                            f"got {e.get('seq')!r})")
                    if e.get("prev_hash") != prev:
                        reasons.append(f"line {lineno}: chain break")
                    for field in ("ts", "type", "payload", "hash",
                                  "operator_pubkey", "signature"):
                        if field not in e:
                            reasons.append(
                                f"line {lineno}: missing field '{field}'")
                    if e.get("type") not in LOG_EVENT_TYPES:
                        reasons.append(
                            f"line {lineno}: unknown event type "
                            f"{e.get('type')!r}")
                    if not isinstance(e.get("payload"), dict):
                        reasons.append(f"line {lineno}: payload not an object")
                    # Recompute the hash over the entry minus hash/signature.
                    try:
                        want_hash = hashlib.sha256(
                            canonical(_unsigned(e))).hexdigest()
                    except (TypeError, ValueError):
                        reasons.append(f"line {lineno}: unhashable entry")
                        prev = e.get("hash", prev)
                        continue
                    if e.get("hash") != want_hash:
                        reasons.append(
                            f"line {lineno}: hash mismatch (tampered body?)")
                    op = e.get("operator_pubkey")
                    if trusted is not None and op not in trusted:
                        reasons.append(
                            f"line {lineno}: operator key not trusted")
                    elif not _verify_entry_sig(e):
                        reasons.append(f"line {lineno}: bad signature")
                    prev = e.get("hash", prev)
        except OSError as exc:
            return False, [f"log unreadable: {exc.strerror or exc}"]
        except Exception:
            return False, ["log verification hit an unexpected error"]
        return (len(reasons) == 0), reasons


def _unsigned(entry):
    return {k: v for k, v in entry.items() if k not in ("hash", "signature")}


def _unsigned_sig(entry):
    return {k: v for k, v in entry.items() if k != "signature"}


def _verify_entry_sig(entry):
    """Signature over canonical(entry minus signature). Never raises."""
    try:
        return ed25519.verify_hex(
            entry["operator_pubkey"],
            canonical(_unsigned_sig(entry)),
            entry["signature"])
    except Exception:
        return False


# ---------------------------------------------------------------- enrollment certificate
def issue_enrollment_certificate(*, principal_id, tier, domain, key_ids,
                                 operator_priv_hex, operator_pub_hex,
                                 log_seq, ttl_s=ENROLLMENT_TTL_S,
                                 issued_at=None):
    """Signed statement binding principal_id -> key_ids.

    key_ids: [{"key_id","pubkey","label","status"}] — every key_id is
    recomputed from its pubkey here (a cert must never claim a key_id
    that does not match the pubkey).

    Returns the cert dict (with "signature"). Raises ValueError on any
    bad input — issuance fails loudly, never mints a malformed cert.
    """
    _check_id(principal_id, "principal_id", _MAX_ID_LEN)
    if tier not in TIERS:
        raise ValueError(f"tier must be one of {sorted(TIERS)}")
    if domain is not None:
        _check_id(domain, "domain", _MAX_ID_LEN)
    if not isinstance(key_ids, list) or not key_ids:
        raise ValueError("key_ids must be a non-empty list")
    bound = []
    for k in key_ids:
        if not isinstance(k, dict):
            raise ValueError("key_ids entries must be dicts")
        pubkey = k.get("pubkey")
        _check_hex32(pubkey, "key pubkey")
        kid = jwk_thumbprint(pubkey)
        if k.get("key_id") != kid:
            raise ValueError("key_id does not match pubkey thumbprint")
        label = k.get("label", "")
        _check_id(label or "key", "key label", _MAX_LABEL_LEN)
        if k.get("status", "active") != "active":
            raise ValueError("newly enrolled keys must be 'active'")
        bound.append({"key_id": kid, "pubkey": pubkey,
                      "label": label, "status": "active"})
    if not isinstance(log_seq, int) or isinstance(log_seq, bool) \
            or log_seq < 1:
        raise ValueError("log_seq must be a positive int")
    if not (isinstance(ttl_s, (int, float)) and ttl_s > 0):
        raise ValueError("ttl_s must be positive")
    op_pub = _check_hex32(operator_pub_hex, "operator_pub_hex").hex()
    if op_pub != _operator_pubkey_from_priv(operator_priv_hex):
        raise ValueError("operator_pub_hex does not match operator_priv_hex")
    now = _ts(issued_at)
    cert = {
        "principal_id": principal_id,
        "tier": tier,
        "domain": domain,
        "key_ids": bound,
        "enrolled_at": now,
        "expires_at": round(now + ttl_s, 3),
        "enrollment_log_seq": log_seq,
        "operator_pubkey": op_pub,
        "signature": "",
    }
    cert["signature"] = ed25519.sign_hex(
        operator_priv_hex, canonical(_unsigned_sig(cert)))
    return cert


def verify_enrollment_certificate(cert, operator_pubkey, now=None):
    """Check a cert's shape, timestamps, key binding, and signature.

    Returns (ok, reasons). Never raises on malformed input — any doubt
    fails closed.
    """
    reasons = []
    try:
        now = _ts(now)
        if not isinstance(cert, dict):
            return False, ["certificate is not an object"]
        for f in ("principal_id", "tier", "domain", "key_ids",
                  "enrolled_at", "expires_at", "enrollment_log_seq",
                  "operator_pubkey", "signature"):
            if f not in cert:
                reasons.append(f"certificate missing field '{f}'")
        if reasons:
            return False, reasons
        if cert["tier"] not in TIERS:
            reasons.append(f"unknown tier {cert['tier']!r}")
        if not isinstance(cert["key_ids"], list) or not cert["key_ids"]:
            reasons.append("certificate key_ids must be a non-empty list")
        else:
            for i, k in enumerate(cert["key_ids"]):
                if not isinstance(k, dict):
                    reasons.append(f"key_ids[{i}] not an object")
                    continue
                try:
                    want = jwk_thumbprint(k.get("pubkey"))
                except ValueError:
                    reasons.append(f"key_ids[{i}] has a bad pubkey")
                    continue
                if k.get("key_id") != want:
                    reasons.append(
                        f"key_ids[{i}] key_id does not match its pubkey")
                if k.get("status") not in _KEY_STATUSES:
                    reasons.append(
                        f"key_ids[{i}] has unknown status {k.get('status')!r}")
        try:
            enrolled = float(cert["enrolled_at"])
            expires = float(cert["expires_at"])
        except (TypeError, ValueError):
            reasons.append("certificate has non-numeric timestamps")
            enrolled = expires = None
        if enrolled is not None:
            if not (enrolled <= now < expires):
                reasons.append("certificate expired or not yet valid")
        try:
            _check_hex32(operator_pubkey, "operator_pubkey")
        except ValueError:
            reasons.append("operator_pubkey is not a valid Ed25519 pubkey")
            return False, reasons
        if cert["operator_pubkey"] != operator_pubkey:
            reasons.append("certificate not signed by the expected operator")
        if not ed25519.verify_hex(
                operator_pubkey,
                canonical(_unsigned_sig(cert)),
                cert["signature"]):
            reasons.append("certificate signature invalid")
    except Exception:
        return False, ["certificate verification hit an unexpected error"]
    return (len(reasons) == 0), reasons


# ---------------------------------------------------------------- trust-root manifest
_MANIFEST_STATE_SUFFIX = ".manifest_version"
_manifest_lock = threading.Lock()
_MANIFEST_STATE = {}  # path -> {"versions": {operator_pubkey: int}}


def _manifest_state_path(log):
    return log.path + _MANIFEST_STATE_SUFFIX


def _next_manifest_version(log, operator_pubkey):
    """Strictly increasing version per operator, persisted beside the log."""
    path = _manifest_state_path(log)
    with _manifest_lock:
        state = _MANIFEST_STATE.get(path)
        if state is None:
            state = {"versions": {}}
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        loaded = json.load(f)
                    if isinstance(loaded, dict) and isinstance(
                            loaded.get("versions"), dict):
                        state = loaded
                    else:
                        raise ValueError("bad manifest version state")
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    raise ValueError(
                        f"manifest version state unreadable: {exc}")
            _MANIFEST_STATE[path] = state
        versions = state["versions"]
        nxt = int(versions.get(operator_pubkey, 0)) + 1
        versions[operator_pubkey] = nxt
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"versions": versions}, f, sort_keys=True)
                f.write("\n")
            os.replace(tmp, path)
        except OSError as exc:
            raise ValueError(f"cannot persist manifest version: {exc}")
        return nxt


def _new_principal_entry(payload, log_seq):
    keys = []
    for k in payload["keys"]:
        keys.append({
            "key_id": k["key_id"],
            "pubkey": k["pubkey"],
            "label": k.get("label", ""),
            "status": "active",
            "valid_until": payload["expires_at"],
        })
    return {
        "principal_id": payload["principal_id"],
        "tier": payload["tier"],
        "domain": payload.get("domain"),
        "keys": keys,
        "status": "active",
        "enrollment_log_seq": log_seq,
        "enrolled_at": payload["enrolled_at"],
        "expires_at": payload["expires_at"],
    }


def _fold_log_into_principals(entries):
    """Materialize principal state from the log.

    Payload schemas (frozen; Phase 10 append helpers must match):
      enroll:            {"principal_id","tier","domain",
                          "keys":[{"key_id","pubkey","label"}],
                          "enrolled_at","expires_at"}
      rotate:            {"principal_id","old_key_id",
                          "new_key":{"key_id","pubkey","label"},
                          "rotated_at","overlap_s"}
      suspend:           {"principal_id","suspended_at","reason"}
      unsuspend:         {"principal_id","unsuspended_at"}
      revoke-key:        {"principal_id","key_id","revoked_at","reason"}
      revoke-credential: {"revocation_handle"}
      revoke-delegation-link: {"principal_id" (audit context),
                               "revocation_handle"}
      operator-key:      {"pubkey","action"}  # recorded, not folded here
    """
    principals = {}
    revoked_credentials = []
    revoked_delegation_links = []
    for e in entries:
        p = e["payload"]
        t = e["type"]
        if t == "enroll":
            pid = p["principal_id"]
            if pid in principals:
                raise ValueError(
                    f"duplicate enrollment for principal {pid!r}")
            principals[pid] = _new_principal_entry(p, e["seq"])
        elif t == "rotate":
            entry = principals.get(p["principal_id"])
            if entry is None:
                raise ValueError("rotate for unknown principal")
            old = next((k for k in entry["keys"]
                        if k["key_id"] == p["old_key_id"]), None)
            if old is None:
                raise ValueError("rotate for unknown key")
            old["status"] = "superseded"
            old["valid_until"] = round(
                p["rotated_at"] + p.get("overlap_s", ROTATION_OVERLAP_S), 3)
            nk = p["new_key"]
            entry["keys"].append({
                "key_id": nk["key_id"],
                "pubkey": nk["pubkey"],
                "label": nk.get("label", ""),
                "status": "active",
                "valid_until": entry["expires_at"],
            })
        elif t == "suspend":
            entry = principals.get(p["principal_id"])
            if entry is None:
                raise ValueError("suspend for unknown principal")
            entry["status"] = "suspended"
        elif t == "unsuspend":
            entry = principals.get(p["principal_id"])
            if entry is None:
                raise ValueError("unsuspend for unknown principal")
            entry["status"] = "active"
        elif t == "revoke-key":
            entry = principals.get(p["principal_id"])
            if entry is None:
                raise ValueError("revoke-key for unknown principal")
            key = next((k for k in entry["keys"]
                        if k["key_id"] == p["key_id"]), None)
            if key is None:
                raise ValueError("revoke-key for unknown key")
            key["status"] = "revoked"
        elif t == "revoke-credential":
            handle = p.get("revocation_handle")
            if handle and handle not in revoked_credentials:
                revoked_credentials.append(handle)
        elif t == "revoke-delegation-link":
            # Surgical revocation of one delegation grant. The handle is
            # minted into the link at issuance (issue_delegation) and
            # signed; verification denies any chain containing it
            # (credentials._verify_chain, fail-closed). principal_id is
            # audit context only — the handle alone identifies the grant.
            handle = p.get("revocation_handle")
            if handle and handle not in revoked_delegation_links:
                revoked_delegation_links.append(handle)
        elif t == "operator-key":
            continue  # operator set changes are recorded, not folded here
        else:
            raise ValueError(f"cannot fold unknown event type {t!r}")
    return principals, revoked_credentials, revoked_delegation_links


def build_manifest(*, log, operator_priv_hex, operator_pubkey,
                   valid_for_s=300, issued_at=None):
    """Build the signed trust-root manifest from the log.

    version: int, strictly increasing per operator (persisted beside the
    log so restarts cannot reuse a version). valid_for_s default 300 —
    verifiers fail closed on a stale manifest, so the window stays short.
    Raises ValueError on any inconsistency (fail-closed: never publish
    a manifest that misstates the log).
    """
    if not isinstance(log, TransparencyLog):
        raise ValueError("log must be a TransparencyLog")
    op_pub = _check_hex32(operator_pubkey, "operator_pubkey").hex()
    if op_pub != _operator_pubkey_from_priv(operator_priv_hex):
        raise ValueError("operator_pubkey does not match operator_priv_hex")
    if not (isinstance(valid_for_s, (int, float)) and valid_for_s > 0):
        raise ValueError("valid_for_s must be positive")
    ok, reasons = log.verify()
    if not ok:
        raise ValueError(f"refusing to build manifest from a broken log: "
                         f"{reasons[0] if reasons else 'unknown'}")
    principals, revoked, revoked_links = _fold_log_into_principals(log.entries())
    now = _ts(issued_at)
    manifest = {
        "version": _next_manifest_version(log, op_pub),
        "issued_at": now,
        "not_before": now,
        "valid_until": round(now + valid_for_s, 3),
        "operator_pubkey": op_pub,
        "principals": [principals[pid] for pid in sorted(principals)],
        "revoked_credentials": sorted(revoked),
        "revoked_delegation_handles": sorted(revoked_links),
        "signature": "",
    }
    manifest["signature"] = ed25519.sign_hex(
        operator_priv_hex, canonical(_unsigned_sig(manifest)))
    return manifest


def verify_manifest(manifest, operator_pubkeys, now=None):
    """Check a manifest's shape, freshness window, and operator signature.

    Signature must verify against one of operator_pubkeys (str or list).
    Freshness: not_before <= now < valid_until, else fail-closed.
    Returns (ok, reasons); never raises on malformed input.
    """
    reasons = []
    try:
        now = _ts(now)
        if not isinstance(manifest, dict):
            return False, ["manifest is not an object"]
        for f in ("version", "issued_at", "not_before", "valid_until",
                  "operator_pubkey", "principals", "revoked_credentials",
                  "revoked_delegation_handles", "signature"):
            if f not in manifest:
                reasons.append(f"manifest missing field '{f}'")
        if reasons:
            return False, reasons
        v = manifest["version"]
        if not isinstance(v, int) or isinstance(v, bool) or v < 1:
            reasons.append("manifest version must be a positive int")
        try:
            nb = float(manifest["not_before"])
            vu = float(manifest["valid_until"])
        except (TypeError, ValueError):
            reasons.append("manifest has non-numeric validity window")
            nb = vu = None
        if nb is not None:
            if now < nb:
                reasons.append("manifest not yet valid")
            elif not now < vu:
                reasons.append(
                    f"trust root stale: manifest expired at {vu}")
        if not isinstance(manifest["principals"], list):
            reasons.append("manifest principals must be a list")
        else:
            for i, pe in enumerate(manifest["principals"]):
                reasons.extend(
                    f"principal[{i}]: {w}"
                    for w in _check_principal_entry(pe))
        if not isinstance(manifest["revoked_credentials"], list):
            reasons.append("manifest revoked_credentials must be a list")
        if not isinstance(manifest["revoked_delegation_handles"], list):
            reasons.append("manifest revoked_delegation_handles must be a list")
        try:
            _check_hex32(manifest["operator_pubkey"], "operator_pubkey")
        except ValueError:
            reasons.append("manifest operator_pubkey is not a valid pubkey")
        if isinstance(operator_pubkeys, str):
            pubs = [operator_pubkeys]
        else:
            try:
                pubs = list(operator_pubkeys)
            except TypeError:
                reasons.append("operator_pubkeys is not usable")
                pubs = []
        sig_ok = False
        for pub in pubs:
            try:
                if ed25519.verify_hex(pub, canonical(_unsigned_sig(manifest)),
                                      manifest["signature"]):
                    sig_ok = True
                    break
            except Exception:
                continue
        if not sig_ok:
            reasons.append("manifest signature invalid "
                           "(not signed by a trusted operator)")
    except Exception:
        return False, ["manifest verification hit an unexpected error"]
    return (len(reasons) == 0), reasons


def _check_principal_entry(pe):
    """Structural sanity of one manifest principal entry -> [reasons]."""
    why = []
    if not isinstance(pe, dict):
        return ["not an object"]
    for f in ("principal_id", "tier", "domain", "keys", "status",
              "enrollment_log_seq", "enrolled_at", "expires_at"):
        if f not in pe:
            why.append(f"missing field '{f}'")
    if why:
        return why
    if pe["tier"] not in TIERS:
        why.append(f"unknown tier {pe['tier']!r}")
    if pe["status"] not in _PRINCIPAL_STATUSES:
        why.append(f"unknown status {pe['status']!r}")
    if not isinstance(pe["keys"], list) or not pe["keys"]:
        why.append("keys must be a non-empty list")
    else:
        for i, k in enumerate(pe["keys"]):
            if not isinstance(k, dict):
                why.append(f"keys[{i}] not an object")
                continue
            for f in ("key_id", "pubkey", "label", "status", "valid_until"):
                if f not in k:
                    why.append(f"keys[{i}] missing field '{f}'")
            if k.get("status") not in _KEY_STATUSES:
                why.append(f"keys[{i}] unknown status {k.get('status')!r}")
            try:
                if jwk_thumbprint(k.get("pubkey")) != k.get("key_id"):
                    why.append(f"keys[{i}] key_id does not match its pubkey")
            except ValueError:
                why.append(f"keys[{i}] has a bad pubkey")
    return why


def lookup_principal(manifest, principal_id):
    """Return a copy of the manifest's entry for principal_id, or None.

    None (unknown principal) is the fail-closed answer — the verifier
    denies anything it cannot find here.
    """
    try:
        if not isinstance(manifest, dict):
            return None
        if not isinstance(principal_id, str):
            return None
        for pe in manifest.get("principals", []):
            if isinstance(pe, dict) and pe.get("principal_id") == principal_id:
                return copy.deepcopy(pe)
    except Exception:
        return None
    return None


def principal_key_status(entry, pubkey_hex, now=None):
    """Usability of one key under a principal entry.

    Returns exactly one of: "active" | "revoked" | "suspended" |
    "superseded-valid" | "superseded-expired" | "expired" | "unknown".
    Never raises — anything ambiguous is "unknown" (verifier denies).
    """
    try:
        now = _ts(now)
        if not isinstance(entry, dict):
            return "unknown"
        keys = entry.get("keys")
        if not isinstance(keys, list):
            return "unknown"
        try:
            kid = jwk_thumbprint(pubkey_hex)
        except ValueError:
            return "unknown"
        key = next((k for k in keys
                    if isinstance(k, dict) and k.get("key_id") == kid), None)
        if key is None:
            return "unknown"
        ks = key.get("status")
        if ks == "revoked":
            return "revoked"
        if ks == "suspended" or entry.get("status") == "suspended":
            return "suspended"
        if ks == "superseded":
            try:
                vu = float(key["valid_until"])
            except (TypeError, ValueError, KeyError):
                return "unknown"
            return "superseded-valid" if now < vu else "superseded-expired"
        # Active keys still die with the enrollment.
        try:
            exp = float(entry["expires_at"])
            kvu = float(key["valid_until"])
        except (TypeError, ValueError, KeyError):
            return "unknown"
        if now >= exp or now >= kvu:
            return "expired"
        return "active" if ks == "active" else "unknown"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------- Tier 0 enrollment
def enroll_principal_tier0(*, log, principal_id, pubkey_hex, label,
                           operator_priv_hex, operator_pub_hex,
                           issued_at=None):
    """Enroll one principal at Tier 0 ("allowlist").

    Manual enrollment: the operator adds the principal's key after a
    human conversation — there is no automated proof here, and the tier
    string says so plainly. Appends the "enroll" event to the log, then
    issues the enrollment certificate pointing at that log seq.

    Returns (cert, manifest_entry). Raises ValueError on bad input.
    """
    if not isinstance(log, TransparencyLog):
        raise ValueError("log must be a TransparencyLog")
    _check_id(principal_id, "principal_id", _MAX_ID_LEN)
    _check_id(label, "label", _MAX_LABEL_LEN)
    _check_hex32(pubkey_hex, "pubkey_hex")
    op_pub = _check_hex32(operator_pub_hex, "operator_pub_hex").hex()
    if op_pub != _operator_pubkey_from_priv(operator_priv_hex):
        raise ValueError("operator_pub_hex does not match operator_priv_hex")

    key_id = jwk_thumbprint(pubkey_hex)
    now = _ts(issued_at)
    payload = {
        "principal_id": principal_id,
        "tier": TIER_ALLOWLIST,
        "domain": None,
        "keys": [{"key_id": key_id, "pubkey": pubkey_hex, "label": label}],
        "enrolled_at": now,
        "expires_at": round(now + ENROLLMENT_TTL_S, 3),
    }
    entry = log.append("enroll", payload, operator_priv_hex, ts=now)
    cert = issue_enrollment_certificate(
        principal_id=principal_id,
        tier=TIER_ALLOWLIST,
        domain=None,
        key_ids=[{"key_id": key_id, "pubkey": pubkey_hex,
                  "label": label, "status": "active"}],
        operator_priv_hex=operator_priv_hex,
        operator_pub_hex=op_pub,
        log_seq=entry["seq"],
        ttl_s=ENROLLMENT_TTL_S,
        issued_at=now,
    )
    manifest_entry = _new_principal_entry(payload, entry["seq"])
    return cert, manifest_entry


# ---------------------------------------------------------------- Tier 1: DNS challenge + domain-control enrollment
#
# Phase 10 — Tier 1 ("domain-control"). A principal proves control of a
# domain by publishing a random token as a DNS TXT record at
# _vouch-challenge.<domain>, and by serving the enrolling key in the
# domain's /.well-known/vouch-keys JWKS directory (Phase 12 shape).
#
# This binds the principal to domain control, nothing more. It says
# nothing about who the principal is — the tier string and every
# user-facing message say exactly that.
#
# Prototype honesty: the DNS check runs over the system resolver with
# no DNSSEC validation. A network-path attacker who can spoof your DNS
# can spoof this check. Tier 1 proves domain control against casual
# attackers only. The HTTPS fetch likewise trusts the system TLS stack
# (no pinning in this prototype).
#
# Network access is injectable everywhere: tests pass stubs, the
# operator console passes the real fetchers.

_CHALLENGE_LABEL = "_vouch-challenge"
_MAX_JWKS_BYTES = 1 << 20          # 1 MiB cap on fetched key directories
_MAX_REASON_LEN = 256

# A DNS label: alphanumerics plus interior hyphens, 1-63 chars.
_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _check_domain(domain):
    """Validate a DNS domain name; return it normalized.

    Raises ValueError on anything that is not plain DNS (scheme, path,
    whitespace, control chars, userinfo are all rejected here).
    """
    if not isinstance(domain, str) or not domain:
        raise ValueError("domain must be a non-empty string")
    d = domain.strip().rstrip(".")
    if not d or len(d) > 253:
        raise ValueError("domain is empty or too long")
    labels = d.split(".")
    for lab in labels:
        if not _DNS_LABEL_RE.match(lab):
            raise ValueError(f"domain has a bad label: {lab!r}")
    return d.lower()


def create_dns_challenge(domain):
    """Mint a DNS-01 style challenge for a domain.

    Returns {"domain","token","txt_name","created_at"} where token is a
    256-bit value (64 hex chars) from the secrets module and txt_name is
    "_vouch-challenge." + domain. The principal proves domain control
    by publishing the token as a TXT record at txt_name.
    """
    d = _check_domain(domain)
    token = secrets.token_hex(32)
    return {
        "domain": d,
        "token": token,
        "txt_name": _CHALLENGE_LABEL + "." + d,
        "created_at": _ts(),
    }


def _unquote_txt(line):
    """Strip DNS TXT quoting: join "chunk" segments into one string."""
    if not isinstance(line, str):
        return ""
    chunks = re.findall(r'"([^"]*)"', line)
    if chunks:
        return "".join(chunks)
    return line.strip()


def verify_dns_challenge(challenge, fetch_txt):
    """Check the challenge token against live TXT records.

    fetch_txt(txt_name) -> [str] is injectable. Returns (ok, reason);
    never raises — every doubt (bad challenge shape, lookup failure,
    missing token) fails closed.
    """
    try:
        if not isinstance(challenge, dict):
            return False, "challenge is not an object"
        domain = challenge.get("domain")
        token = challenge.get("token")
        txt_name = challenge.get("txt_name")
        if not (isinstance(domain, str) and domain):
            return False, "challenge has no domain"
        if not (isinstance(token, str) and token):
            return False, "challenge has no token"
        if txt_name != _CHALLENGE_LABEL + "." + domain:
            return False, "challenge txt_name does not match its domain"
        if not callable(fetch_txt):
            return False, "fetch_txt is not callable"
        try:
            records = fetch_txt(txt_name)
        except Exception as exc:
            # Class name only — the underlying message may carry
            # resolver/network detail we do not want in deny reasons.
            return False, f"TXT lookup failed ({exc.__class__.__name__})"
        if not isinstance(records, (list, tuple)):
            return False, "fetch_txt did not return a list of records"
        seen = []
        for r in records:
            if isinstance(r, bytes):
                try:
                    r = r.decode("utf-8", "replace")
                except Exception:
                    continue
            if isinstance(r, str):
                seen.append(_unquote_txt(r))
        if token in seen:
            return True, "token present in TXT records"
        if not seen:
            return False, "no TXT records found at the challenge name"
        return False, "token not present in TXT records"
    except Exception:
        return False, "challenge verification hit an unexpected error"


def fetch_txt_via_dig(txt_name, timeout_s=10):
    """Resolve TXT records with the system `dig` binary.

    Real fetcher for the operator console; tests inject stubs instead.
    Never raises — any failure (bad name, missing dig, timeout, parse
    error) returns [], which fails the challenge check closed. Args are
    passed as a list (no shell). See the section docstring for the
    plain-language trust caveat: this trusts the system resolver, no
    DNSSEC.
    """
    try:
        if not isinstance(txt_name, str):
            return []
        name = txt_name.strip().rstrip(".")
        if not name or len(name) > 253:
            return []
        for lab in name.split("."):
            # The challenge label starts with an underscore, which is
            # legal for DNS TXT owner names (RFC 8555 style).
            stripped = lab.lstrip("_")
            if not _DNS_LABEL_RE.match(stripped or "_"):
                return []
        proc = subprocess.run(
            ["dig", "+short", "TXT", name],
            capture_output=True, text=True,
            timeout=timeout_s, check=False)
        out = proc.stdout or ""
    except Exception:
        return []
    records = []
    for line in out.splitlines():
        txt = _unquote_txt(line)
        if txt:
            records.append(txt)
    return records


def fetch_https_json(url, timeout_s=10):
    """GET a URL and parse the body as JSON. Raises ValueError on failure.

    Hardened for the console's future use: https scheme only (no
    scheme/host injection — userinfo/@ is rejected), 10s timeout, 1 MiB
    response cap, strict JSON parse. Callers treat a raise as "not
    proven" and fail closed. Redirects are followed only while the
    final URL stays https.
    """
    try:
        parts = urllib.parse.urlparse(url)
    except Exception:
        raise ValueError("https fetch failed: malformed URL")
    if parts.scheme != "https":
        raise ValueError("https fetch failed: only https is allowed")
    if not parts.hostname:
        raise ValueError("https fetch failed: URL has no host")
    if "@" in parts.netloc:
        raise ValueError("https fetch failed: userinfo not allowed")
    try:
        req = urllib.request.Request(
            url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if urllib.parse.urlparse(resp.geturl()).scheme != "https":
                raise ValueError("redirect left https")
            body = resp.read(_MAX_JWKS_BYTES + 1)
    except ValueError:
        raise
    except Exception:
        raise ValueError(
            f"https fetch failed for host {parts.hostname}")
    if len(body) > _MAX_JWKS_BYTES:
        raise ValueError("https fetch failed: response exceeds size cap")
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        raise ValueError("https fetch failed: response is not JSON")


def _require_pubkey_in_jwks(jwks, pubkey_hex):
    """Fail-closed check: the enrolling key must appear in the JWKS dict.

    A key entry matches when its "kid" equals the key's JWK thumbprint
    (the Phase 12 kid convention) OR its "x" equals the base64url of the
    raw public key bytes. Raises ValueError when the directory is
    malformed or the key is absent.
    """
    if not isinstance(jwks, dict):
        raise ValueError("key directory is not a JSON object")
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise ValueError("key directory has no 'keys' list")
    if len(keys) > 4096:
        raise ValueError("key directory lists an absurd number of keys")
    want_kid = jwk_thumbprint(pubkey_hex)
    want_x = _b64url_nopad(bytes.fromhex(pubkey_hex))
    for entry in keys:
        if not isinstance(entry, dict):
            continue
        if entry.get("kid") == want_kid:
            return
        if entry.get("x") == want_x:
            return
    raise ValueError("enrolling key not present in the domain key directory")


def _current_principals(log):
    """Fold the log to today's principal state (raises ValueError if bad)."""
    principals, _, _ = _fold_log_into_principals(log.entries())
    return principals


def enroll_principal_tier1(*, log, principal_id, domain, pubkey_hex, label,
                           challenge, fetch_txt, fetch_https,
                           operator_priv_hex, operator_pub_hex,
                           issued_at=None):
    """Enroll one principal at Tier 1 ("domain-control").

    Steps, all fail-closed:
      1. verify the DNS challenge (raises on failure),
      2. fetch https://<domain>/.well-known/vouch-keys (raises on failure),
      3. require the enrolling pubkey to be listed in that JWKS,
      4. append the "enroll" event (tier "domain-control", domain set)
         and issue the enrollment certificate pointing at that log seq.

    fetch_txt(txt_name) -> [str] and fetch_https(url) -> dict are
    injectable; the console passes fetch_txt_via_dig / fetch_https_json.

    Returns (cert, manifest_entry). Raises ValueError on any failure —
    nothing half-enrolled ever happens.
    """
    if not isinstance(log, TransparencyLog):
        raise ValueError("log must be a TransparencyLog")
    _check_id(principal_id, "principal_id", _MAX_ID_LEN)
    d = _check_domain(domain)
    _check_id(label, "label", _MAX_LABEL_LEN)
    _check_hex32(pubkey_hex, "pubkey_hex")
    op_pub = _check_hex32(operator_pub_hex, "operator_pub_hex").hex()
    if op_pub != _operator_pubkey_from_priv(operator_priv_hex):
        raise ValueError("operator_pub_hex does not match operator_priv_hex")
    if not isinstance(challenge, dict):
        raise ValueError("challenge must be a dict")
    if challenge.get("domain") != d:
        raise ValueError("challenge was not created for this domain")
    ok, reason = verify_dns_challenge(challenge, fetch_txt)
    if not ok:
        raise ValueError(f"domain control check failed: {reason}")
    if not callable(fetch_https):
        raise ValueError("fetch_https is not callable")
    url = "https://" + d + "/.well-known/vouch-keys"
    try:
        jwks = fetch_https(url)
    except Exception as exc:
        raise ValueError(
            f"key directory fetch failed ({exc.__class__.__name__})")
    _require_pubkey_in_jwks(jwks, pubkey_hex)

    key_id = jwk_thumbprint(pubkey_hex)
    now = _ts(issued_at)
    payload = {
        "principal_id": principal_id,
        "tier": TIER_DOMAIN_CONTROL,
        "domain": d,
        "keys": [{"key_id": key_id, "pubkey": pubkey_hex, "label": label}],
        "enrolled_at": now,
        "expires_at": round(now + ENROLLMENT_TTL_S, 3),
    }
    entry = log.append("enroll", payload, operator_priv_hex, ts=now)
    cert = issue_enrollment_certificate(
        principal_id=principal_id,
        tier=TIER_DOMAIN_CONTROL,
        domain=d,
        key_ids=[{"key_id": key_id, "pubkey": pubkey_hex,
                  "label": label, "status": "active"}],
        operator_priv_hex=operator_priv_hex,
        operator_pub_hex=op_pub,
        log_seq=entry["seq"],
        ttl_s=ENROLLMENT_TTL_S,
        issued_at=now,
    )
    manifest_entry = _new_principal_entry(payload, entry["seq"])
    return cert, manifest_entry


# ---------------------------------------------------------------- key lifecycle (Phase 10)
def rotate_key(*, log, principal_id, old_pubkey_hex, new_pubkey_hex, label,
               operator_priv_hex, overlap_s=ROTATION_OVERLAP_S,
               issued_at=None):
    """Rotate a principal's key with a grace overlap.

    Appends the frozen "rotate" payload:
        {"principal_id","old_key_id",
         "new_key":{"key_id","pubkey","label"},
         "rotated_at","overlap_s"}
    The old key becomes "superseded" and stays usable until
    rotated_at + overlap_s (default 72h) so in-flight credentials keep
    working. The old key must currently be active; the new key must not
    already be enrolled. Returns the appended log entry.
    """
    if not isinstance(log, TransparencyLog):
        raise ValueError("log must be a TransparencyLog")
    _check_id(principal_id, "principal_id", _MAX_ID_LEN)
    _check_hex32(old_pubkey_hex, "old_pubkey_hex")
    _check_hex32(new_pubkey_hex, "new_pubkey_hex")
    _check_id(label, "label", _MAX_LABEL_LEN)
    if old_pubkey_hex.lower() == new_pubkey_hex.lower():
        raise ValueError("new key must differ from the old key")
    if (not isinstance(overlap_s, (int, float))
            or isinstance(overlap_s, bool) or overlap_s <= 0):
        raise ValueError("overlap_s must be a positive number")
    if overlap_s > 30 * 24 * 3600:
        raise ValueError("overlap_s is absurdly long (cap: 30 days)")
    principals = _current_principals(log)
    entry = principals.get(principal_id)
    if entry is None:
        raise ValueError("rotate for unknown principal")
    if entry["status"] != "active":
        raise ValueError("cannot rotate a key of a non-active principal")
    old_kid = jwk_thumbprint(old_pubkey_hex)
    old = next((k for k in entry["keys"] if k["key_id"] == old_kid), None)
    if old is None:
        raise ValueError("old key is not enrolled for this principal")
    if old["status"] != "active":
        raise ValueError("old key is not active")
    new_kid = jwk_thumbprint(new_pubkey_hex)
    if any(k["key_id"] == new_kid for k in entry["keys"]):
        raise ValueError("new key is already enrolled for this principal")
    now = _ts(issued_at)
    payload = {
        "principal_id": principal_id,
        "old_key_id": old_kid,
        "new_key": {"key_id": new_kid, "pubkey": new_pubkey_hex,
                    "label": label},
        "rotated_at": now,
        "overlap_s": overlap_s,
    }
    return log.append("rotate", payload, operator_priv_hex, ts=now)


def revoke_key(*, log, principal_id, pubkey_hex, reason,
               operator_priv_hex, issued_at=None):
    """Revoke one of a principal's keys, effective immediately.

    Appends the frozen "revoke-key" payload:
        {"principal_id","key_id","revoked_at","reason"}
    Revocation is permanent — a revoked key never becomes usable again
    (use rotate_key to move to a new key). Returns the appended entry.
    """
    if not isinstance(log, TransparencyLog):
        raise ValueError("log must be a TransparencyLog")
    _check_id(principal_id, "principal_id", _MAX_ID_LEN)
    _check_hex32(pubkey_hex, "pubkey_hex")
    _check_id(reason, "reason", _MAX_REASON_LEN)
    principals = _current_principals(log)
    entry = principals.get(principal_id)
    if entry is None:
        raise ValueError("revoke-key for unknown principal")
    kid = jwk_thumbprint(pubkey_hex)
    key = next((k for k in entry["keys"] if k["key_id"] == kid), None)
    if key is None:
        raise ValueError("revoke-key for a key not enrolled for this principal")
    if key["status"] == "revoked":
        raise ValueError("key is already revoked")
    payload = {
        "principal_id": principal_id,
        "key_id": kid,
        "revoked_at": _ts(issued_at),
        "reason": reason,
    }
    return log.append("revoke-key", payload, operator_priv_hex,
                      ts=payload["revoked_at"])


def suspend_principal(*, log, principal_id, reason,
                      operator_priv_hex, issued_at=None):
    """Suspend a principal: all its keys report "suspended" in the fold.

    Appends the frozen "suspend" payload:
        {"principal_id","suspended_at","reason"}
    Returns the appended log entry.
    """
    if not isinstance(log, TransparencyLog):
        raise ValueError("log must be a TransparencyLog")
    _check_id(principal_id, "principal_id", _MAX_ID_LEN)
    _check_id(reason, "reason", _MAX_REASON_LEN)
    principals = _current_principals(log)
    entry = principals.get(principal_id)
    if entry is None:
        raise ValueError("suspend for unknown principal")
    if entry["status"] == "suspended":
        raise ValueError("principal is already suspended")
    payload = {
        "principal_id": principal_id,
        "suspended_at": _ts(issued_at),
        "reason": reason,
    }
    return log.append("suspend", payload, operator_priv_hex,
                      ts=payload["suspended_at"])


def unsuspend_principal(*, log, principal_id, operator_priv_hex,
                        issued_at=None):
    """Lift a suspension: the principal's status returns to "active".

    Appends the frozen "unsuspend" payload:
        {"principal_id","unsuspended_at"}
    Keys revoked or superseded while suspended stay that way — only the
    principal-level status is restored. Returns the appended log entry.
    """
    if not isinstance(log, TransparencyLog):
        raise ValueError("log must be a TransparencyLog")
    _check_id(principal_id, "principal_id", _MAX_ID_LEN)
    principals = _current_principals(log)
    entry = principals.get(principal_id)
    if entry is None:
        raise ValueError("unsuspend for unknown principal")
    if entry["status"] != "suspended":
        raise ValueError("principal is not suspended")
    payload = {
        "principal_id": principal_id,
        "unsuspended_at": _ts(issued_at),
    }
    return log.append("unsuspend", payload, operator_priv_hex,
                      ts=payload["unsuspended_at"])
