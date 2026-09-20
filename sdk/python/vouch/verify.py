"""Client-side (offline) verification of Vouch receipt chains.

Mirrors ``services/receipts/store.py::verify_tenant`` exactly:

* seq continuity per tenant, ``prev_hash`` linkage from ``"GENESIS"``
* body hash: ``sha256(prev_hash_bytes + json.dumps(body, sort_keys=True))``
* signature: ``HMAC-SHA256(key, json.dumps({**body, "hash": hash}, sort_keys=True))``
* bookkeeping fields (``hash``, ``sig``, ``ingested_at``, ``v1_seq``) are never signed

Keys stay server-side in production — this helper is for operators with key
access (self-host, export/audit tooling). Tenants without key material should
use ``VouchClient.verify()`` (server-side ``GET /v1/verify``) instead.
"""

import hashlib
import hmac
import json

_V1_BODY_KEYS = ("seq", "ts", "tenant_id", "kid", "task_id", "agent_id",
                "tool", "args_sha256", "decision", "reason", "prev_hash")


def _key_bytes(key):
    if isinstance(key, bytes):
        return key
    if isinstance(key, str):
        # hex-encoded (as stored in tenant_keys.key_hex) or raw string
        try:
            return bytes.fromhex(key)
        except ValueError:
            return key.encode("utf-8")
    raise TypeError(f"key must be bytes or str, got {type(key).__name__}")


def _body_for(receipt):
    """Reconstruct the signed body for one receipt dict."""
    if receipt.get("v1_seq") is not None:
        # Imported v1 row: re-verify against the ORIGINAL v1 body (global seq),
        # which is what the preserved hash/sig cover.
        body = {k: receipt[k] for k in _V1_BODY_KEYS}
        body["seq"] = receipt["v1_seq"]
        return body
    return {k: v for k, v in receipt.items()
            if k not in ("hash", "sig", "ingested_at", "v1_seq")}


def verify_chain(receipts, keys):
    """Replay a per-tenant receipt chain and check every HMAC.

    ``receipts``: list of receipt dicts (as returned by ``GET /v1/receipts``),
    in any order (sorted by seq internally).
    ``keys``: ``{kid: key}`` where key is bytes or hex string.

    Returns ``(ok, failures)`` — ``failures`` is a list of
    ``{"seq": n, "error": "..."}`` dicts, same shape as the server's.
    """
    receipts = sorted(receipts, key=lambda r: r["seq"])
    failures = []
    prev_hash, prev_v1_seq = "GENESIS", None
    for want_seq, r in enumerate(receipts, start=1):
        seq = r["seq"]
        if seq != want_seq:
            failures.append({"seq": seq,
                             "error": f"seq break (want {want_seq})"})
        imported = r.get("v1_seq") is not None
        if imported:
            if prev_v1_seq is not None and r["v1_seq"] <= prev_v1_seq:
                failures.append({"seq": seq,
                                 "error": "imported v1_seq out of order"})
            prev_v1_seq = r["v1_seq"]
        else:
            if seq == 1:
                if r["prev_hash"] != "GENESIS":
                    failures.append({"seq": seq,
                                     "error": "chain break at genesis"})
            elif r["prev_hash"] != prev_hash:
                failures.append({"seq": seq, "error": "chain break"})
        body = _body_for(r)
        want_hash = hashlib.sha256(
            r["prev_hash"].encode("utf-8")
            + json.dumps(body, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if r["hash"] != want_hash:
            failures.append({"seq": seq,
                             "error": "hash mismatch (tampered body?)"})
        kid = r.get("kid")
        key = keys.get(kid) if kid else None
        if key is None:
            failures.append({"seq": seq,
                             "error": f"unknown key id '{kid}'"})
        else:
            want_sig = hmac.new(
                _key_bytes(key),
                json.dumps({**body, "hash": r["hash"]},
                           sort_keys=True).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(want_sig, r["sig"]):
                failures.append({"seq": seq, "error": "bad signature"})
        prev_hash = r["hash"]
    return (len(failures) == 0), failures
