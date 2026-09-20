"""Tamper-evident, hash-chained, HMAC-signed receipts for agent actions.

Every intercepted tool call — allowed or denied — gets a receipt:
  seq, ts, tenant_id, kid, task_id, agent_id, tool, args_sha256,
  decision, reason, prev_hash, hash, sig

The hash chain makes insertion/deletion/reordering detectable.
The HMAC signature proves the receipt came from this gatekeeper —
signed with the *calling tenant's* key, so tenants cannot forge
each other's audit trails. `kid` pins which key signed it, so
receipts keep verifying after key rotation.

args are never stored raw — only their SHA-256 — so receipts stay
safe to hand to auditors.

The `key` argument is either:
  - bytes/str: a single static key (v0 behavior; tenant defaults to
    "default", kid to "k0"), or
  - a resolver with signing_key(tenant_id) -> (kid, key_bytes) and
    verification_keys(tenant_id) -> {kid: key_bytes}
    (gatekeeper.tenants.TenantRegistry implements this).
"""
import hashlib
import hmac
import json
import os
import threading
import time


def build_receipt(*, seq, prev_hash, tenant_id, kid, key, task_id, agent_id,
                  tool, args, decision, reason=None, rule_id=None,
                  policy_version=None, ts=None):
    """Construct and HMAC-sign one receipt body (no I/O).

    Extracted from ReceiptLog.record so the gatekeeper can mint
    per-tenant-chained receipts for the receipt service with the exact same
    crypto as the local v1 file fallback. `rule_id` / `policy_version` are
    the v2 fields (§6); None keeps v1-shaped receipts, which still verify.
    """
    body = {
        "seq": seq,
        "ts": round(time.time(), 3) if ts is None else ts,
        "tenant_id": tenant_id,
        "kid": kid,
        "task_id": task_id,
        "agent_id": agent_id,
        "tool": tool,
        "args_sha256": hashlib.sha256(
            json.dumps(args, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest(),
        "decision": decision,  # "allow" | "deny"
        "reason": reason,
        "rule_id": rule_id,
        "policy_version": policy_version,
        "prev_hash": prev_hash,
    }
    body["hash"] = hashlib.sha256(
        prev_hash.encode("utf-8")
        + json.dumps(body, sort_keys=True).encode("utf-8")
    ).hexdigest()
    body["sig"] = hmac.new(
        key, json.dumps(body, sort_keys=True).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return body


class _StaticKeyResolver:
    """Adapts a single v0-style key to the resolver interface."""

    def __init__(self, key):
        self._key = key.encode("utf-8") if isinstance(key, str) else key

    def signing_key(self, tenant_id):
        return "k0", self._key

    def verification_keys(self, tenant_id):
        return {"k0": self._key}


class ReceiptLog:
    def __init__(self, path, key):
        self.path = path
        if hasattr(key, "signing_key") and hasattr(key, "verification_keys"):
            self.resolver = key
        else:
            self.resolver = _StaticKeyResolver(key)
        self._lock = threading.Lock()
        self.seq = 0
        self.prev_hash = "GENESIS"
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    r = json.loads(line)
                    self.seq = r["seq"]
                    self.prev_hash = r["hash"]

    def record(self, *, task_id, agent_id, tool, args, decision,
               reason=None, tenant_id="default", rule_id=None,
               policy_version=None):
        kid, key = self.resolver.signing_key(tenant_id)
        with self._lock:
            self.seq += 1
            body = build_receipt(
                seq=self.seq,
                prev_hash=self.prev_hash,
                tenant_id=tenant_id,
                kid=kid,
                key=key,
                task_id=task_id,
                agent_id=agent_id,
                tool=tool,
                args=args,
                decision=decision,
                reason=reason,
                rule_id=rule_id,
                policy_version=policy_version,
            )
            self.prev_hash = body["hash"]
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(body) + "\n")
            return body

    def verify(self):
        """Replay the whole chain. Returns (ok, failures).

        Each receipt is verified against the key its own (tenant_id, kid)
        points at — rotation-safe, and cross-tenant forgery fails here."""
        failures = []
        prev = "GENESIS"
        seq = 0
        if not os.path.exists(self.path):
            return True, []
        with open(self.path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                seq += 1
                if r["seq"] != seq:
                    failures.append(f"line {i}: seq break (want {seq}, got {r['seq']})")
                if r["prev_hash"] != prev:
                    failures.append(f"line {i}: chain break")
                body = {k: v for k, v in r.items() if k not in ("hash", "sig")}
                want_hash = hashlib.sha256(
                    prev.encode("utf-8")
                    + json.dumps(body, sort_keys=True).encode("utf-8")
                ).hexdigest()
                if r["hash"] != want_hash:
                    failures.append(f"line {i}: hash mismatch (tampered body?)")
                tenant_id = r.get("tenant_id", "default")
                kid = r.get("kid")
                try:
                    keys = self.resolver.verification_keys(tenant_id)
                except KeyError:
                    failures.append(f"line {i}: unknown tenant '{tenant_id}'")
                    prev = r["hash"]
                    continue
                if kid is None:
                    # legacy v0 receipt: try every known key for the tenant
                    candidates = list(keys.values())
                elif kid not in keys:
                    failures.append(
                        f"line {i}: unknown key id '{kid}' for tenant '{tenant_id}'"
                        " (rotated away?)"
                    )
                    prev = r["hash"]
                    continue
                else:
                    candidates = [keys[kid]]
                want_sig = None
                for ck in candidates:
                    want_sig = hmac.new(
                        ck,
                        json.dumps({**body, "hash": r["hash"]}, sort_keys=True).encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()
                    if want_sig == r["sig"]:
                        break
                else:
                    failures.append(f"line {i}: bad signature")
                prev = r["hash"]
        return (len(failures) == 0), failures
