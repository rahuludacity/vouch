"""Tamper-evident, hash-chained, HMAC-signed receipts for agent actions.

Every intercepted tool call — allowed or denied — gets a receipt:
  seq, ts, task_id, agent_id, tool, args_sha256, decision, reason,
  prev_hash, hash, sig

The hash chain makes insertion/deletion/reordering detectable.
The HMAC signature proves the receipt came from this gatekeeper.
args are never stored raw — only their SHA-256 — so receipts stay
safe to hand to auditors.
"""
import hashlib
import hmac
import json
import os
import time


class ReceiptLog:
    def __init__(self, path, key):
        self.path = path
        self.key = key.encode("utf-8") if isinstance(key, str) else key
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

    def record(self, *, task_id, agent_id, tool, args, decision, reason=None):
        self.seq += 1
        body = {
            "seq": self.seq,
            "ts": round(time.time(), 3),
            "task_id": task_id,
            "agent_id": agent_id,
            "tool": tool,
            "args_sha256": hashlib.sha256(
                json.dumps(args, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest(),
            "decision": decision,  # "allow" | "deny"
            "reason": reason,
            "prev_hash": self.prev_hash,
        }
        body["hash"] = hashlib.sha256(
            self.prev_hash.encode("utf-8")
            + json.dumps(body, sort_keys=True).encode("utf-8")
        ).hexdigest()
        body["sig"] = hmac.new(
            self.key, json.dumps(body, sort_keys=True).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        self.prev_hash = body["hash"]
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(body) + "\n")
        return body

    def verify(self):
        """Replay the whole chain. Returns (ok, failures)."""
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
                want_sig = hmac.new(
                    self.key,
                    json.dumps({**body, "hash": r["hash"]}, sort_keys=True).encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                if r["sig"] != want_sig:
                    failures.append(f"line {i}: bad signature")
                prev = r["hash"]
        return (len(failures) == 0), failures
