"""Migrate a v1 receipts.jsonl (one global chain) into per-tenant v2 chains (§6).

For each tenant: rows are ordered by v1 seq, every signature is verified
against the tenant's keys BEFORE import (any failure aborts the whole
import — nothing is written), then rows are inserted with a per-tenant v2
seq (1..N). Original fields are preserved byte-for-byte: ts, prev_hash,
hash, sig; the v1 global seq is kept in the v1_seq side column for audit
continuity. New post-import receipts chain off each tenant's tip_hash.

An import manifest row is emitted per tenant:
    {tenant_id, v1_lines, imported, tip_hash}
Tenants that already have v2 rows are skipped (import targets empty stores).

The original file is never modified.

Run:  python3 -m services.receipts.import_v1 --db receipts.db \
          --ledger receipts.jsonl [--tenants tenants.json] [--tenant acme ...]
"""
import argparse
import hashlib
import hmac
import json
import os
import sys

from .store import ReceiptStore

HERE = os.path.dirname(__file__)


def _verify_v1_record(r, keys):
    """Verify one v1 record's hash + HMAC. Returns error string or None."""
    body = {k: v for k, v in r.items() if k not in ("hash", "sig")}
    want_hash = hashlib.sha256(
        r["prev_hash"].encode("utf-8")
        + json.dumps(body, sort_keys=True).encode("utf-8")
    ).hexdigest()
    if r["hash"] != want_hash:
        return "hash mismatch (tampered body?)"
    kid = r.get("kid")
    candidates = [keys[kid]] if kid in keys else (
        list(keys.values()) if kid is None else [])
    if not candidates:
        return f"unknown key id '{kid}'"
    sig_body = json.dumps({**body, "hash": r["hash"]},
                          sort_keys=True).encode("utf-8")
    for ck in candidates:
        if hmac.compare_digest(
                hmac.new(ck, sig_body, hashlib.sha256).hexdigest(), r["sig"]):
            return None
    return "bad signature"


def _load_keys(tenants_path):
    with open(os.path.abspath(tenants_path), "r", encoding="utf-8") as f:
        tenants = json.load(f).get("tenants", {})
    return {tid: {kid: bytes.fromhex(k) for kid, k in t["keys"].items()}
            for tid, t in tenants.items()}


def main(argv=None):
    ap = argparse.ArgumentParser(description="import v1 receipts.jsonl -> v2 store")
    ap.add_argument("--db", required=True, help="sqlite db path")
    ap.add_argument("--ledger", required=True, help="v1 receipts.jsonl path")
    ap.add_argument("--tenants", default=os.path.join(HERE, "..", "..", "tenants.json"))
    ap.add_argument("--tenant", action="append", default=None,
                    help="only import these tenants (default: all)")
    args = ap.parse_args(argv)

    with open(args.ledger, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]
    keymap = _load_keys(args.tenants)

    by_tenant = {}
    for r in records:
        tid = r.get("tenant_id", "default")
        if args.tenant and tid not in args.tenant:
            continue
        by_tenant.setdefault(tid, []).append(r)

    # ---- phase 1: verify EVERYTHING before writing anything ----
    for tid, rows in by_tenant.items():
        keys = keymap.get(tid)
        if not keys:
            print(f"ERROR: unknown tenant '{tid}' in ledger "
                  f"(no keys in {args.tenants}); aborting", file=sys.stderr)
            return 2
        rows.sort(key=lambda r: r["seq"])
        for r in rows:
            err = _verify_v1_record(r, keys)
            if err:
                print(f"ERROR: tenant '{tid}' v1_seq {r['seq']}: {err}; "
                      f"aborting (nothing imported)", file=sys.stderr)
                return 2

    # ---- phase 2: import ----
    store = ReceiptStore(args.db)
    manifest = []
    for tid, rows in sorted(by_tenant.items()):
        if store.has_receipts(tid):
            print(f"SKIP: tenant '{tid}' already has v2 receipts")
            continue
        for v2_seq, r in enumerate(rows, start=1):
            row = dict(r, tenant_id=tid, seq=v2_seq)
            store.insert_imported(row, v1_seq=r["seq"])
        tip_hash = rows[-1]["hash"]
        store.record_import_manifest(tid, len(rows), len(rows), tip_hash)
        manifest.append({"tenant_id": tid, "v1_lines": len(rows),
                         "imported": len(rows), "tip_hash": tip_hash})
        print(f"imported tenant '{tid}': {len(rows)} receipts, tip {tip_hash[:16]}…")
    store.close()
    print(json.dumps({"manifest": manifest}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
