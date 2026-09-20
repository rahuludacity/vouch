"""Verify the receipt chain: proves no receipt was added, removed,
reordered, or altered since issuance — per tenant.

Each receipt is checked against the key its own (tenant_id, kid) points
at, so verification stays valid across key rotations, and a receipt
forged with another tenant's key fails here.

Run: python3 -m gatekeeper.verify
Env: GATEKEEPER_TENANTS_PATH / GATEKEEPER_RECEIPTS_PATH (same as proxy)"""
import os

from .receipts import ReceiptLog
from .tenants import DEFAULT_PATH as TENANTS_DEFAULT, TenantRegistry

HERE = os.path.dirname(__file__)
TENANTS_PATH = os.environ.get("GATEKEEPER_TENANTS_PATH", TENANTS_DEFAULT)
PATH = os.environ.get(
    "GATEKEEPER_RECEIPTS_PATH", os.path.join(HERE, "..", "receipts.jsonl")
)

registry = TenantRegistry(TENANTS_PATH)
ok, failures = ReceiptLog(PATH, registry).verify()
if ok:
    print("RECEIPTS VERIFIED: chain intact, all signatures valid.")
else:
    print("RECEIPT VERIFICATION FAILED:")
    for f in failures:
        print("  -", f)
    raise SystemExit(1)
