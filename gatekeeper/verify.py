"""Verify the receipt chain: proves no receipt was added, removed,
reordered, or altered since issuance. Run: python3 gatekeeper/verify.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from receipts import ReceiptLog  # noqa: E402

KEY = os.environ.get("GATEKEEPER_KEY", "dev-only-change-me")
PATH = os.path.join(os.path.dirname(__file__), "..", "receipts.jsonl")

ok, failures = ReceiptLog(PATH, KEY).verify()
if ok:
    print("RECEIPTS VERIFIED: chain intact, all signatures valid.")
else:
    print("RECEIPT VERIFICATION FAILED:")
    for f in failures:
        print("  -", f)
    sys.exit(1)
