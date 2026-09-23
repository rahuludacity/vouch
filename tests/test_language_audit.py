"""Language audit (PRD section 4): Tier 1 proves domain control, never identity.

Scans every Python module in services/verifier/ for the banned
user-facing phrases and fails if any appear (case-insensitive).
New modules added later (e.g. rfc9421.py in Phase 12) are covered
automatically because the scan is by directory, not by file list.

The banned phrases live in this test only as search patterns — never
copy them into product code or user-facing strings.
"""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

VERIFIER_DIR = os.path.join(REPO, "services", "verifier")

# Phrases that overclaim: a DNS/domain check proves control of a domain,
# not identity. Tier 1 receipts say tier "domain-control", nothing more.
_BANNED = (
    "verified identity",
    "identity verified",
    "verified principal",
)
_PATTERNS = [re.compile(re.escape(p), re.IGNORECASE) for p in _BANNED]


def _scan_file(path):
    hits = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            for pat in _PATTERNS:
                if pat.search(line):
                    hits.append(f"{path}:{lineno}: {line.strip()[:120]}")
    return hits


class LanguageAuditTest(unittest.TestCase):
    def test_no_identity_overclaims_in_verifier(self):
        hits = []
        for name in sorted(os.listdir(VERIFIER_DIR)):
            if not name.endswith(".py"):
                continue
            hits.extend(_scan_file(os.path.join(VERIFIER_DIR, name)))
        self.assertEqual(
            hits, [],
            "identity-overclaim language found in services/verifier/:\n"
            + "\n".join(hits))


if __name__ == "__main__":
    unittest.main()
