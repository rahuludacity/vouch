"""Tests for vouch.verify — client-side chain replay.

Mints receipts with the exact vouch crypto (build_receipt equivalent),
then checks ok/tamper/rotation/reorder/drop cases.
"""

import hashlib
import hmac
import json
import unittest

from vouch.verify import verify_chain


def mint(seq, prev_hash, tenant_id, kid, key, task_id, agent_id, tool, args,
         decision, reason=None, rule_id=None, policy_version=None, ts=1700000000.0):
    body = {
        "seq": seq, "ts": ts, "tenant_id": tenant_id, "kid": kid,
        "task_id": task_id, "agent_id": agent_id, "tool": tool,
        "args_sha256": hashlib.sha256(
            json.dumps(args, sort_keys=True, default=str).encode()).hexdigest(),
        "decision": decision, "reason": reason, "rule_id": rule_id,
        "policy_version": policy_version, "prev_hash": prev_hash,
    }
    body["hash"] = hashlib.sha256(
        prev_hash.encode() + json.dumps(body, sort_keys=True).encode()
    ).hexdigest()
    body["sig"] = hmac.new(
        key, json.dumps(body, sort_keys=True).encode(), hashlib.sha256
    ).hexdigest()
    return body


def make_chain(n=4, tenant_id="acme", keys=None):
    keys = keys or {"k1": b"secret-one"}
    receipts, prev = [], "GENESIS"
    for i in range(1, n + 1):
        r = mint(i, prev, tenant_id, "k1", keys["k1"], "deploy-staging",
                 "agent-1", "run_tests", {"suite": "unit"},
                 "allow" if i % 2 else "deny",
                 reason=None if i % 2 else "denied by rule 'no-x'",
                 rule_id="tests-ok" if i % 2 else "no-x", policy_version=3)
        receipts.append(r)
        prev = r["hash"]
    return receipts, keys


class TestVerifyChain(unittest.TestCase):
    def test_clean_chain_ok(self):
        receipts, keys = make_chain(5)
        ok, failures = verify_chain(receipts, keys)
        self.assertTrue(ok, failures)
        self.assertEqual(failures, [])

    def test_accepts_shuffled_input(self):
        receipts, keys = make_chain(4)
        ok, _ = verify_chain(list(reversed(receipts)), keys)
        self.assertTrue(ok)

    def test_body_tamper_detected(self):
        receipts, keys = make_chain(4)
        receipts[1]["decision"] = "allow"  # seq 2 was deny
        ok, failures = verify_chain(receipts, keys)
        self.assertFalse(ok)
        self.assertTrue(any(f["seq"] == 2 for f in failures))

    def test_sig_tamper_detected(self):
        receipts, keys = make_chain(3)
        receipts[1]["sig"] = "0" * 64
        ok, failures = verify_chain(receipts, keys)
        self.assertFalse(ok)
        self.assertTrue(any("bad signature" in f["error"]
                            for f in failures if f["seq"] == 2))

    def test_reorder_detected(self):
        # The server (and this helper) orders by seq; a real reorder attack
        # swaps seq values, breaking seq continuity and the body hash.
        receipts, keys = make_chain(4)
        receipts[1]["seq"], receipts[2]["seq"] = 3, 2
        ok, failures = verify_chain(receipts, keys)
        self.assertFalse(ok)

    def test_drop_detected(self):
        receipts, keys = make_chain(4)
        del receipts[1]  # remove seq 2
        ok, failures = verify_chain(receipts, keys)
        self.assertFalse(ok)
        self.assertTrue(any("seq break" in f["error"] for f in failures))

    def test_wrong_key_fails(self):
        receipts, _ = make_chain(3)
        ok, _ = verify_chain(receipts, {"k1": b"wrong-key"})
        self.assertFalse(ok)

    def test_hex_key_accepted(self):
        receipts, keys = make_chain(2)
        hexkeys = {k: v.hex() for k, v in keys.items()}
        ok, failures = verify_chain(receipts, hexkeys)
        self.assertTrue(ok, failures)

    def test_rotation_two_kids(self):
        k1, k2 = b"old-secret", b"new-secret"
        receipts, prev = [], "GENESIS"
        for i, (kid, key) in enumerate([("k1", k1), ("k1", k1),
                                        ("k2", k2), ("k2", k2)], start=1):
            r = mint(i, prev, "acme", kid, key, "t", "a", "read_file",
                     {"path": "x"}, "allow")
            receipts.append(r)
            prev = r["hash"]
        ok, failures = verify_chain(receipts, {"k1": k1, "k2": k2})
        self.assertTrue(ok, failures)

    def test_unknown_kid_fails(self):
        receipts, keys = make_chain(2)
        ok, failures = verify_chain(receipts, {})
        self.assertFalse(ok)
        self.assertTrue(any("unknown key id" in f["error"] for f in failures))

    def test_empty_chain_ok(self):
        ok, failures = verify_chain([], {"k1": b"x"})
        self.assertTrue(ok)
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
