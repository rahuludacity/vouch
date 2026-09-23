// Cross-language golden test (H-4): receipts minted by the REAL Python
// receipt code (gatekeeper/receipts.py::build_receipt) must verify in the
// JS SDK end to end. The fixture lives at test/fixtures/python_golden.json
// and carries unicode strings, nested args, floats, booleans, and nulls.
//
// With the old no-space canonicalizer this test fails with "hash
// mismatch" on every receipt — that is the H-4 bug, proven by the stash
// run in the remediation notes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyChain } from "../src/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(readFileSync(
  join(here, "fixtures", "python_golden.json"), "utf-8"));

test("python-minted golden chain verifies end to end", () => {
  assert.ok(fixture.receipts.length >= 2, "fixture needs a real chain");
  const { ok, failures } = verifyChain(fixture.receipts, fixture.keys);
  assert.equal(ok, true, JSON.stringify(failures, null, 2));
  assert.deepEqual(failures, []);
});

test("golden fixture really exercises the tricky encodings", () => {
  const bodies = fixture.receipts.map(r => JSON.stringify(r));
  assert.ok(bodies.some(b => b.includes("café") || b.includes("décision")),
    "expected unicode in a receipt body");
  assert.ok(bodies.some(b => b.includes("1789286880.123")),
    "expected a non-integral float ts");
  assert.ok(bodies.some(b => b.includes("rule_id")),
    "expected v2 fields on at least one receipt");
  // Chain linkage the verifier itself enforces:
  assert.equal(fixture.receipts[0].prev_hash, "GENESIS");
  for (let i = 1; i < fixture.receipts.length; i++) {
    assert.equal(fixture.receipts[i].prev_hash, fixture.receipts[i - 1].hash);
    assert.equal(fixture.receipts[i].seq, i + 1);
  }
});

test("tampering the golden fixture is detected", () => {
  const tampered = JSON.parse(JSON.stringify(fixture.receipts));
  tampered[1].reason = "forged reason";
  const { ok, failures } = verifyChain(tampered, fixture.keys);
  assert.equal(ok, false);
  assert.ok(failures.some(f => f.seq === 2 && /hash mismatch/.test(f.error)));
});

test("golden fixture fails with the wrong key", () => {
  const { ok } = verifyChain(fixture.receipts, { [fixture.kid]: "00".repeat(32) });
  assert.equal(ok, false);
});
