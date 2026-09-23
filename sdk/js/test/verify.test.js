// Tests for verifyChain — same golden-crypto approach as the Python SDK:
// mint with the exact vouch crypto, then check ok/tamper/rotation/reorder.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, createHash } from "node:crypto";
import { verifyChain, canonicalJson } from "../src/verify.js";

// Mint with the exact verification encoding (canonicalJson is byte-
// identical to Python's json.dumps(sort_keys=True)), so these fixtures
// exercise the same code path as real Python-minted receipts.
const canon = canonicalJson;

function mint(seq, prevHash, tenantId, kid, key, taskId, agentId, tool, args, decision, ts = 1700000000.0) {
  const body = {
    seq, ts, tenant_id: tenantId, kid, task_id: taskId, agent_id: agentId,
    tool, args_sha256: createHash("sha256").update(canon(args)).digest("hex"),
    decision, reason: null, rule_id: null, policy_version: null, prev_hash: prevHash,
  };
  body.hash = createHash("sha256").update(prevHash, "utf-8").update(canon(body), "utf-8").digest("hex");
  body.sig = createHmac("sha256", key).update(canon({ ...body, hash: body.hash }), "utf-8").digest("hex");
  return body;
}

function makeChain(n = 4) {
  const keys = { k1: Buffer.from("secret-one") };
  const receipts = [];
  let prev = "GENESIS";
  for (let i = 1; i <= n; i++) {
    const r = mint(i, prev, "acme", "k1", keys.k1, "t", "a", "read_file",
      { path: "x" }, i % 2 ? "allow" : "deny");
    receipts.push(r); prev = r.hash;
  }
  return { receipts, keys };
}

test("clean chain verifies", () => {
  const { receipts, keys } = makeChain(5);
  const { ok, failures } = verifyChain(receipts, keys);
  assert.equal(ok, true, JSON.stringify(failures));
  assert.deepEqual(failures, []);
});

test("accepts shuffled input (sorted internally like the server)", () => {
  const { receipts, keys } = makeChain(4);
  assert.equal(verifyChain([...receipts].reverse(), keys).ok, true);
});

test("body tamper detected", () => {
  const { receipts, keys } = makeChain(4);
  receipts[1].decision = "allow"; // was deny
  const { ok, failures } = verifyChain(receipts, keys);
  assert.equal(ok, false);
  assert.ok(failures.some(f => f.seq === 2));
});

test("signature tamper detected", () => {
  const { receipts, keys } = makeChain(3);
  receipts[1].sig = "0".repeat(64);
  const { ok, failures } = verifyChain(receipts, keys);
  assert.equal(ok, false);
  assert.ok(failures.some(f => f.seq === 2 && /bad signature/.test(f.error)));
});

test("reordered seq values detected", () => {
  const { receipts, keys } = makeChain(4);
  receipts[1].seq = 3; receipts[2].seq = 2;
  assert.equal(verifyChain(receipts, keys).ok, false);
});

test("dropped receipt detected", () => {
  const { receipts, keys } = makeChain(4);
  receipts.splice(1, 1);
  const { ok, failures } = verifyChain(receipts, keys);
  assert.equal(ok, false);
  assert.ok(failures.some(f => /seq break/.test(f.error)));
});

test("wrong key fails", () => {
  const { receipts } = makeChain(3);
  assert.equal(verifyChain(receipts, { k1: Buffer.from("wrong") }).ok, false);
});

test("hex key accepted", () => {
  const { receipts } = makeChain(2);
  const { ok } = verifyChain(receipts, { k1: Buffer.from("secret-one").toString("hex") });
  assert.equal(ok, true);
});

test("rotation with two kids verifies", () => {
  const k1 = Buffer.from("old"), k2 = Buffer.from("new");
  const receipts = []; let prev = "GENESIS";
  [["k1", k1], ["k1", k1], ["k2", k2], ["k2", k2]].forEach(([kid, key], i) => {
    const r = mint(i + 1, prev, "acme", kid, key, "t", "a", "read_file", { p: 1 }, "allow");
    receipts.push(r); prev = r.hash;
  });
  assert.equal(verifyChain(receipts, { k1, k2 }).ok, true);
});

test("unknown kid fails", () => {
  const { receipts } = makeChain(2);
  const { ok, failures } = verifyChain(receipts, {});
  assert.equal(ok, false);
  assert.ok(failures.some(f => /unknown key id/.test(f.error)));
});
