/** Client-side (offline) verification of Vouch receipt chains.
 *
 * Mirrors services/receipts/store.py::verify_tenant exactly:
 * seq continuity per tenant, prev_hash linkage from "GENESIS",
 * body hash = sha256(prev_hash_bytes + canonicalJson(body)),
 * sig = HMAC-SHA256(key, canonicalJson({...body, hash})).
 * Bookkeeping fields (hash, sig, ingested_at, v1_seq) are never signed.
 *
 * canonicalJson = JSON.stringify with keys sorted recursively — the same
 * canonical form as Python's json.dumps(..., sort_keys=True).
 */

import { createHmac, createHash, timingSafeEqual } from "node:crypto";

const V1_BODY_KEYS = ["seq", "ts", "tenant_id", "kid", "task_id", "agent_id",
  "tool", "args_sha256", "decision", "reason", "prev_hash"];

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  return "{" + Object.keys(value).sort()
    .map(k => JSON.stringify(k) + ":" + canonicalJson(value[k])).join(",") + "}";
}

function keyBytes(key) {
  if (Buffer.isBuffer(key)) return key;
  if (typeof key === "string") {
    if (/^[0-9a-fA-F]+$/.test(key) && key.length % 2 === 0) {
      try { return Buffer.from(key, "hex"); } catch { /* fall through */ }
    }
    return Buffer.from(key, "utf-8");
  }
  throw new TypeError(`key must be Buffer or string, got ${typeof key}`);
}

function bodyFor(receipt) {
  if (receipt.v1_seq != null) {
    // Imported v1 row: re-verify against the ORIGINAL v1 body (global seq).
    const body = {};
    for (const k of V1_BODY_KEYS) body[k] = receipt[k];
    body.seq = receipt.v1_seq;
    return body;
  }
  const body = {};
  for (const k of Object.keys(receipt)) {
    if (!["hash", "sig", "ingested_at", "v1_seq"].includes(k)) body[k] = receipt[k];
  }
  return body;
}

/** Replay a per-tenant receipt chain. Returns {ok, failures:[{seq,error}]}. */
export function verifyChain(receipts, keys) {
  const ordered = [...receipts].sort((a, b) => a.seq - b.seq);
  const failures = [];
  let prevHash = "GENESIS", prevV1Seq = null;
  for (let i = 0; i < ordered.length; i++) {
    const r = ordered[i], wantSeq = i + 1, seq = r.seq;
    if (seq !== wantSeq) failures.push({ seq, error: `seq break (want ${wantSeq})` });
    const imported = r.v1_seq != null;
    if (imported) {
      if (prevV1Seq !== null && r.v1_seq <= prevV1Seq)
        failures.push({ seq, error: "imported v1_seq out of order" });
      prevV1Seq = r.v1_seq;
    } else if (seq === 1) {
      if (r.prev_hash !== "GENESIS") failures.push({ seq, error: "chain break at genesis" });
    } else if (r.prev_hash !== prevHash) {
      failures.push({ seq, error: "chain break" });
    }
    const body = bodyFor(r);
    const wantHash = createHash("sha256")
      .update(r.prev_hash, "utf-8").update(canonicalJson(body), "utf-8").digest("hex");
    if (r.hash !== wantHash)
      failures.push({ seq, error: "hash mismatch (tampered body?)" });
    const key = r.kid ? keys[r.kid] : undefined;
    if (key === undefined) {
      failures.push({ seq, error: `unknown key id '${r.kid}'` });
    } else {
      const wantSig = createHmac("sha256", keyBytes(key))
        .update(canonicalJson({ ...body, hash: r.hash }), "utf-8").digest("hex");
      let match = false;
      try {
        match = timingSafeEqual(Buffer.from(wantSig, "hex"), Buffer.from(r.sig, "hex"));
      } catch { match = false; }
      if (!match) failures.push({ seq, error: "bad signature" });
    }
    prevHash = r.hash;
  }
  return { ok: failures.length === 0, failures };
}
