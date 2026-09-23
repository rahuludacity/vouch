/** Client-side (offline) verification of Vouch receipt chains.
 *
 * Mirrors services/receipts/store.py::verify_tenant exactly:
 * seq continuity per tenant, prev_hash linkage from "GENESIS",
 * body hash = sha256(prev_hash_bytes + canonicalJson(body)),
 * sig = HMAC-SHA256(key, canonicalJson({...body, hash})).
 * Bookkeeping fields (hash, sig, ingested_at, v1_seq) are never signed.
 *
 * canonicalJson is byte-identical to Python's
 * json.dumps(value, sort_keys=True) for every JSON value this SDK can
 * observe:
 *   - object keys sorted by Unicode code point (NOT UTF-16 code unit:
 *     Python compares str by code point, so astral-plane keys sort
 *     differently than JS's default Array#sort would place them);
 *   - separators ", " (items) and ": " (key/value) — Python's defaults,
 *     i.e. WITH the spaces the old no-space canonicalizer dropped;
 *   - strings escaped exactly like ensure_ascii=True: '"' and '\\',
 *     \b \f \n \r \t, every other code point < 0x20 and 0x7f as \u00xx,
 *     and every code point >= 0x80 as \uXXXX (astral code points as UTF-16
 *     surrogate pairs), all hex lowercase like CPython;
 *   - floats rendered like CPython's repr: shortest round-trip digits,
 *     integral values keep ".0" ("1.0"), -0.0 stays "-0.0", exponents use
 *     a sign and at least two digits ("1e-07", "1e+16"), and the
 *     fixed-vs-exponential threshold matches CPython (exponential iff
 *     the decimal point sits at <= -4 or > 16). Non-finite floats render
 *     as NaN/Infinity/-Infinity, exactly what json.dumps emits with the
 *     default allow_nan=True.
 *
 * Known transport limitation (documented, not worked around): JSON
 * parsing erases the int-vs-float distinction, so a Python float with an
 * integral value (e.g. ts 1789286880.0) arrives in JS as the integer
 * 1789286880 and re-emits as "1789286880", while Python wrote
 * "1789286880.0". Likewise integers beyond 2**53 lose precision in JS.
 * The receipt schema keeps every integer field a true int and its only
 * float field (ts, epoch seconds rounded to millis) non-integral in
 * practice; cross-language tests pin this contract.
 */

import { createHmac, createHash, timingSafeEqual } from "node:crypto";

const V1_BODY_KEYS = ["seq", "ts", "tenant_id", "kid", "task_id", "agent_id",
  "tool", "args_sha256", "decision", "reason", "prev_hash"];

/** Compare two strings by Unicode code point, like Python's str ordering. */
function compareCodePoints(a, b) {
  const acp = Array.from(a), bcp = Array.from(b); // code-point arrays
  const n = Math.min(acp.length, bcp.length);
  for (let i = 0; i < n; i++) {
    const d = acp[i].codePointAt(0) - bcp[i].codePointAt(0);
    if (d !== 0) return d;
  }
  return acp.length - bcp.length;
}

/** Escape one string exactly like Python json.dumps(ensure_ascii=True). */
function pythonString(s) {
  let out = '"';
  for (const ch of s) { // for..of iterates code points (lone surrogates solo)
    const cp = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (cp === 0x08) out += "\\b";
    else if (cp === 0x09) out += "\\t";
    else if (cp === 0x0a) out += "\\n";
    else if (cp === 0x0c) out += "\\f";
    else if (cp === 0x0d) out += "\\r";
    else if (cp < 0x20 || cp === 0x7f) out += "\\u" + cp.toString(16).padStart(4, "0");
    else if (cp < 0x7f) out += ch; // printable ASCII (quote/backslash done above)
    else if (cp <= 0xffff) out += "\\u" + cp.toString(16).padStart(4, "0");
    else {
      // Astral code point -> UTF-16 surrogate pair, each \uXXXX lowercase.
      const v = cp - 0x10000;
      out += "\\u" + (0xd800 + (v >> 10)).toString(16).padStart(4, "0")
           + "\\u" + (0xdc00 + (v & 0x3ff)).toString(16).padStart(4, "0");
    }
  }
  return out + '"';
}

/** Render a finite float like CPython's repr (shortest round-trip). */
function pythonFloat(x) {
  if (Object.is(x, 0)) return "0.0";
  if (Object.is(x, -0)) return "-0.0";
  const neg = x < 0;
  const a = neg ? -x : x;
  // V8's String() already yields the unique shortest round-trip digits;
  // only the fixed-vs-exponential layout differs from CPython, so parse
  // the digits out and re-lay them out by CPython's rule.
  const m = /^(\d+?)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(String(a));
  let digits = m[1] + (m[2] || "");
  // decpt: value = 0.digits x 10^decpt, with digits[0] != '0'. Strip
  // leading zeros (adjusting decpt) then trailing zeros (decpt unchanged:
  // they were already counted in m[1].length).
  let decpt = m[1].length + (m[3] ? parseInt(m[3], 10) : 0);
  const stripped = digits.replace(/^0+/, "");
  decpt -= digits.length - stripped.length;
  digits = stripped.replace(/0+$/, "") || "0";
  let body;
  if (decpt <= -4 || decpt > 16) {
    // Exponential: d1[.d2...]e{+,-}XX (exponent: sign + >= 2 digits).
    const exp = decpt - 1;
    const mant = digits.length > 1 ? digits[0] + "." + digits.slice(1) : digits;
    const es = (exp < 0 ? "-" : "+") + String(Math.abs(exp)).padStart(2, "0");
    body = mant + "e" + es;
  } else if (decpt <= 0) {
    body = "0." + "0".repeat(-decpt) + digits;
  } else if (decpt >= digits.length) {
    body = digits + "0".repeat(decpt - digits.length);
    if (!body.includes(".")) body += ".0"; // integral float keeps ".0"
  } else {
    body = digits.slice(0, decpt) + "." + digits.slice(decpt);
  }
  if (!/[.eEnN]/.test(body)) body += ".0"; // e.g. "100" -> "100.0"
  return (neg ? "-" : "") + body;
}

/** Byte-identical to Python's json.dumps(value, sort_keys=True). Exported
 *  so tests and SDK minting helpers use the exact verification encoding. */
export function canonicalJson(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "string") return pythonString(value);
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) {
      if (Number.isNaN(value)) return "NaN";
      return value > 0 ? "Infinity" : "-Infinity";
    }
    // Integers (and unsafe integers, precision already lost at parse)
    // render as Python ints; non-integral numbers use float repr.
    // -0.0 is checked first: it is "an integer" to Number.isInteger but
    // Python renders it "-0.0".
    if (Object.is(value, -0)) return "-0.0";
    return Number.isInteger(value) ? String(value) : pythonFloat(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(", ") + "]";
  }
  if (t === "object") {
    return "{" + Object.keys(value).sort(compareCodePoints)
      .map(k => pythonString(k) + ": " + canonicalJson(value[k])).join(", ") + "}";
  }
  throw new TypeError(`canonicalJson: unsupported type ${t}`);
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
