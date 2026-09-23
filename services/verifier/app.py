"""Vouch agent verifier (:9005) — the demand-side gateway.

A site submits an agent's credential plus the action being attempted; the
verifier checks signatures, delegation-chain integrity, authorization
scope, replay, and rate limits, then returns an allow/deny decision.

Every decision — allow or deny — emits a signed, hash-chained receipt
through the existing receipt pipeline
(gatekeeper.ingest.ReceiptEmitter: receipt service when reachable, local
append-only file otherwise). The local file IS the prototype's
append-only transparency log; it verifies with
`python3 -m gatekeeper.verify`.

Lane model (the site's gateway policy; the verifier reports which lane
the request belongs to):
  verified-agent lane  valid credential -> fast passage, per-principal
                       daily rate limit, receipt emitted.
  human lane           never reaches the verifier: the site serves normal
                       human traffic unchanged.
  unverified lane      missing/invalid credential -> deny; the site routes
                       these to its status-quo challenge path.

Endpoints:
    POST /v1/verify   {tenant_id, credential, action, nonce, ts,
                       agent_signature}
                      -> 200 {decision, reason, lane, receipt_seq,
                              receipt_hash}
                         400 {error} on malformed input
    GET  /v1/health   no auth -> {ok: true, ...}

Env:
    VERIFIER_PORT               default 9005
    VOUCH_BIND                  default 127.0.0.1
    VERIFIER_TENANTS_PATH       default <repo>/tenants.json
    VERIFIER_RECEIPTS_PATH      default <repo>/verifier-receipts.jsonl
    VERIFIER_TRUSTED_ISSUERS    comma-separated Ed25519 pubkey hex
                                (the principals this site trusts)
    VERIFIER_PRINCIPAL_DAILY_LIMIT  default 1000
    RECEIPT_SVC_URL / RECEIPT_SVC_TOKEN  optional receipt-service fan-in
                                (empty string = local file only)

Run: python3 -m services.verifier.app
"""
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO)

from gatekeeper.ingest import ReceiptEmitter  # noqa: E402
from gatekeeper.receipts import ReceiptLog  # noqa: E402
from gatekeeper.tenants import TenantRegistry  # noqa: E402
from services.verifier import credentials  # noqa: E402
from services.verifier import rfc9421  # noqa: E402

BIND = os.environ.get("VOUCH_BIND", "127.0.0.1")
PORT = int(os.environ.get("VERIFIER_PORT", "9005"))
TENANTS_PATH = os.environ.get(
    "VERIFIER_TENANTS_PATH",
    os.path.join(REPO, "tenants.json"))
RECEIPTS_PATH = os.environ.get(
    "VERIFIER_RECEIPTS_PATH",
    os.path.join(REPO, "verifier-receipts.jsonl"))
TRUSTED_ISSUERS = [s.strip() for s in
                   os.environ.get("VERIFIER_TRUSTED_ISSUERS", "").split(",")
                   if s.strip()]
PRINCIPAL_DAILY_LIMIT = int(
    os.environ.get("VERIFIER_PRINCIPAL_DAILY_LIMIT", "1000"))
# Phase 11: enrollment-anchored verification v2. When VOUCH_MANIFEST_PATH
# is set, decide() verifies against the signed trust-root manifest (PRD
# check order, tier policy hook) instead of the v1 trusted-issuers list.
MANIFEST_PATH = os.environ.get("VOUCH_MANIFEST_PATH", "")
OPERATOR_PUBKEYS = [s.strip() for s in
                    os.environ.get("VOUCH_OPERATOR_PUBKEYS", "").split(",")
                    if s.strip()]
try:
    MIN_TIERS = json.loads(os.environ.get("VOUCH_MIN_TIERS", "{}"))
except json.JSONDecodeError:
    raise ValueError("VOUCH_MIN_TIERS is not valid JSON")
if not isinstance(MIN_TIERS, dict):
    raise ValueError("VOUCH_MIN_TIERS must be a JSON object "
                     "{action_pattern: minimum_tier}")
MAX_BODY = 1024 * 1024


class VerifierState:
    """In-memory replay + rate-limit state (prototype; not durable)."""

    # Hard cap on the nonce table. Nonces are reserved *before* credential
    # verification, so an attacker can grow the table with garbage requests
    # (only a 10-minute time prune stood in the way). 100k entries is
    # single-digit MB; oldest entries are evicted first. Evicted nonces fall
    # back on the request-timestamp window for replay safety.
    MAX_NONCES = 100_000

    def __init__(self):
        self._lock = threading.Lock()
        self._nonces = {}          # nonce -> expiry ts
        self._agent_usage = {}     # (agent_pubkey, action_type, day) -> count
        self._principal_usage = {}  # (principal_pubkey, day) -> count
        # Phase 11: spending ceilings, keyed (credential_id, action_type,
        # day) -> cents used. Only actions with amount_cents add to it.
        self._spending = {}

    def _prune(self, now):
        for n, exp in list(self._nonces.items()):
            if exp <= now:
                del self._nonces[n]

    def nonce_seen(self, nonce):
        """Membership test for the v2 replay check (read-only)."""
        with self._lock:
            return nonce in self._nonces

    def check_and_reserve(self, nonce, now):
        """Replay check. Returns True if the nonce is fresh (and reserves it)."""
        with self._lock:
            self._prune(now)
            if nonce in self._nonces:
                return False
            while len(self._nonces) >= self.MAX_NONCES:
                # dicts are insertion-ordered and every entry is stamped with
                # a monotonic expiry, so the front of the dict is the oldest.
                self._nonces.pop(next(iter(self._nonces)))
            self._nonces[nonce] = now + 2 * credentials.CLOCK_SKEW
            return True

    def agent_used(self, agent_pubkey, action_type, day):
        with self._lock:
            return self._agent_usage.get((agent_pubkey, action_type, day), 0)

    def principal_used(self, principal_pubkey, day):
        with self._lock:
            return self._principal_usage.get((principal_pubkey, day), 0)

    def record_allow(self, agent_pubkey, principal_pubkey, action_type, day):
        with self._lock:
            k = (agent_pubkey, action_type, day)
            self._agent_usage[k] = self._agent_usage.get(k, 0) + 1
            k2 = (principal_pubkey, day)
            self._principal_usage[k2] = self._principal_usage.get(k2, 0) + 1

    def spending_used(self, credential_id, action_type, day):
        """Cents already spent under the spending ceiling (read-only)."""
        with self._lock:
            return self._spending.get((credential_id, action_type, day), 0)

    def check_and_add_spending(self, credential_id, action_type, day,
                               amount_cents, ceiling_cents):
        """Atomic spend check+increment under the state lock.

        Returns (ok, used). ok False means used + amount_cents would exceed
        the ceiling — nothing was added (no TOCTOU between the verifier's
        read and this write). Stale day buckets are pruned so the table
        stays bounded to the active day.
        """
        with self._lock:
            for k in [k for k in self._spending if k[2] != day]:
                del self._spending[k]
            k = (credential_id, action_type, day)
            used = self._spending.get(k, 0)
            if (ceiling_cents is not None and
                    used + amount_cents > ceiling_cents):
                return False, used
            self._spending[k] = used + amount_cents
            return True, used + amount_cents


STATE = VerifierState()
EMITTER = None  # set in main()


def decide(req):
    """Core decision logic (pure apart from STATE). Returns
    (decision, reason, lane, cred_or_None, evidence_or_None).

    evidence is the v2 enrollment-evidence dict (receipt vouch_enrollment
    block); None on the v1 path.
    """
    now = time.time()
    tenant_id = req.get("tenant_id", "default")
    cred = req.get("credential") or {}
    action = req.get("action") or {}
    atype = action.get("type", "")

    if MANIFEST_PATH:
        return _decide_v2(req, now, tenant_id, cred, action, atype)

    # Replay is checked before anything else: a replayed request is denied
    # even if it would otherwise verify (it also must not consume quota).
    nonce = req.get("nonce")
    if not nonce or not STATE.check_and_reserve(nonce, now):
        return ("deny", "replay: nonce already seen", "unverified",
                cred if isinstance(cred, dict) else None, None)

    ok, reasons = credentials.verify_action_request(
        req, TRUSTED_ISSUERS, now=now, usage=_UsageView(STATE))
    if not ok:
        return ("deny", "; ".join(reasons), "unverified",
                cred if isinstance(cred, dict) else None, None)

    # Per-principal daily rate limit (the verified-agent lane's throttle).
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    principal_pubkey = cred["principal"]["pubkey"]
    used = STATE.principal_used(principal_pubkey, day)
    if used >= PRINCIPAL_DAILY_LIMIT:
        return ("deny",
                f"principal rate limit exceeded: {used}/{PRINCIPAL_DAILY_LIMIT}/day",
                "unverified", cred, None)

    STATE.record_allow(cred["agent_pubkey"], principal_pubkey, atype, day)
    return ("allow", "credential valid; action within scope",
            "verified-agent", cred, None)


def _decide_v2(req, now, tenant_id, cred, action, atype):
    """v2 path: enrollment-anchored verification (PRD check order).

    Returns the same 5-tuple as decide(); evidence is the 7-field
    enrollment block (or None on deny, where the receipt omits it).
    """
    try:
        # Manifest is loaded fresh per request — no stale-cache TOCTOU:
        # a revoked key/credential takes effect on the next rebuild.
        with open(MANIFEST_PATH, encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception:
        # Fail closed: no trust root -> deny (no details leak).
        return ("deny", "trust root stale: manifest file unreadable",
                "unverified", cred if isinstance(cred, dict) else None,
                None)

    hook = credentials.default_tier_policy(MIN_TIERS)
    ok, reasons, evidence = credentials.verify_action_request_v2(
        req, manifest=manifest, operator_pubkeys=OPERATOR_PUBKEYS,
        policy_hook=hook, now=now, nonces=_NoncesView(STATE),
        usage=_UsageView(STATE), spending=_SpendingView(STATE))
    if not ok:
        return ("deny", "; ".join(reasons), "unverified",
                cred if isinstance(cred, dict) else None, None)

    # v2 only reads the nonce store; reserve it now that the request is
    # good. A racing duplicate that slips the read is denied here.
    nonce = req.get("nonce")
    if not nonce or not STATE.check_and_reserve(nonce, now):
        return ("deny", "replayed request", "unverified",
                cred if isinstance(cred, dict) else None, None)

    # Per-principal daily rate limit (the verified-agent lane's throttle).
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    principal_pubkey = cred["principal"]["pubkey"]
    used = STATE.principal_used(principal_pubkey, day)
    if used >= PRINCIPAL_DAILY_LIMIT:
        return ("deny",
                f"principal rate limit exceeded: {used}/{PRINCIPAL_DAILY_LIMIT}/day",
                "unverified", cred, None)

    # Spending ceiling: atomic check+increment (no TOCTOU). The verifier
    # already read-checked the ceiling; this is the authoritative gate.
    # H-2: never treat an absent ceiling as unlimited when the delegation
    # chain implies one — fail closed. (v2 already denies this above; this
    # is the gate's own invariant.)
    amount = action.get("amount_cents") or 0
    lim = (credentials._norm_scope(cred.get("scope"))
           .get("limits", {}).get(atype, {}))
    ok_cl, why_cl = credentials.check_chain_limits_present(cred, atype)
    if not ok_cl:
        return ("deny", "; ".join(why_cl), "unverified", cred, None)
    ceiling = lim.get("max_spend_per_day")
    if amount and ceiling is not None:
        ok_spend, used_cents = STATE.check_and_add_spending(
            cred["credential_id"], atype, day, amount, ceiling)
        if not ok_spend:
            return ("deny",
                    f"spending ceiling exceeded: "
                    f"{used_cents + amount}/{ceiling} {atype}/day (cents)",
                    "unverified", cred, None)

    STATE.record_allow(cred["agent_pubkey"], principal_pubkey, atype, day)
    return ("allow", "credential valid; action within scope",
            "verified-agent", cred, evidence)


class _UsageView:
    """Read-only adapter so credentials.py can consult STATE's counters."""

    def __init__(self, state):
        self._state = state

    def get(self, key, default=0):
        agent_pubkey, atype, day = key
        return self._state.agent_used(agent_pubkey, atype, day)


class _NoncesView:
    """Read-only membership view of STATE's reserved nonces (v2 replay)."""

    def __init__(self, state):
        self._state = state

    def __contains__(self, nonce):
        return self._state.nonce_seen(nonce)


class _SpendingView:
    """Read-only adapter for STATE's spending counters (v2 ceilings)."""

    def __init__(self, state):
        self._state = state

    def get(self, key, default=0):
        credential_id, atype, day = key
        return self._state.spending_used(credential_id, atype, day)


class Handler(BaseHTTPRequestHandler):
    server_version = "VouchVerifier/1.0"

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        self._send_bytes(code, json.dumps(obj).encode("utf-8"),
                         "application/json")

    def _send_bytes(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/v1/health":
            self._send(200, {"ok": True, "service": "verifier",
                             "trusted_issuers": len(TRUSTED_ISSUERS),
                             "principal_daily_limit": PRINCIPAL_DAILY_LIMIT})
        elif self.path.split("?", 1)[0] == "/.well-known/vouch-keys":
            self._serve_key_directory()
        else:
            self._send(404, {"error": "not_found"})

    def _serve_key_directory(self):
        """GET /.well-known/vouch-keys — RFC 9421 key directory (JWKS).

        The manifest JSON path comes from $VOUCH_MANIFEST_PATH (read per
        request so the directory tracks manifest rebuilds). Unset or
        unreadable -> 404 {"error":"no_manifest"}.
        """
        try:
            manifest_path = os.environ.get("VOUCH_MANIFEST_PATH", "")
            if not manifest_path:
                raise ValueError("VOUCH_MANIFEST_PATH unset")
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)
            directory = rfc9421.build_key_directory(manifest)
        except Exception:
            # Fail closed: no directory without a readable manifest.
            # (No manifest details leak into the response.)
            self._send(404, {"error": "no_manifest"})
            return
        self._send_bytes(200, json.dumps(directory).encode("utf-8"),
                         "application/http-message-signatures-directory+json")

    def do_POST(self):
        if self.path != "/v1/verify":
            self._send(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._send(400, {"error": "bad_request",
                             "message": "missing or oversize body"})
            return
        try:
            req = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._send(400, {"error": "bad_request",
                             "message": "body is not valid JSON"})
            return
        if not isinstance(req, dict):
            self._send(400, {"error": "bad_request",
                             "message": "body must be a JSON object"})
            return

        decision, reason, lane, cred, evidence = decide(req)

        # Every decision emits a signed, hash-chained receipt — this is the
        # demand-side audit trail: proof of what was checked and decided.
        agent_id = (cred or {}).get("agent_id", "unknown")
        task_id = (cred or {}).get("credential_id", "no-credential")
        receipt_args = {"action": req.get("action"),
                        "credential_id": task_id,
                        "lane": lane}
        if evidence:
            # Phase 11: enrollment evidence rides in the receipt args block
            # (v2 path only; the v1 path is unchanged).
            receipt_args["vouch_enrollment"] = evidence
        receipt = EMITTER.emit(
            tenant_id=req.get("tenant_id", "default"),
            task_id=task_id,
            agent_id=agent_id,
            tool="agent.verify",
            args=receipt_args,
            decision=decision,
            reason=reason,
        )
        self._send(200, {
            "decision": decision,
            "reason": reason,
            "lane": lane,
            "receipt_seq": receipt.get("seq"),
            "receipt_hash": receipt.get("hash"),
        })


def main():
    global EMITTER
    registry = TenantRegistry(TENANTS_PATH)
    log = ReceiptLog(RECEIPTS_PATH, registry)
    EMITTER = ReceiptEmitter(registry, log)
    # Fail fast if the tenant registry is unusable (matches gatekeeper
    # behavior of resolving keys at startup): touch a signing key path.
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"verifier listening on {BIND}:{PORT} "
          f"(trusted issuers: {len(TRUSTED_ISSUERS)})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
