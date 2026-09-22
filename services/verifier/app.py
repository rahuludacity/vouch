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

    def _prune(self, now):
        for n, exp in list(self._nonces.items()):
            if exp <= now:
                del self._nonces[n]

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


STATE = VerifierState()
EMITTER = None  # set in main()


def decide(req):
    """Core decision logic (pure apart from STATE). Returns
    (decision, reason, lane, cred_or_None)."""
    now = time.time()
    tenant_id = req.get("tenant_id", "default")
    cred = req.get("credential") or {}
    action = req.get("action") or {}
    atype = action.get("type", "")

    # Replay is checked before anything else: a replayed request is denied
    # even if it would otherwise verify (it also must not consume quota).
    nonce = req.get("nonce")
    if not nonce or not STATE.check_and_reserve(nonce, now):
        return ("deny", "replay: nonce already seen", "unverified",
                cred if isinstance(cred, dict) else None)

    ok, reasons = credentials.verify_action_request(
        req, TRUSTED_ISSUERS, now=now, usage=_UsageView(STATE))
    if not ok:
        return ("deny", "; ".join(reasons), "unverified",
                cred if isinstance(cred, dict) else None)

    # Per-principal daily rate limit (the verified-agent lane's throttle).
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    principal_pubkey = cred["principal"]["pubkey"]
    used = STATE.principal_used(principal_pubkey, day)
    if used >= PRINCIPAL_DAILY_LIMIT:
        return ("deny",
                f"principal rate limit exceeded: {used}/{PRINCIPAL_DAILY_LIMIT}/day",
                "unverified", cred)

    STATE.record_allow(cred["agent_pubkey"], principal_pubkey, atype, day)
    return ("allow", "credential valid; action within scope",
            "verified-agent", cred)


class _UsageView:
    """Read-only adapter so credentials.py can consult STATE's counters."""

    def __init__(self, state):
        self._state = state

    def get(self, key, default=0):
        agent_pubkey, atype, day = key
        return self._state.agent_used(agent_pubkey, atype, day)


class Handler(BaseHTTPRequestHandler):
    server_version = "VouchVerifier/1.0"

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/v1/health":
            self._send(200, {"ok": True, "service": "verifier",
                             "trusted_issuers": len(TRUSTED_ISSUERS),
                             "principal_daily_limit": PRINCIPAL_DAILY_LIMIT})
        else:
            self._send(404, {"error": "not_found"})

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

        decision, reason, lane, cred = decide(req)

        # Every decision emits a signed, hash-chained receipt — this is the
        # demand-side audit trail: proof of what was checked and decided.
        agent_id = (cred or {}).get("agent_id", "unknown")
        task_id = (cred or {}).get("credential_id", "no-credential")
        receipt = EMITTER.emit(
            tenant_id=req.get("tenant_id", "default"),
            task_id=task_id,
            agent_id=agent_id,
            tool="agent.verify",
            args={"action": req.get("action"),
                  "credential_id": task_id,
                  "lane": lane},
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
