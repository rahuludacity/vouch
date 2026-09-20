"""Vouch receipt service (:9001) — durable per-tenant receipt store.

Accepts already-signed receipts from gatekeepers (it never signs). Serves
queries, a live SSE stream, chain/signature verification, and per-tenant
monthly usage counters.

Endpoints (§4.2, §4.6):
    POST /v1/ingest                  service token
      201 {"tenant_id","seq","hash"} | 409 {"error":"duplicate_seq"}
      | 422 {"error":"chain_break","expected_prev_hash",...}
    GET  /v1/receipts?task_id=&tool=&decision=&agent_id=&limit=&cursor=&order=
         service token (tenant_id required) or tenant API key (scoped to its
         tenant; ?tenant_id= optional, must match)
    GET  /v1/receipts/<seq>          service token or tenant API key (same scoping)
    GET  /v1/receipts/stream?task_id=   SSE, service token or tenant API key
    GET  /v1/verify                  service token or tenant API key (§4.6:
                                     "public-with-key"; keys stay server-side)
    GET  /internal/usage/<tenant_id>?month=YYYY-MM  service token (CP fan-in)
    GET  /v1/health                  no auth (gatekeeper circuit-breaker)

Tenant API keys (vouch_sk_*) are validated against the control plane's
GET /v1/tenants/me (introspection, 60s cache) — no key material here.

Signature verification runs server-side against tenants.json (§4.7 moves
this to the control plane in Phase 2). Key material never leaves the server.

Run:  python3 -m services.receipts.app
Env:  RECEIPT_PORT        (default 9001)
      RECEIPT_DB          sqlite path (default <repo>/receipts.db)
      RECEIPT_SVC_TOKEN   bearer token — REQUIRED in production: the service
                          refuses to boot with the dev default unless
                          VOUCH_ALLOW_DEV_DEFAULTS=1 (see M-5 note in main()).
      TENANTS_PATH        tenant registry (default <repo>/tenants.json)
      CONTROLPLANE_URL    control plane base (default ""; when set, verify
                          fetches tenant keys from the control plane per §4.7,
                          with tenants.json as fallback)
      CONTROLPLANE_SVC_TOKEN  bearer the receipt service presents to the
                          control plane (default "")
"""
import json
import os
import sys
import hashlib
import hmac
import queue
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .store import ReceiptStore, ChainBreak, DuplicateSeq
from . import keys as keys_module
from .keys import load_verification_keys, KeyAuthorityUnavailable

HERE = os.path.dirname(__file__)
BIND = os.environ.get("VOUCH_BIND", "127.0.0.1")
PORT = int(os.environ.get("RECEIPT_PORT", "9001"))
DB_PATH = os.environ.get(
    "RECEIPT_DB", os.path.join(HERE, "..", "..", "receipts.db"))
SVC_TOKEN = os.environ.get("RECEIPT_SVC_TOKEN", "dev-token")
TENANTS_PATH = os.environ.get(
    "TENANTS_PATH", os.path.join(HERE, "..", "..", "tenants.json"))
# Phase 2: when set, tenant keys come from the control plane (§4.7) with the
# tenants.json file as fallback. The service presents CP_SVC_TOKEN there.
CONTROLPLANE_URL = os.environ.get("CONTROLPLANE_URL", "").rstrip("/")
CP_SVC_TOKEN = os.environ.get("CONTROLPLANE_SVC_TOKEN", "")

REQUIRED_FIELDS = (
    "tenant_id", "seq", "ts", "kid", "task_id", "agent_id", "tool",
    "args_sha256", "decision", "prev_hash", "hash", "sig",
)


class Handler(BaseHTTPRequestHandler):
    store = None          # ReceiptStore, set in main()
    tenants_path = None
    svc_token = None
    controlplane_url = None
    cp_token = None
    # tenant API-key introspection cache: sha256(key) -> (tenant_id, expires)
    _tenant_key_cache = {}
    _tenant_key_lock = threading.Lock()
    _TENANT_KEY_TTL = 60.0
    subscribers = {}      # tenant_id -> [queue.Queue, ...]
    subs_lock = threading.Lock()

    server_version = "VouchReceipts/1.0"

    # ------------------------------------------------------------ helpers
    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _err(self, code, error, message=""):
        self._send(code, {"error": error, "message": message or error})

    def _authed(self):
        if self.svc_token in (None, ""):
            return True  # no token configured: open (local dev only)
        # L-1: constant-time comparison.
        return hmac.compare_digest(
            self.headers.get("Authorization", ""),
            f"Bearer {self.svc_token}")

    def _require_auth(self):
        if not self._authed():
            self._err(401, "unauthorized", "bad or missing bearer token")
            return False
        return True

    # --------------------------------------- tenant API-key auth (§4.6)
    def _auth_context(self):
        """Who is calling: ("service", None) | ("tenant", tenant_id) | None.

        Service tokens keep full access (gatekeeper ingest, ops). Tenant
        `vouch_sk_*` keys are validated against the control plane's
        GET /v1/tenants/me (token introspection — no new endpoint needed),
        cached 60s; failures fail closed and are never cached.
        """
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:]
        # L-1: constant-time comparison for the service bearer.
        if self.svc_token and hmac.compare_digest(token, self.svc_token):
            return ("service", None)
        if token.startswith("vouch_sk_") and self.controlplane_url:
            tid = self._introspect_tenant_key(token)
            if tid:
                return ("tenant", tid)
        return None

    @classmethod
    def _introspect_tenant_key(cls, token):
        """tenant_id for a vouch_sk_* key, or None. Never raises."""
        digest = hashlib.sha256(token.encode()).hexdigest()
        now = time.time()
        with cls._tenant_key_lock:
            hit = cls._tenant_key_cache.get(digest)
            if hit and hit[1] > now:
                return hit[0]
        url = cls.controlplane_url.rstrip("/") + "/v1/tenants/me"
        req = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    return None
                tid = json.loads(resp.read().decode("utf-8")).get("tenant_id")
        except Exception:  # noqa: BLE001 - fail closed, don't cache
            return None
        if not tid:
            return None
        with cls._tenant_key_lock:
            cls._tenant_key_cache[digest] = (tid, now + cls._TENANT_KEY_TTL)
        return tid

    def _scoped_tenant(self, q, auth):
        """Effective tenant_id for a tenant-API read.

        Service callers pass ?tenant_id= (required, as before). Tenant-key
        callers are scoped to their own tenant: an explicit ?tenant_id=
        must match it (§4.6: the key IS the tenant).
        """
        kind, tid = auth
        if kind == "service":
            return q.get("tenant_id")
        requested = q.get("tenant_id")
        if requested and requested != tid:
            return "FORBIDDEN"
        return tid

    def _path(self):
        u = urlparse(self.path)
        return u.path, {k: v[0] for k, v in parse_qs(u.query).items()}

    def _read_json(self):
        # M-2: 1MB request cap — reject before allocating.
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            return "INVALID"
        if length > 1_000_000:
            return "TOO_LARGE"
        if not length:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            return "INVALID"

    def log_message(self, *a):  # quieter logs
        pass

    # ---------------------------------------------------------------- GET
    def do_GET(self):
        path, q = self._path()
        if path == "/v1/health":
            return self._send(200, {"ok": True})
        if path.startswith("/internal/usage/"):
            # control-plane usage fan-in (§4.8): service token only.
            if not self._require_auth():
                return
            return self._usage(path, q)
        auth = self._auth_context()
        if auth is None:
            return self._err(401, "unauthorized",
                             "service token or vouch_sk_* API key required")
        if path == "/v1/receipts":
            return self._get_receipts(q, auth)
        if path == "/v1/receipts/stream":
            return self._stream(q, auth)
        if path.startswith("/v1/receipts/"):
            return self._get_receipt_one(path, q, auth)
        if path == "/v1/verify":
            return self._verify(q, auth)
        return self._err(404, "not_found")

    def _get_receipts(self, q, auth):
        tenant_id = self._scoped_tenant(q, auth)
        if tenant_id == "FORBIDDEN":
            return self._err(403, "forbidden",
                             "tenant_id does not match the API key")
        if not tenant_id:
            return self._err(400, "bad_request", "tenant_id is required")
        try:
            items, next_cursor = self.store.get_receipts(
                tenant_id,
                task_id=q.get("task_id"), tool=q.get("tool"),
                decision=q.get("decision"), agent_id=q.get("agent_id"),
                limit=q.get("limit", 50), cursor=q.get("cursor"),
                order=q.get("order", "desc"),
            )
        except (ValueError, TypeError) as e:
            return self._err(400, "bad_request", str(e))
        return self._send(200, {"items": items, "next_cursor": next_cursor})

    def _get_receipt_one(self, path, q, auth):
        tenant_id = self._scoped_tenant(q, auth)
        seq = path[len("/v1/receipts/"):]
        if tenant_id == "FORBIDDEN":
            return self._err(403, "forbidden",
                             "tenant_id does not match the API key")
        if not tenant_id or not seq.isdigit():
            return self._err(400, "bad_request",
                             "tenant_id and numeric seq are required")
        row = self.store.get_receipt(tenant_id, int(seq))
        if row is None:
            return self._err(404, "not_found")
        return self._send(200, row)

    def _verify(self, q, auth):
        tenant_id = self._scoped_tenant(q, auth)
        if tenant_id == "FORBIDDEN":
            return self._err(403, "forbidden",
                             "tenant_id does not match the API key")
        if not tenant_id:
            return self._err(400, "bad_request", "tenant_id is required")
        try:
            keys = load_verification_keys(self.tenants_path, tenant_id,
                                          self.controlplane_url, self.cp_token)
        except KeyAuthorityUnavailable as e:
            return self._err(503, "key_authority_unavailable", str(e))
        except (KeyError, FileNotFoundError, ValueError) as e:
            return self._err(404, "unknown_tenant", str(e))
        ok, failures = self.store.verify_tenant(tenant_id, keys)
        if (not ok and self.controlplane_url and any(
                f.get("error", "").startswith("unknown key id")
                for f in failures)):
            # Rotation race: the 5-minute key cache predates a key rotation.
            # Refresh once and re-verify instead of failing the chain.
            keys_module.invalidate_cache(tenant_id)
            try:
                keys = load_verification_keys(self.tenants_path, tenant_id,
                                              self.controlplane_url,
                                              self.cp_token)
            except (KeyAuthorityUnavailable, KeyError, FileNotFoundError,
                    ValueError):
                pass  # keep the original (more informative) failures
            else:
                ok, failures = self.store.verify_tenant(tenant_id, keys)
        return self._send(200, {
            "tenant_id": tenant_id,
            "receipts": self.store.count(tenant_id),
            "chain_ok": ok,
            "failures": failures,
        })

    def _usage(self, path, q):
        tenant_id = path[len("/internal/usage/"):]
        if not tenant_id:
            return self._err(400, "bad_request", "tenant_id is required")
        return self._send(200, self.store.get_usage(tenant_id, q.get("month")))

    # ---------------------------------------------------------------- SSE
    def _stream(self, q, auth):
        tenant_id = self._scoped_tenant(q, auth)
        if tenant_id == "FORBIDDEN":
            return self._err(403, "forbidden",
                             "tenant_id does not match the API key")
        if not tenant_id:
            return self._err(400, "bad_request", "tenant_id is required")
        task_id = q.get("task_id")
        inbox = queue.Queue()
        with self.subs_lock:
            self.subscribers.setdefault(tenant_id, []).append(inbox)
        # HTTP/1.1 + chunked: lets clients read event-by-event instead of
        # waiting for connection close (HTTP/1.0 close-delimited SSE would
        # stall small reads). Per-connection: this handler instance dies
        # with the connection, and we force close when the stream ends.
        self.protocol_version = "HTTP/1.1"
        self.close_connection = True
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            last_sent = 0
            # backlog first (oldest -> newest), then live
            items, _ = self.store.get_receipts(
                tenant_id, task_id=task_id, limit=200, order="asc")
            for r in items:
                if self._send_event(r):
                    return
                last_sent = r["seq"]
            while True:
                try:
                    r = inbox.get(timeout=15)
                except queue.Empty:
                    if self._send_raw(b": ping\n\n"):
                        return
                    continue
                if r["seq"] <= last_sent:
                    continue  # already sent in backlog
                if task_id and r.get("task_id") != task_id:
                    continue
                last_sent = r["seq"]
                if self._send_event(r):
                    return
        finally:
            with self.subs_lock:
                subs = self.subscribers.get(tenant_id, [])
                if inbox in subs:
                    subs.remove(inbox)

    def _send_raw(self, data):
        """Write one chunk. Returns True if the client went away."""
        try:
            self.wfile.write(b"%X\r\n" % len(data))
            self.wfile.write(data)
            self.wfile.write(b"\r\n")
            self.wfile.flush()
            return False
        except (BrokenPipeError, ConnectionResetError):
            return True

    def _send_event(self, receipt):
        """Write one SSE event as a chunk. Returns True if client went away."""
        return self._send_raw(
            f"event: receipt\ndata: {json.dumps(receipt)}\n\n".encode("utf-8"))

    @classmethod
    def _publish(cls, receipt):
        with cls.subs_lock:
            inboxes = list(cls.subscribers.get(receipt["tenant_id"], ()))
        for inbox in inboxes:
            try:
                inbox.put_nowait(receipt)
            except queue.Full:
                pass

    # --------------------------------------------------------------- POST
    def do_POST(self):
        path, _ = self._path()
        if path != "/v1/ingest":
            return self._err(404, "not_found")
        if not self._require_auth():
            return
        body = self._read_json()
        if body == "TOO_LARGE":
            return self._err(413, "payload_too_large",
                             "request body exceeds 1MB")
        if body is None or body == "INVALID" or not isinstance(body, dict):
            return self._err(400, "invalid_receipt", "body must be a JSON object")
        missing = [f for f in REQUIRED_FIELDS if f not in body]
        if missing:
            return self._err(400, "invalid_receipt",
                             f"missing fields: {', '.join(missing)}")
        if not isinstance(body["seq"], int) or body["seq"] < 1:
            return self._err(400, "invalid_receipt", "seq must be a positive int")
        if body["decision"] not in ("allow", "deny"):
            return self._err(400, "invalid_receipt",
                             "decision must be 'allow' or 'deny'")
        try:
            stored = self.store.ingest(body)
        except DuplicateSeq:
            return self._err(409, "duplicate_seq",
                             f"seq {body['seq']} already stored for tenant "
                             f"'{body['tenant_id']}'")
        except ChainBreak as e:
            return self._send(422, {
                "error": "chain_break",
                "message": "receipt does not continue the tenant tip",
                "expected_seq": e.expected_seq,
                "expected_prev_hash": e.expected_prev_hash,
            })
        self._publish(stored)
        return self._send(201, {"tenant_id": stored["tenant_id"],
                               "seq": stored["seq"], "hash": stored["hash"]})


def main():
    # M-5: refuse to boot with the dev default outside the local-dev
    # escape hatch. Receipt ingestion accepts signed receipts on the
    # strength of this Bearer <redacted> — "dev-token" in production would
    # let anyone forge the chain.
    if SVC_TOKEN == "dev-token" and os.environ.get("VOUCH_ALLOW_DEV_DEFAULTS") != "1":
        print("FATAL: RECEIPT_SVC_TOKEN is the dev default 'dev-token'. "
              "Set a real secret, or export VOUCH_ALLOW_DEV_DEFAULTS=1 for "
              "local demos only.", file=sys.stderr)
        sys.exit(2)
    if SVC_TOKEN == "dev-token":
        print("WARNING: RECEIPT_SVC_TOKEN not set, using default 'dev-token'. "
              "Set it in production.")
    Handler.store = ReceiptStore(DB_PATH)
    Handler.tenants_path = TENANTS_PATH
    Handler.svc_token = SVC_TOKEN
    Handler.controlplane_url = CONTROLPLANE_URL
    Handler.cp_token = CP_SVC_TOKEN
    print(f"vouch receipt service listening on {BIND}:{PORT}")
    print(f"db:      {DB_PATH}")
    print(f"tenants: {TENANTS_PATH}")
    if CONTROLPLANE_URL:
        print(f"key authority: control plane at {CONTROLPLANE_URL} (file fallback)")
    else:
        print("key authority: tenants.json file")
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
