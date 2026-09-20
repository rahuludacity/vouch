"""Vouch receipt service (:9001) — durable per-tenant receipt store.

Accepts already-signed receipts from gatekeepers (it never signs). Serves
queries, a live SSE stream, chain/signature verification, and per-tenant
monthly usage counters.

Endpoints (§4.2, §4.6):
    POST /v1/ingest                  service token
      201 {"tenant_id","seq","hash"} | 409 {"error":"duplicate_seq"}
      | 422 {"error":"chain_break","expected_prev_hash",...}
    GET  /v1/receipts?tenant_id=&task_id=&tool=&decision=&agent_id=
         &limit=&cursor=&order=      service token
    GET  /v1/receipts/<seq>?tenant_id=  service token
    GET  /v1/receipts/stream?tenant_id=&task_id=   SSE, service token
    GET  /v1/verify?tenant_id=       service token
    GET  /internal/usage/<tenant_id>?month=YYYY-MM  service token
    GET  /v1/health                  no auth (gatekeeper circuit-breaker)

Auth, Phase 1: one service-token bearer for every endpoint except /v1/health.
Tenant API keys (vouch_sk_*) arrive with the control plane in Phase 2.

Signature verification runs server-side against tenants.json (§4.7 moves
this to the control plane in Phase 2). Key material never leaves the server.

Run:  python3 -m services.receipts.app
Env:  RECEIPT_PORT        (default 9001)
      RECEIPT_DB          sqlite path (default <repo>/receipts.db)
      RECEIPT_SVC_TOKEN   bearer token (default "dev-token"; set in prod)
      TENANTS_PATH        tenant registry (default <repo>/tenants.json)
"""
import json
import os
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .store import ReceiptStore, ChainBreak, DuplicateSeq
from .keys import load_verification_keys

HERE = os.path.dirname(__file__)
PORT = int(os.environ.get("RECEIPT_PORT", "9001"))
DB_PATH = os.environ.get(
    "RECEIPT_DB", os.path.join(HERE, "..", "..", "receipts.db"))
SVC_TOKEN = os.environ.get("RECEIPT_SVC_TOKEN", "dev-token")
TENANTS_PATH = os.environ.get(
    "TENANTS_PATH", os.path.join(HERE, "..", "..", "tenants.json"))

REQUIRED_FIELDS = (
    "tenant_id", "seq", "ts", "kid", "task_id", "agent_id", "tool",
    "args_sha256", "decision", "prev_hash", "hash", "sig",
)


class Handler(BaseHTTPRequestHandler):
    store = None          # ReceiptStore, set in main()
    tenants_path = None
    svc_token = None
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
        return (self.headers.get("Authorization", "") ==
                f"Bearer {self.svc_token}")

    def _require_auth(self):
        if not self._authed():
            self._err(401, "unauthorized", "bad or missing bearer token")
            return False
        return True

    def _path(self):
        u = urlparse(self.path)
        return u.path, {k: v[0] for k, v in parse_qs(u.query).items()}

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
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
        if not self._require_auth():
            return
        if path == "/v1/receipts":
            return self._get_receipts(q)
        if path == "/v1/receipts/stream":
            return self._stream(q)
        if path.startswith("/v1/receipts/"):
            return self._get_receipt_one(path, q)
        if path == "/v1/verify":
            return self._verify(q)
        if path.startswith("/internal/usage/"):
            return self._usage(path, q)
        return self._err(404, "not_found")

    def _get_receipts(self, q):
        tenant_id = q.get("tenant_id")
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

    def _get_receipt_one(self, path, q):
        tenant_id = q.get("tenant_id")
        seq = path[len("/v1/receipts/"):]
        if not tenant_id or not seq.isdigit():
            return self._err(400, "bad_request",
                             "tenant_id and numeric seq are required")
        row = self.store.get_receipt(tenant_id, int(seq))
        if row is None:
            return self._err(404, "not_found")
        return self._send(200, row)

    def _verify(self, q):
        tenant_id = q.get("tenant_id")
        if not tenant_id:
            return self._err(400, "bad_request", "tenant_id is required")
        try:
            keys = load_verification_keys(self.tenants_path, tenant_id)
        except (KeyError, FileNotFoundError, ValueError) as e:
            return self._err(404, "unknown_tenant", str(e))
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
    def _stream(self, q):
        tenant_id = q.get("tenant_id")
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
    if SVC_TOKEN == "dev-token":
        print("WARNING: RECEIPT_SVC_TOKEN not set, using default 'dev-token'. "
              "Set it in production.")
    Handler.store = ReceiptStore(DB_PATH)
    Handler.tenants_path = TENANTS_PATH
    Handler.svc_token = SVC_TOKEN
    print(f"vouch receipt service listening on :{PORT}")
    print(f"db:      {DB_PATH}")
    print(f"tenants: {TENANTS_PATH}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
