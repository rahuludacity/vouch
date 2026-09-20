"""Vouch gatekeeper v1: MCP Streamable HTTP proxy with task-scoped policy.

Speaks real MCP Streamable HTTP (spec.modelcontextprotocol.io):
  - POST /mcp carries JSON-RPC messages. The client sends
    `Accept: application/json, text/event-stream`; the gatekeeper answers
    with an SSE stream (`Content-Type: text/event-stream`, `event: message`
    frames) when the client accepts it, otherwise a single JSON object.
  - `Mcp-Session-Id` is relayed between client and upstream: the upstream's
    session id (from `initialize`) is passed straight back to the client,
    and the client's session header is forwarded upstream on every call.
  - GET /mcp opens a server-push SSE stream (relayed to upstream).
  - DELETE /mcp terminates a session (relayed to upstream).
  - Notifications and client responses (no reply expected) get 202 + empty
    body, per spec.

Policy enforcement is unchanged from v0: only `tools/call` is gated,
checked against policy.yaml for the X-Task-Id scope. Every allow AND
deny emits a receipt signed with the calling tenant's HMAC key.

Tenant identification, in order:
  1. X-Tenant-Id request header (unknown tenant -> 403)
  2. tenant bound to this request's Mcp-Session-Id
  3. the auto-created "default" tenant

Run:  python3 -m gatekeeper.proxy   (listens on :9000, forwards to :9001)
Env:  GATEKEEPER_PORT           listen port (default 9000)
      GATEKEEPER_UPSTREAM       upstream MCP endpoint (default http://127.0.0.1:9001/mcp)
      GATEKEEPER_TENANTS_PATH   tenant registry file (default <repo>/tenants.json)
      GATEKEEPER_RECEIPTS_PATH  receipt ledger file (default <repo>/receipts.jsonl)
"""
import json
import os
import threading
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml

from .receipts import ReceiptLog
from .tenants import TenantRegistry

HERE = os.path.dirname(__file__)
LISTEN_PORT = int(os.environ.get("GATEKEEPER_PORT", "9000"))
UPSTREAM = os.environ.get("GATEKEEPER_UPSTREAM", "http://127.0.0.1:9001/mcp")
POLICY_PATH = os.path.join(HERE, "..", "policy.yaml")
TENANTS_PATH = os.environ.get(
    "GATEKEEPER_TENANTS_PATH", os.path.join(HERE, "..", "tenants.json")
)
RECEIPT_PATH = os.environ.get(
    "GATEKEEPER_RECEIPTS_PATH", os.path.join(HERE, "..", "receipts.jsonl")
)
DEFAULT_ACCEPT = "application/json, text/event-stream"


def load_policy():
    with open(POLICY_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)["tasks"]


class Handler(BaseHTTPRequestHandler):
    policy = load_policy()
    registry = TenantRegistry(TENANTS_PATH)
    registry.ensure("default")  # requests without X-Tenant-Id land here
    log = ReceiptLog(RECEIPT_PATH, registry)

    sessions = {}  # Mcp-Session-Id -> tenant_id
    sessions_lock = threading.Lock()

    server_version = "VouchGatekeeper/1.0"

    # ---------- response helpers ----------
    def _send(self, code, obj, content_type="application/json", session_id=None):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if session_id:
            self.send_header("Mcp-Session-Id", session_id)
        self.end_headers()
        self.wfile.write(body)

    def _send_raw(self, code, body, content_type="application/json", session_id=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if session_id:
            self.send_header("Mcp-Session-Id", session_id)
        self.end_headers()
        self.wfile.write(body)

    def _send_empty(self, code, session_id=None):
        self.send_response(code)
        if session_id:
            self.send_header("Mcp-Session-Id", session_id)
        self.end_headers()

    def _send_sse_start(self, code=200, session_id=None):
        # NOTE: no `Connection: keep-alive` here. BaseHTTPRequestHandler
        # flips close_connection=False when it sees that header (and so
        # does http.client on the read side), which deadlocks a
        # close-delimited SSE response. HTTP/1.0 close-delimits instead:
        # the server closes after the last event and the client reads EOF.
        self.send_response(code)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        if session_id:
            self.send_header("Mcp-Session-Id", session_id)
        self.end_headers()

    def _send_sse_event(self, msg):
        try:
            self.wfile.write(
                f"event: message\ndata: {json.dumps(msg)}\n\n".encode("utf-8")
            )
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _wants_sse(self):
        return "text/event-stream" in self.headers.get("Accept", "")

    def _send_rpc(self, msg, session_id=None):
        """One JSON-RPC message, SSE or plain JSON per client Accept."""
        if self._wants_sse():
            self._send_sse_start(200, session_id)
            self._send_sse_event(msg)
        else:
            self._send(200, msg, session_id=session_id)

    def _rpc_error(self, req_id, code, message):
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    # ---------- tenant / session bookkeeping ----------
    def _resolve_tenant(self):
        """(tenant_id, error_response). error_response is None on success."""
        tid = self.headers.get("X-Tenant-Id")
        sid = self.headers.get("Mcp-Session-Id")
        if tid:
            try:
                self.registry.signing_key(tid)
            except KeyError:
                return None, (403, {"error": f"unknown tenant '{tid}'"})
            if sid:
                with self.sessions_lock:
                    self.sessions[sid] = tid
            return tid, None
        if sid:
            with self.sessions_lock:
                bound = self.sessions.get(sid)
            if bound:
                return bound, None
        return "default", None

    def _bind_session(self, session_id, tenant_id):
        if session_id:
            with self.sessions_lock:
                self.sessions[session_id] = tenant_id

    def _unbind_session(self, session_id):
        if session_id:
            with self.sessions_lock:
                self.sessions.pop(session_id, None)

    # ---------- upstream plumbing ----------
    @staticmethod
    def _up_code(up):
        return up.code if isinstance(up, urllib.error.HTTPError) else up.status

    def _upstream_request(self, method, data=None, extra_headers=None):
        headers = {
            "Accept": self.headers.get("Accept", DEFAULT_ACCEPT),
            "Mcp-Session-Id": self.headers.get("Mcp-Session-Id", ""),
            "Last-Event-ID": self.headers.get("Last-Event-ID", ""),
        }
        headers = {k: v for k, v in headers.items() if v}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(UPSTREAM, data=data, headers=headers, method=method)
        try:
            return urllib.request.urlopen(req, timeout=30)
        except urllib.error.HTTPError as e:
            return e  # carries .code/.headers/.read() for relay
        except Exception as e:  # noqa: BLE001 - prototype surface
            return None, e

    def _relay_response(self, up):
        """Relay an upstream HTTP response to the client, streaming.

        Returns (session_id, rpc_message_or_None). rpc_message is the
        parsed JSON-RPC response when the body held exactly one."""
        if isinstance(up, tuple):  # (None, exc) -> upstream unreachable
            _, exc = up
            self._send(502, {"error": f"upstream unreachable: {exc}"})
            return None, None
        session_id = up.headers.get("Mcp-Session-Id")
        ctype = up.headers.get("Content-Type", "")
        code = self._up_code(up)
        if code == 202 or code == 204:
            self._send_empty(code, session_id)
            return session_id, None
        if "text/event-stream" in ctype:
            self._send_sse_start(code, session_id)
            raw = self._pump(up)
            msgs = parse_sse_messages(raw)
            return session_id, msgs[-1] if msgs else None
        body = up.read()
        self._send_raw(code, body, ctype or "application/json", session_id)
        try:
            return session_id, json.loads(body) if body else None
        except json.JSONDecodeError:
            return session_id, None

    def _pump(self, up):
        """Stream upstream bytes to the client, returning all of them."""
        chunks = []
        try:
            while True:
                chunk = up.read(8192)
                if not chunk:
                    break
                chunks.append(chunk)
                try:
                    self.wfile.write(chunk)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    break
        finally:
            up.close()
        return b"".join(chunks)

    # ---------- HTTP verbs ----------
    def do_POST(self):
        if self.path != "/mcp":
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return self._send(400, {"error": "empty body"})
        try:
            req = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            return self._send(400, {"error": "invalid json"})
        if isinstance(req, list):
            return self._send(400, {"error": "JSON-RPC batches not supported in v1"})

        tenant_id, err = self._resolve_tenant()
        if err:
            code, obj = err
            return self._send(code, obj)

        method = req.get("method", "")
        req_id = req.get("id")
        is_notification = "method" in req and "id" not in req
        is_response = "id" in req and ("result" in req or "error" in req)

        if is_notification or is_response:
            # Nothing to gate and no reply expected: forward, answer 202.
            up = self._upstream_request("POST", json.dumps(req).encode("utf-8"))
            if isinstance(up, tuple):
                return self._send(502, {"error": f"upstream unreachable: {up[1]}"})
            session_id = up.headers.get("Mcp-Session-Id")
            up.close()
            self._bind_session(session_id, tenant_id)
            return self._send_empty(202, session_id)

        agent_id = self.headers.get("X-Agent-Id", "unknown")
        task_id = self.headers.get("X-Task-Id")

        if method == "initialize":
            up = self._upstream_request("POST", json.dumps(req).encode("utf-8"))
            session_id, _ = self._relay_response(up)
            self._bind_session(session_id, tenant_id)
            print(f"[SESSION] tenant={tenant_id} session={session_id}")
            return

        if method == "tools/call":
            return self._handle_tools_call(req, req_id, tenant_id, agent_id, task_id)

        # Discovery / capability calls pass through untouched.
        up = self._upstream_request("POST", json.dumps(req).encode("utf-8"))
        session_id, _ = self._relay_response(up)
        self._bind_session(session_id, tenant_id)

    def _handle_tools_call(self, req, req_id, tenant_id, agent_id, task_id):
        tool = (req.get("params") or {}).get("name", "")
        args = (req.get("params") or {}).get("arguments", {})

        task = self.policy.get(task_id) if task_id else None
        allowed = bool(task) and tool in task.get("allow", [])

        if not allowed:
            reason = (
                f"task '{task_id}' is not granted tool '{tool}'"
                if task
                else f"unknown task '{task_id}'"
            )
            receipt = self.log.record(
                task_id=task_id or "unknown",
                agent_id=agent_id,
                tool=tool,
                args=args,
                decision="deny",
                reason=reason,
                tenant_id=tenant_id,
            )
            print(
                f"[DENY] tenant={tenant_id} task={task_id} agent={agent_id} "
                f"tool={tool} receipt={receipt['seq']}"
            )
            return self._send_rpc(
                self._rpc_error(
                    req_id, -32000, f"policy denied: {reason} (receipt #{receipt['seq']})"
                )
            )

        # Allowed: forward upstream, stream the reply through, then receipt it.
        up = self._upstream_request("POST", json.dumps(req).encode("utf-8"))
        session_id, _ = self._relay_response(up)
        self._bind_session(session_id, tenant_id)
        receipt = self.log.record(
            task_id=task_id,
            agent_id=agent_id,
            tool=tool,
            args=args,
            decision="allow",
            reason=None,
            tenant_id=tenant_id,
        )
        print(
            f"[ALLOW] tenant={tenant_id} task={task_id} agent={agent_id} "
            f"tool={tool} receipt={receipt['seq']}"
        )

    def do_GET(self):
        # Client-opened SSE stream for server-initiated messages: relay it.
        if self.path != "/mcp":
            return self._send(404, {"error": "not found"})
        tenant_id, err = self._resolve_tenant()
        if err:
            code, obj = err
            return self._send(code, obj)
        if not self.headers.get("Mcp-Session-Id"):
            return self._send(400, {"error": "Mcp-Session-Id required"})
        up = self._upstream_request("GET")
        if isinstance(up, tuple):
            return self._send(502, {"error": f"upstream unreachable: {up[1]}"})
        session_id = up.headers.get("Mcp-Session-Id")
        self._send_sse_start(self._up_code(up), session_id)
        self._pump(up)

    def do_DELETE(self):
        # Session termination: relay upstream, forget the binding.
        if self.path != "/mcp":
            return self._send(404, {"error": "not found"})
        session_id = self.headers.get("Mcp-Session-Id")
        up = self._upstream_request("DELETE")
        if isinstance(up, tuple):
            return self._send(502, {"error": f"upstream unreachable: {up[1]}"})
        code = self._up_code(up)
        up.close()
        if 200 <= code < 300:
            self._unbind_session(session_id)
            print(f"[SESSION] terminated session={session_id}")
        return self._send_empty(code)

    def log_message(self, *a):  # quieter logs
        pass


def parse_sse_messages(raw):
    """Parse SSE bytes -> list of JSON `data:` payloads (dicts)."""
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    messages = []
    for block in raw.split("\n\n"):
        data_lines = [
            line[5:].strip()
            for line in block.splitlines()
            if line.startswith("data:")
        ]
        if not data_lines:
            continue
        payload = "\n".join(data_lines).strip()
        if payload == "[DONE]":
            continue
        try:
            messages.append(json.loads(payload))
        except json.JSONDecodeError:
            continue
    return messages


def main():
    print(f"vouch gatekeeper v1 listening on :{LISTEN_PORT}, upstream {UPSTREAM}")
    print(f"policy:   {POLICY_PATH}")
    print(f"tenants:  {TENANTS_PATH}")
    print(f"receipts: {RECEIPT_PATH}")
    ThreadingHTTPServer(("127.0.0.1", LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
