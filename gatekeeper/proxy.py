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
deny emits a receipt signed with the calling tenant's HMAC key. A
notification-shaped `tools/call` (no JSON-RPC "id") is gated exactly
like the id-carrying form (C-1 fail closed); other notifications are
forwarded ONLY when the policy's top-level `allow_notifications`
explicitly lists the method — default deny.

Tenant identification:
  - Control-plane mode (CONTROLPLANE_URL set): the caller MUST present the
    per-deployment credential (H-1 fix) in the X-Deployment-Token header —
    minted by the control plane at deployment creation and injected by the
    runner into the agent container. The gatekeeper validates it (HMAC +
    revocation-aware binding check) and the credential's tenant is
    authoritative. X-Tenant-Id may be sent as a hint but must match; a
    missing/forged credential -> 403. Self-asserted identity is never
    trusted on this path.
  - v1 file mode (no control plane): X-Tenant-Id header as before (local
    dev only).
  X-Agent-Id and X-Task-Id remain headers (attribution, non-security).

Run:  python3 -m gatekeeper.proxy   (listens on :9000, forwards to :9001)
Env:  VOUCH_BIND            bind address (default 127.0.0.1; set 0.0.0.0 when
                        running without network_mode: host, see compose)
      GATEKEEPER_PORT           listen port (default 9000)
      GATEKEEPER_UPSTREAM       upstream MCP endpoint (default http://127.0.0.1:9001/mcp)
      GATEKEEPER_TENANTS_PATH   tenant registry file (default <repo>/tenants.json)
      GATEKEEPER_RECEIPTS_PATH  receipt ledger file (default <repo>/receipts.jsonl)
      GATEKEEPER_POLICY_PATH    policy file, v1 or v2 schema (default <repo>/policy.yaml)
      RECEIPT_SVC_URL           receipt service base (default http://127.0.0.1:9001;
                                empty disables remote ingest -> local file only)
      RECEIPT_SVC_TOKEN         bearer token for POST /v1/ingest (default "")
      RECEIPT_FLUSH_INTERVAL    flusher pass interval in seconds (default 5.0)
      CONTROLPLANE_URL          control plane base (default ""; empty keeps the
                                v1 file-backed tenant registry + policy.yaml)
      GATEKEEPER_SVC_TOKEN      bearer token for control-plane internal calls
                                (default ""); also validates the push
                                POST /internal/cache/invalidate
      POLICY_POLL_INTERVAL      policy bundle poll seconds (default 15)

When CONTROLPLANE_URL is set, the key authority moves to the control plane
(§4.3): per-tenant key bundles are cached with a 60s TTL and served stale
while the control plane is down; `status != active` denies everything with
reason "tenant suspended"; policies come from the control-plane bundle with
the file policy as fallback. The v1 file path is untouched otherwise.
"""
import json
import hmac
import os
import threading
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml

from . import policy_v2
from .controlplane import (
    KeyBundleCache, PolicyBundleCache, DeploymentTokenVerifier)

HERE = os.path.dirname(__file__)
BIND = os.environ.get("VOUCH_BIND", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("GATEKEEPER_PORT", "9000"))
from .ingest import ReceiptEmitter
from .receipts import ReceiptLog
from .tenants import TenantRegistry

HERE = os.path.dirname(__file__)
LISTEN_PORT = int(os.environ.get("GATEKEEPER_PORT", "9000"))
UPSTREAM = os.environ.get("GATEKEEPER_UPSTREAM", "http://127.0.0.1:9001/mcp")
CONTROLPLANE_URL = os.environ.get("CONTROLPLANE_URL", "").rstrip("/")
GATEKEEPER_SVC_TOKEN = os.environ.get("GATEKEEPER_SVC_TOKEN", "")
POLICY_POLL_INTERVAL = float(os.environ.get("POLICY_POLL_INTERVAL", "15"))
CP_ACTIVE = bool(CONTROLPLANE_URL)
POLICY_PATH = os.environ.get(
    "GATEKEEPER_POLICY_PATH", os.path.join(HERE, "..", "policy.yaml")
)
TENANTS_PATH = os.environ.get(
    "GATEKEEPER_TENANTS_PATH", os.path.join(HERE, "..", "tenants.json")
)
RECEIPT_PATH = os.environ.get(
    "GATEKEEPER_RECEIPTS_PATH", os.path.join(HERE, "..", "receipts.jsonl")
)
DEFAULT_ACCEPT = "application/json, text/event-stream"


def load_policy():
    """Load the policy file (v1 or v2 schema) -> compiled policy_v2.Policy.

    v1 files are upgraded in memory via upgrade_v1_policy(): byte-for-byte
    file compatibility, zero behavior change (§5.3)."""
    with open(POLICY_PATH, "r", encoding="utf-8") as f:
        return policy_v2.Policy.from_dict(yaml.safe_load(f))


class Handler(BaseHTTPRequestHandler):
    policy = load_policy()  # file policy: fallback when the control plane
    # is off or its bundle is unavailable. Never removed.
    if CP_ACTIVE:
        # Key authority is the control plane (§4.3): per-tenant key bundles
        # with 60s TTL, served stale while the control plane is down.
        key_resolver = KeyBundleCache(CONTROLPLANE_URL, GATEKEEPER_SVC_TOKEN)
        policy_cache = PolicyBundleCache(CONTROLPLANE_URL, GATEKEEPER_SVC_TOKEN,
                                         POLICY_POLL_INTERVAL)
        # H-1: per-deployment gatekeeper credentials. The runner injects
        # VOUCH_DEPLOYMENT_TOKEN into each agent container; the agent sends
        # it as X-Deployment-Token and the gatekeeper validates it here
        # before honoring any identity header.
        dep_verifier = DeploymentTokenVerifier(CONTROLPLANE_URL,
                                               GATEKEEPER_SVC_TOKEN)
        registry = None  # no file registry in control-plane mode
    else:
        key_resolver = TenantRegistry(TENANTS_PATH)
        key_resolver.ensure("default")  # requests without X-Tenant-Id land here
        registry = key_resolver  # v1 alias (tests, demo tooling)
        policy_cache = None
        dep_verifier = None
    log = ReceiptLog(RECEIPT_PATH, key_resolver)
    # Receipt emitter: POSTs per-tenant receipts to the receipt service;
    # any ingest failure falls back to the local ReceiptLog file above.
    emitter = ReceiptEmitter(key_resolver, log)

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
    # 1MB body cap (M-2): client-controlled Content-Length must never drive
    # an unbounded rfile.read() on a ThreadingHTTPServer worker.
    _MAX_BODY = 1_000_000

    def _body_length(self):
        """Content-Length as int, or None when missing/garbage/over cap."""
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            return "bad"
        if length < 0:
            return "bad"
        if length > self._MAX_BODY:
            return "too_large"
        return length

    def _resolve_tenant(self):
        """(tenant_id, error_response). error_response is None on success."""
        if CP_ACTIVE:
            return self._resolve_tenant_cp()
        tid = self.headers.get("X-Tenant-Id")
        sid = self.headers.get("Mcp-Session-Id")
        if tid:
            try:
                self.key_resolver.signing_key(tid)
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

    def _resolve_tenant_cp(self):
        """Control-plane mode identity (H-1 fix).

        The X-Deployment-Token bearer is authoritative: it is validated
        (HMAC + revocation-aware deployment binding) and its tenant is the
        tenant of the request. X-Tenant-Id is accepted only as a hint and
        must match the credential — a forged tenant header without a
        matching credential is rejected. No credential -> 403.
        """
        token = self.headers.get("X-Deployment-Token", "")
        if not token:
            return None, (403, {
                "error": "deployment_credential_required",
                "message": "X-Deployment-Token header required; the runner "
                           "injects VOUCH_DEPLOYMENT_TOKEN into agent "
                           "containers at deployment creation",
            })
        tenant_id = self.dep_verifier.verify(token)
        if tenant_id is None:
            return None, (403, {
                "error": "invalid_deployment_credential",
                "message": "deployment credential is malformed, forged, or "
                           "revoked (deployment stopped/deleted)",
            })
        hint = self.headers.get("X-Tenant-Id")
        if hint and hint != tenant_id:
            return None, (403, {
                "error": "tenant_mismatch",
                "message": "X-Tenant-Id does not match the deployment "
                           "credential's tenant",
            })
        sid = self.headers.get("Mcp-Session-Id")
        if sid:
            with self.sessions_lock:
                self.sessions[sid] = tenant_id
        return tenant_id, None

    def _is_suspended(self, tenant_id):
        """True when the control plane marks the tenant non-active.

        Fail closed: if the key authority can't answer, the tenant is
        treated as suspended.
        """
        if not CP_ACTIVE:
            return False
        try:
            return self.key_resolver.status(tenant_id) != "active"
        except KeyError:
            return True

    def _policy_for(self, tenant_id):
        """Compiled policy for this tenant.

        Control-plane bundle when active and available (refreshed
        opportunistically on bundle-version drift, plus the background
        poller); the file policy otherwise. Enforcement never blocks on a
        fresh fetch.
        """
        if CP_ACTIVE:
            try:
                kb_version = self.key_resolver.policy_version(tenant_id)
            except KeyError:
                kb_version = 0
            if kb_version > self.policy_cache.bundle_version(tenant_id):
                self.policy_cache.refresh_tenant(tenant_id)
            cached = self.policy_cache.policy_for(tenant_id)
            if cached is not None:
                return cached
        return self.policy

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
        if self.path == "/internal/cache/invalidate":
            return self._handle_invalidate()
        if self.path != "/mcp":
            return self._send(404, {"error": "not found"})
        length = self._body_length()
        if length == "bad":
            return self._send(400, {"error": "bad Content-Length"})
        if length == "too_large":
            return self._send(413, {"error": "payload_too_large"})
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

        agent_id = self.headers.get("X-Agent-Id", "unknown")
        task_id = self.headers.get("X-Task-Id")

        if method == "tools/call" and is_notification:
            # C-1 fail closed: a notification-shaped tools/call gets the
            # FULL policy evaluation path (decision + signed receipt +
            # upstream forward on allow), exactly like the id-carrying
            # form — never a silent forward. req_id is None, so a deny
            # rides _send_rpc as an id:null JSON-RPC error instead of a
            # misleading 202.
            return self._handle_tools_call(req, req_id, tenant_id, agent_id,
                                           task_id)

        if is_notification or is_response:
            if is_notification:
                # C-1: genuine notifications keep notification semantics
                # ONLY when the policy explicitly permits the method via
                # allow_notifications; default deny for anything the
                # policy doesn't recognize.
                if CP_ACTIVE and self._is_suspended(tenant_id):
                    return self._send(403, {"error": "tenant suspended"})
                if not self._policy_for(tenant_id).notification_allowed(method):
                    print(f"[DENY] tenant={tenant_id} task={task_id} "
                          f"agent={agent_id} notification method={method!r} "
                          f"not in allow_notifications")
                    return self._send(
                        403, {"error": "notification_not_permitted",
                              "message": f"method '{method}' is not permitted "
                                         "as a notification"})
            # Nothing to gate and no reply expected: forward, answer 202.
            up = self._upstream_request("POST", json.dumps(req).encode("utf-8"))
            if isinstance(up, tuple):
                return self._send(502, {"error": f"upstream unreachable: {up[1]}"})
            session_id = up.headers.get("Mcp-Session-Id")
            up.close()
            self._bind_session(session_id, tenant_id)
            return self._send_empty(202, session_id)

        if method == "initialize":
            up = self._upstream_request("POST", json.dumps(req).encode("utf-8"))
            session_id, _ = self._relay_response(up)
            self._bind_session(session_id, tenant_id)
            print(f"[SESSION] tenant={tenant_id} session={session_id}")
            return

        if method == "tools/call":
            return self._handle_tools_call(req, req_id, tenant_id, agent_id, task_id)

        if CP_ACTIVE and self._is_suspended(tenant_id):
            return self._send(403, {"error": "tenant suspended"})

        # Discovery / capability calls pass through untouched.
        up = self._upstream_request("POST", json.dumps(req).encode("utf-8"))
        session_id, _ = self._relay_response(up)
        self._bind_session(session_id, tenant_id)

    def _handle_invalidate(self):
        """POST /internal/cache/invalidate — drop cached key/deployment data.

        Called best-effort by the control plane on rotate/suspend/plan-change
        ({"tenant_id"}) and on deployment stop ({"deployment_id"}); the TTLs
        are the backstop, so this endpoint only hurries them up.
        """
        if not CP_ACTIVE:
            return self._send(404, {"error": "not found"})
        # L-1: constant-time bearer comparison.
        presented = self.headers.get("Authorization", "")
        expect = f"Bearer {GATEKEEPER_SVC_TOKEN}"
        if (not GATEKEEPER_SVC_TOKEN
                or not hmac.compare_digest(presented, expect)):
            return self._send(401, {"error": "unauthorized"})
        length = self._body_length()
        if length in ("bad", "too_large"):
            return self._send(400 if length == "bad" else 413,
                              {"error": "bad Content-Length"})
        try:
            body = json.loads(self.rfile.read(length)) if length else {}
        except json.JSONDecodeError:
            return self._send(400, {"error": "invalid json"})
        tenant_id = body.get("tenant_id", "")
        deployment_id = body.get("deployment_id", "")
        if deployment_id:
            self.dep_verifier.invalidate_binding(deployment_id)
            return self._send(200, {"ok": True,
                                    "deployment_id": deployment_id})
        if not tenant_id:
            return self._send(400, {"error": "tenant_id required"})
        self.key_resolver.invalidate(tenant_id)
        self.policy_cache.invalidate(tenant_id)
        return self._send(200, {"ok": True, "tenant_id": tenant_id})

    def _handle_tools_call(self, req, req_id, tenant_id, agent_id, task_id):
        tool = (req.get("params") or {}).get("name", "")
        args = (req.get("params") or {}).get("arguments", {})

        if CP_ACTIVE and self._is_suspended(tenant_id):
            # Deny-all for suspended tenants (§4.3): still receipted, so the
            # audit trail shows the blocked attempt.
            receipt = self.emitter.emit(
                tenant_id=tenant_id,
                task_id=task_id or "unknown",
                agent_id=agent_id,
                tool=tool,
                args=args,
                decision="deny",
                reason="tenant suspended",
                rule_id=None,
                policy_version=self.key_resolver.policy_version(tenant_id),
            )
            print(
                f"[DENY] tenant={tenant_id} task={task_id} agent={agent_id} "
                f"tool={tool} rule=None receipt={receipt['seq']} (suspended)"
            )
            return self._send_rpc(
                self._rpc_error(
                    req_id, -32000,
                    f"policy denied: tenant suspended (receipt #{receipt['seq']})"
                )
            )

        policy = self._policy_for(tenant_id)
        allowed, reason, rule_id = policy.decide(task_id, tool, args)
        policy_version = policy.version_for(task_id)

        if not allowed:
            receipt = self.emitter.emit(
                tenant_id=tenant_id,
                task_id=task_id or "unknown",
                agent_id=agent_id,
                tool=tool,
                args=args,
                decision="deny",
                reason=reason,
                rule_id=rule_id,
                policy_version=policy_version,
            )
            print(
                f"[DENY] tenant={tenant_id} task={task_id} agent={agent_id} "
                f"tool={tool} rule={rule_id} receipt={receipt['seq']}"
            )
            return self._send_rpc(
                self._rpc_error(
                    req_id, -32000, f"policy denied: {reason} (receipt #{receipt['seq']})"
                )
            )

        # Allowed: receipt the authorization FIRST, then forward upstream
        # (M-4 fix). The policy decision is final here; emitting before the
        # network call closes the crash window where an action executes but
        # no receipt exists ("every action gets a receipt" — the receipt
        # records the authorized call, not the upstream result).
        receipt = self.emitter.emit(
            tenant_id=tenant_id,
            task_id=task_id,
            agent_id=agent_id,
            tool=tool,
            args=args,
            decision="allow",
            reason=None,
            rule_id=rule_id,
            policy_version=policy_version,
        )
        print(
            f"[ALLOW] tenant={tenant_id} task={task_id} agent={agent_id} "
            f"tool={tool} rule={rule_id} receipt={receipt['seq']}"
        )
        up = self._upstream_request("POST", json.dumps(req).encode("utf-8"))
        session_id, _ = self._relay_response(up)
        self._bind_session(session_id, tenant_id)

    def do_GET(self):
        # Client-opened SSE stream for server-initiated messages: relay it.
        if self.path != "/mcp":
            return self._send(404, {"error": "not found"})
        tenant_id, err = self._resolve_tenant()
        if err:
            code, obj = err
            return self._send(code, obj)
        if CP_ACTIVE and self._is_suspended(tenant_id):
            return self._send(403, {"error": "tenant suspended"})
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
        tenant_id, err = self._resolve_tenant()
        if err:
            code, obj = err
            return self._send(code, obj)
        if CP_ACTIVE and self._is_suspended(tenant_id):
            return self._send(403, {"error": "tenant suspended"})
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
    print(f"vouch gatekeeper v1 listening on {BIND}:{LISTEN_PORT}, upstream {UPSTREAM}")
    print(f"policy:   {POLICY_PATH}")
    print(f"tenants:  {TENANTS_PATH}")
    print(f"receipts: {RECEIPT_PATH}")
    if CP_ACTIVE:
        print("identity:   X-Deployment-Token required (H-1 per-deployment credentials)")
    # Reap the regex worker pool on SIGTERM/SIGINT: daemon workers do not
    # die with a SIGTERMed parent (atexit is skipped), and without this
    # they linger as orphans still holding the listening socket.
    import signal as _signal

    def _shutdown(signum, _frame):
        policy_v2._regex_pool.close()
        _signal.signal(signum, _signal.SIG_DFL)
        import os as _os
        _os.kill(_os.getpid(), signum)

    _signal.signal(_signal.SIGTERM, _shutdown)
    _signal.signal(_signal.SIGINT, _shutdown)
    ThreadingHTTPServer((BIND, LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
