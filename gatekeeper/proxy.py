"""Gatekeeper: an MCP (JSON-RPC) proxy that enforces task-scoped capabilities.

The agent talks to this proxy instead of the tool server directly.
Headers required on every request:
    X-Task-Id:   which task this call belongs to (the capability scope)
    X-Agent-Id:  which agent is acting

Behavior:
  - tools/list, initialize, etc. -> forwarded untouched
  - tools/call -> tool name checked against policy.yaml for the task
      - allowed -> forwarded upstream, receipt(decision=allow)
      - denied  -> blocked HERE, never reaches upstream, receipt(decision=deny)

Every decision emits a signed, hash-chained receipt (see receipts.py).

Run:  python3 gatekeeper/proxy.py  (listens on 9000, forwards to 9001)
Env:  GATEKEEPER_KEY  HMAC key for receipt signing (dev default set below)
"""
import json
import os
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

import yaml

from receipts import ReceiptLog

LISTEN_PORT = 9000
UPSTREAM = "http://127.0.0.1:9001/mcp"
POLICY_PATH = os.path.join(os.path.dirname(__file__), "..", "policy.yaml")
RECEIPT_PATH = os.path.join(os.path.dirname(__file__), "..", "receipts.jsonl")
HMAC_KEY = os.environ.get("GATEKEEPER_KEY", "dev-only-change-me")


def load_policy():
    with open(POLICY_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)["tasks"]


class Handler(BaseHTTPRequestHandler):
    policy = load_policy()
    log = ReceiptLog(RECEIPT_PATH, HMAC_KEY)

    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _rpc_error(self, req_id, code, message):
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    def do_POST(self):
        if self.path != "/mcp":
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            return self._send(400, {"error": "invalid json"})

        task_id = self.headers.get("X-Task-Id")
        agent_id = self.headers.get("X-Agent-Id", "unknown")
        method = req.get("method", "")
        req_id = req.get("id")

        # Only tool execution is gated. Discovery/capability calls pass through.
        if method != "tools/call":
            return self._forward(req)

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
            )
            print(f"[DENY] task={task_id} agent={agent_id} tool={tool} receipt={receipt['seq']}")
            return self._send(
                200,
                self._rpc_error(
                    req_id, -32000, f"policy denied: {reason} (receipt #{receipt['seq']})"
                ),
            )

        # Allowed: forward, then receipt the actual execution.
        status, resp = self._forward_raw(req)
        receipt = self.log.record(
            task_id=task_id,
            agent_id=agent_id,
            tool=tool,
            args=args,
            decision="allow",
            reason=None,
        )
        print(f"[ALLOW] task={task_id} agent={agent_id} tool={tool} receipt={receipt['seq']}")
        return self._send(status, resp)

    def _forward_raw(self, req):
        data = json.dumps(req).encode("utf-8")
        upstream = urllib.request.Request(
            UPSTREAM, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(upstream, timeout=15) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, {"error": f"upstream http {e.code}"}
        except Exception as e:  # noqa: BLE001 - prototype surface
            return 502, {"error": f"upstream unreachable: {e}"}

    def _forward(self, req):
        status, resp = self._forward_raw(req)
        return self._send(status, resp)

    def log_message(self, *a):  # quieter logs
        pass


if __name__ == "__main__":
    # PyYAML is required: pip install pyyaml
    print(f"gatekeeper listening on :{LISTEN_PORT}, upstream {UPSTREAM}")
    print(f"policy: {POLICY_PATH}")
    print(f"receipts: {RECEIPT_PATH}")
    HTTPServer(("127.0.0.1", LISTEN_PORT), Handler).serve_forever()
