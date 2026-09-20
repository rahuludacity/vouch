"""MCP client that routes tool calls through the Vouch gatekeeper.

The gatekeeper reads tenant identity from HTTP headers (unchanged v1
contract): ``X-Tenant-Id``, ``X-Agent-Id``, ``X-Task-Id``. Every ``tools/call``
is policy-gated (denied calls return JSON-RPC ``-32000`` and never reach the
upstream tool server) and every decision gets a signed receipt.
"""

import itertools
import json
import urllib.error
import urllib.request


class MCPError(Exception):
    """A denied tool call or transport failure through the gatekeeper."""


class MCPClient:
    """Minimal MCP Streamable HTTP client pinned to the gatekeeper.

    Usage::

        mcp = MCPClient("http://127.0.0.1:9000/mcp",
                        tenant_id="acme", task_id="deploy-staging",
                        agent_id="agent-001")
        mcp.initialize()
        result = mcp.call_tool("run_tests", {"suite": "unit"})
        mcp.close()
    """

    def __init__(self, gatekeeper_url, tenant_id, task_id, agent_id,
                 timeout=30):
        self.gatekeeper_url = gatekeeper_url.rstrip("/")
        self.tenant_id = tenant_id
        self.task_id = task_id
        self.agent_id = agent_id
        self.timeout = timeout
        self.session_id = None
        self._ids = itertools.count(1)

    # ------------------------------------------------------------- transport
    def _headers(self, accept="application/json"):
        h = {
            "Content-Type": "application/json",
            "Accept": accept,
            "X-Tenant-Id": self.tenant_id,
            "X-Agent-Id": self.agent_id,
            "X-Task-Id": self.task_id,
        }
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    def _post(self, message, accept="application/json"):
        req = urllib.request.Request(
            self.gatekeeper_url,
            data=json.dumps(message).encode("utf-8"),
            headers=self._headers(accept),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                self.session_id = (resp.headers.get("Mcp-Session-Id")
                                   or self.session_id)
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raise MCPError(f"gatekeeper HTTP {e.code}: "
                           f"{e.read().decode('utf-8', 'replace')}")
        # JSON response (Accept: application/json) — the gatekeeper also
        # supports SSE; this client requests the single-object form.
        if accept == "application/json":
            return json.loads(body) if body.strip() else {}
        return body

    # ------------------------------------------------------------------ API
    def initialize(self):
        """MCP handshake: initialize + notifications/initialized."""
        resp = self._post({
            "jsonrpc": "2.0",
            "id": next(self._ids),
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "vouch-sdk", "version": "0.6.0"},
            },
        })
        if not self.session_id:
            raise MCPError(f"initialize failed: {resp}")
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return resp

    def call_tool(self, tool, args=None):
        """Call a tool through the gatekeeper. Raises MCPError if denied.

        Returns the tool's ``result`` on allow.
        """
        resp = self._post({
            "jsonrpc": "2.0",
            "id": next(self._ids),
            "method": "tools/call",
            "params": {"name": tool, "arguments": args or {}},
        })
        if "error" in resp:
            err = resp["error"]
            raise MCPError(f"denied: {err.get('message')} "
                           f"(code {err.get('code')})")
        return resp.get("result")

    def close(self):
        """MCP session teardown (DELETE /mcp). Best effort."""
        if not self.session_id:
            return
        req = urllib.request.Request(
            self.gatekeeper_url,
            headers=self._headers(),
            method="DELETE",
        )
        try:
            urllib.request.urlopen(req, timeout=self.timeout)
        except Exception:
            pass
        self.session_id = None
