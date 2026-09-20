"""Simulated agent: makes tool calls THROUGH the vouch gatekeeper.

Now a real MCP Streamable HTTP client:
  1. POSTs `initialize` with `Accept: application/json, text/event-stream`
  2. keeps the `Mcp-Session-Id` the server assigns
  3. sends JSON-RPC requests with that session id, parsing SSE
     (`event: message`) or plain JSON replies

Scenario 1 (legit): task deploy-staging does its job -> all allowed.
Scenario 2 (rogue/compromised): same task tries delete_database -> DENIED,
    the destructive call never reaches the tool server, and the denial
    itself gets a signed receipt (under this tenant's key).
Scenario 3: unknown task gets nothing.

Run: python3 demo/agent_sim.py  (needs upstream :9001 and gatekeeper :9000)
Env: GATEKEEPER_URL (default http://127.0.0.1:9000/mcp)
     VOUCH_TENANT  (default "demo")
"""
import json
import os
import urllib.request
import urllib.error

GATE = os.environ.get("GATEKEEPER_URL", "http://127.0.0.1:9000/mcp")
# Identity: the runner injects VOUCH_*_ID env vars into the agent container
# (§2.5); the legacy VOUCH_TENANT and the demo defaults still work.
TENANT = os.environ.get("VOUCH_TENANT_ID") or os.environ.get("VOUCH_TENANT", "demo")
TASK_ID = os.environ.get("VOUCH_TASK_ID", "deploy-staging")
AGENT_ID = os.environ.get("VOUCH_AGENT_ID", "agent-001")


def parse_sse(raw):
    """SSE bytes -> list of JSON data payloads."""
    text = raw.decode("utf-8", errors="replace")
    out = []
    for block in text.split("\n\n"):
        data = "\n".join(
            ln[5:].strip() for ln in block.splitlines() if ln.startswith("data:")
        ).strip()
        if not data or data == "[DONE]":
            continue
        try:
            out.append(json.loads(data))
        except json.JSONDecodeError:
            pass
    return out


class McpClient:
    def __init__(self, url, tenant_id, task_id, agent_id):
        self.url = url
        self.tenant_id = tenant_id
        self.task_id = task_id
        self.agent_id = agent_id
        self.session_id = None
        self._id = 0

    def _next_id(self):
        self._id += 1
        return self._id

    def _post(self, msg):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "X-Tenant-Id": self.tenant_id,
            "X-Task-Id": self.task_id,
            "X-Agent-Id": self.agent_id,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        req = urllib.request.Request(
            self.url, data=json.dumps(msg).encode(), headers=headers
        )
        try:
            resp = urllib.request.urlopen(req, timeout=15)
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()
        sid = resp.headers.get("Mcp-Session-Id")
        if sid:
            self.session_id = sid
        body = resp.read()
        ctype = resp.headers.get("Content-Type", "")
        if "text/event-stream" in ctype:
            msgs = parse_sse(body)
        else:
            msgs = [json.loads(body)] if body else []
        return resp.status, resp.headers, msgs

    def initialize(self):
        code, _, msgs = self._post(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "demo-agent", "version": "0.1"},
                },
            }
        )
        assert code == 200 and self.session_id, "initialize failed"
        # required initialized notification (202, no body expected)
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        server = (msgs[0].get("result", {}).get("serverInfo", {}) if msgs else {})
        print(f"  connected: session={self.session_id} server={server.get('name')}")
        return msgs

    def call_tool(self, tool, args):
        _, _, msgs = self._post(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "tools/call",
                "params": {"name": tool, "arguments": args},
            }
        )
        return msgs[0] if msgs else {"error": {"message": "empty reply"}}


def show(label, res):
    if "error" in res:
        print(f"  {label}: BLOCKED -> {res['error']['message']}")
    else:
        text = res["result"]["content"][0]["text"]
        print(f"  {label}: ok -> {text}")


def run_scenario(task_id, agent_id, calls):
    client = McpClient(GATE, TENANT, task_id, agent_id)
    client.initialize()
    for label, tool, args in calls:
        show(label, client.call_tool(tool, args))
    # clean session teardown (MCP DELETE)
    req = urllib.request.Request(
        GATE,
        headers={"Mcp-Session-Id": client.session_id, "X-Tenant-Id": TENANT},
        method="DELETE",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        print("  session terminated (DELETE 202)")
    except urllib.error.HTTPError as e:
        print(f"  session teardown -> HTTP {e.code}")


print(f"Scenario 1: legit staging deploy (tenant={TENANT}, task={TASK_ID})")
run_scenario(
    TASK_ID,
    AGENT_ID,
    [
        ("read_file", "read_file", {"path": "app.py"}),
        ("run_tests", "run_tests", {"suite": "unit"}),
        ("deploy_staging", "deploy_staging", {"build": "a1b2c3"}),
    ],
)

print()
print("Scenario 2: compromised agent tries to drop the database")
run_scenario(
    TASK_ID,
    AGENT_ID,
    [("delete_database", "delete_database", {"target": "prod"})],
)

print()
print("Scenario 3: unknown task gets nothing")
run_scenario("no-such-task", "agent-999", [("read_file", "read_file", {"path": "x"})])
