"""Simulated agent: makes tool calls THROUGH the gatekeeper.

Scenario 1 (legit): task deploy-staging does its job -> all allowed.
Scenario 2 (rogue/compromised): same task tries delete_database -> DENIED,
    the destructive call never reaches the tool server, and the denial
    itself gets a signed receipt.

Run: python3 demo/agent_sim.py  (needs upstream :9001 and gatekeeper :9000)
"""
import json
import urllib.request

GATE = "http://127.0.0.1:9000/mcp"


def call(task_id, agent_id, tool, args):
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }
    r = urllib.request.Request(
        GATE,
        data=json.dumps(req).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Task-Id": task_id,
            "X-Agent-Id": agent_id,
        },
    )
    with urllib.request.urlopen(r, timeout=10) as resp:
        return json.loads(resp.read())


def show(label, res):
    if "error" in res:
        print(f"  {label}: BLOCKED -> {res['error']['message']}")
    else:
        text = res["result"]["content"][0]["text"]
        print(f"  {label}: ok -> {text}")


print("Scenario 1: legit staging deploy (task=deploy-staging, agent=agent-001)")
show("read_file", call("deploy-staging", "agent-001", "read_file", {"path": "app.py"}))
show("run_tests", call("deploy-staging", "agent-001", "run_tests", {"suite": "unit"}))
show("deploy_staging", call("deploy-staging", "agent-001", "deploy_staging", {"build": "a1b2c3"}))

print()
print("Scenario 2: compromised agent tries to drop the database")
show(
    "delete_database",
    call("deploy-staging", "agent-001", "delete_database", {"target": "prod"}),
)

print()
print("Scenario 3: unknown task gets nothing")
show("read_file", call("no-such-task", "agent-999", "read_file", {"path": "x"}))
