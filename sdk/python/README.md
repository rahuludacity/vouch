# Vouch Python SDK

Stdlib-only client for [Vouch](https://github.com/rahuludacity/vouch) —
governed agent deployment, with proof. No dependencies beyond Python 3.9+.

```bash
pip install ./sdk/python   # or: pip install vouch (when published)
```

## Quick start

```python
from vouch import VouchClient, MCPClient, verify_chain

# 1. Provision a tenant (api_key is shown once — store it)
client, tenant_id, api_key = VouchClient.provision("acme")

# 2. Write a policy for a task (v2 schema — see docs, ARCHITECTURE.md §5)
client.put_policy("deploy-staging", {
    "allow": [
        {"rule_id": "read-workspace", "tool": "read_file",
         "args": {"path": {"prefix": "/workspace/"}}},
        {"rule_id": "run-tests", "tool": "run_tests"},
        {"rule_id": "deploy-staging", "tool": "deploy_staging",
         "args": {"env": {"in": ["staging"]}}},
    ],
    "deny": [
        {"rule_id": "no-destructive", "tool": "delete_database"},
    ],
})

# 3. Deploy an agent — the runner sandboxes it and routes tool calls
#    through the gatekeeper with the right identity headers
dep = client.deploy_agent(task_id="deploy-staging",
                          agent_image="vouch/agent-demo:latest")

# 4. Read the receipts and verify the chain (server-side; keys stay server-side)
receipts = client.receipts(limit=50)["items"]
print(client.verify())   # {"chain_ok": True, ...}
```

## Talking to tools through the gatekeeper

```python
mcp = MCPClient("http://127.0.0.1:9000/mcp", tenant_id=tenant_id,
                task_id="deploy-staging", agent_id="agent-001")
mcp.initialize()
print(mcp.call_tool("run_tests", {"suite": "unit"}))
try:
    mcp.call_tool("delete_database", {"target": "prod"})
except MCPError as e:
    print("blocked:", e)   # denied at the proxy — never reaches the tool server
mcp.close()
```

## Offline chain verification (operators with key access)

```python
from vouch import verify_chain
ok, failures = verify_chain(receipts, {"k1": key_bytes_or_hex})
```

Mirrors the server's `verify_tenant` exactly (seq continuity, `prev_hash`
linkage, body hash, HMAC). Same failure shape: `{"seq", "error"}`.

## Reference

`VouchClient(api_key, control_plane_url=…, receipt_service_url=…, billing_url=…)`

| method | endpoint |
|---|---|
| `provision(name)` | `POST /v1/tenants` (classmethod) |
| `me()` | `GET /v1/tenants/me` (+ usage fan-in) |
| `rotate_keys()` | `POST /v1/tenants/me/rotate-keys` |
| `list_policies()` / `put_policy(t, rules)` / `delete_policy(t)` | `/v1/policies…` |
| `list_api_keys()` / `create_api_key(name)` / `revoke_api_key(id)` | `/v1/api-keys…` |
| `deploy_agent(task_id, agent_image)` / `list_deployments()` / `get_deployment(id)` / `stop_deployment(id)` | `/v1/deployments…` |
| `receipts(…)` / `get_receipt(seq)` / `verify()` | receipt service `/v1/…` |
| `checkout(plan)` / `subscription()` / `portal_url()` | billing `/v1/billing/…` |

Errors raise `VouchError(status, code, message)` with the server's
`{"error", "message"}` payload.
