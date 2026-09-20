# Quickstart — Vouch in 5 minutes

**Prereqs:** `python3`, `curl`, `pip install pyyaml`. No Docker needed.

## One command

```bash
git clone --branch phase6-docs-sdks https://github.com/rahuludacity/vouch.git
cd vouch
pip install pyyaml
bash quickstart.sh
```

That boots the whole stack (gatekeeper `:9000`, receipts `:9001`, control
plane `:9002`, dashboard `:3000`, billing `:9004` in mock test mode),
provisions a tenant, writes a policy, deploys an agent, runs it, and verifies
the receipt chain. Expected ending:

```
{"tenant_id": "quickstart", "receipts": 10, "chain_ok": true, "failures": []}
Done. Every decision above has a signed, tamper-evident receipt.
Dashboard: http://127.0.0.1:3000  (overview / receipts / policies / keys)
```

## The same flow, by hand

The script is just automation over the frozen API (§4). Here's what it does,
so you can drive it yourself:

```bash
# 1. start the services (see quickstart.sh for the full env block)
python3 -m services.controlplane.app &   # :9002
python3 -m services.receipts.app &       # :9001
python3 -m gatekeeper.proxy &             # :9000 (needs an upstream MCP server)
python3 -m web.dashboard.app &           # :3000

# 2. provision a tenant — the api_key is shown ONCE, save it
curl -s -X POST localhost:9002/v1/tenants \
  -H 'Content-Type: application/json' -d '{"name":"acme"}'
# {"tenant_id":"acme","api_key":"vouch_sk_…","plan":"free"}

export KEY=vouch_sk_…

# 3. write a policy for the task
curl -s -X PUT localhost:9002/v1/policies/deploy-staging \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d '{
    "rules": {
      "allow": [
        {"rule_id":"read-ok","tool":"read_file"},
        {"rule_id":"tests-ok","tool":"run_tests"},
        {"rule_id":"staging-ok","tool":"deploy_staging",
         "args":{"build":{"regex":"^[0-9a-f]{6,40}$"}}}
      ],
      "deny": [{"rule_id":"no-db-drop","tool":"delete_database"}]
    }}'
# {"task_id":"deploy-staging","version":1}

# 4. deploy an agent — the runner sandboxes it and injects gatekeeper identity
curl -s -X POST localhost:9002/v1/deployments \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"task_id":"deploy-staging","agent_image":"vouch/agent-demo:latest"}'
# {"deployment_id":"dep_…","status":"pending"}

# 5. run a tool call through the gatekeeper (or use the SDK's MCPClient)
#    allowed:
curl -s -X POST localhost:9000/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -H 'X-Tenant-Id: acme' -H 'X-Task-Id: deploy-staging' -H 'X-Agent-Id: a1' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"run_tests","arguments":{"suite":"unit"}}}'
#    denied (never reaches the tool server — error -32000 names the receipt):
curl -s -X POST localhost:9000/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -H 'X-Tenant-Id: acme' -H 'X-Task-Id: deploy-staging' -H 'X-Agent-Id: a1' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"delete_database","arguments":{"target":"prod"}}}'

# 6. read the receipts and verify the chain
curl -s "localhost:9001/v1/receipts?limit=10" -H "Authorization: Bearer $KEY"
curl -s "localhost:9001/v1/verify" -H "Authorization: Bearer $KEY"
# {"tenant_id":"acme","receipts":N,"chain_ok":true,"failures":[]}
```

Open the dashboard at `http://localhost:3000` (paste the API key once, or
set `DASHBOARD_API_KEY` to skip login) and click through the same receipts,
policies, and keys in the UI.

## With the SDKs

```python
from vouch import VouchClient
client = VouchClient(api_key="vouch_sk_…")
client.put_policy("deploy-staging", {...})          # step 3
dep = client.deploy_agent("deploy-staging", "vouch/agent-demo:latest")  # step 4
print(client.verify())                              # step 6
```

```js
import { VouchClient } from "@vouch/sdk";
const client = new VouchClient("vouch_sk_…");
await client.putPolicy("deploy-staging", {...});
console.log(await client.verify());
```

See `sdk/python/README.md` for the full surface.
