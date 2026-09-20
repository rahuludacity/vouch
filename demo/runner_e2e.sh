#!/bin/bash
# Phase 3 end-to-end: control-plane API -> runner -> agent -> gatekeeper ->
# receipts -> verify. (ARCHITECTURE.md §9, Phase 3 exit gate.)
#
# Docker is unavailable on this host, so the runner runs with
# RUNNER_DOCKER_FAKE=1: the "container" is demo/agent_sim.py spawned as a
# subprocess with exactly the env the sandbox spec would inject
# (GATEKEEPER_URL, VOUCH_TENANT_ID, VOUCH_TASK_ID, VOUCH_AGENT_ID).
# Everything below the docker call is real: the control plane, receipt
# service, gatekeeper, and upstream MCP server all run as real processes and
# speak the frozen §4 contracts.
#
# One command:  bash demo/runner_e2e.sh
#
# On a real docker host, replace step 5 with the real runner
# (`python3 -m services.runner.app`, no RUNNER_DOCKER_FAKE) and set
# GATEKEEPER_AGENT_URL to the gatekeeper as seen from the vouch-sandbox
# network (see docker-compose.yml).
set -e
cd "$(dirname "$0")/.."
REPO="$PWD"
TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMP"' EXIT

GK=9000 RC=9001 CP=9002 UP=9010

echo "=== 1. seed service tokens ==="
eval "$(python3 -m services.controlplane.seed_tokens --db "$TMP/cp.db" | grep -v '^#')"
# -> RECEIPT_SVC_TOKEN, RUNNER_TOKEN, GATEKEEPER_SVC_TOKEN, BILLING_SVC_TOKEN

echo "=== 2. start control plane, receipt service, gatekeeper, upstream ==="
CONTROLPLANE_PORT=$CP CONTROLPLANE_DB="$TMP/cp.db" \
  CONTROLPLANE_INVALIDATE_TOKEN="$GATEKEEPER_SVC_TOKEN" \
  python3 -m services.controlplane.app >"$TMP/cp.log" 2>&1 &
RECEIPT_PORT=$RC RECEIPT_DB="$TMP/rc.db" RECEIPT_SVC_TOKEN="$RECEIPT_SVC_TOKEN" \
  CONTROLPLANE_URL="http://127.0.0.1:$CP" CONTROLPLANE_SVC_TOKEN="$RECEIPT_SVC_TOKEN" \
  python3 -m services.receipts.app >"$TMP/rc.log" 2>&1 &
UPSTREAM_PORT=$UP python3 demo/upstream.py >"$TMP/up.log" 2>&1 &
GATEKEEPER_PORT=$GK GATEKEEPER_UPSTREAM="http://127.0.0.1:$UP/mcp" \
  GATEKEEPER_POLICY_PATH="$REPO/policy.yaml" \
  GATEKEEPER_RECEIPTS_PATH="$TMP/spool.jsonl" \
  RECEIPT_SVC_URL="http://127.0.0.1:$RC" RECEIPT_SVC_TOKEN="$RECEIPT_SVC_TOKEN" \
  RECEIPT_FLUSH_INTERVAL="1" \
  CONTROLPLANE_URL="http://127.0.0.1:$CP" GATEKEEPER_SVC_TOKEN="$GATEKEEPER_SVC_TOKEN" \
  POLICY_POLL_INTERVAL="5" \
  python3 -m gatekeeper.proxy >"$TMP/gk.log" 2>&1 &

wait_for() { # host port — every service must be listening before we proceed
  for _ in $(seq 1 30); do
    if (echo > /dev/tcp/$1/$2) 2>/dev/null; then return 0; fi
    sleep 1
  done
  echo "port $1:$2 never came up (see $TMP/*.log)" >&2
  return 1
}
wait_for 127.0.0.1 $CP
wait_for 127.0.0.1 $RC
wait_for 127.0.0.1 $UP
wait_for 127.0.0.1 $GK

echo "=== 3. create tenant + policy via API ==="
TENANT_JSON=$(curl -s -X POST "http://127.0.0.1:$CP/v1/tenants" \
  -H 'Content-Type: application/json' -d '{"name":"acme"}')
TID=$(python3 -c "import json,sys; print(json.load(sys.stdin)['tenant_id'])" <<<"$TENANT_JSON")
API_KEY=$(python3 -c "import json,sys; print(json.load(sys.stdin)['api_key'])" <<<"$TENANT_JSON")
echo "tenant: $TID"
curl -s -X PUT "http://127.0.0.1:$CP/v1/policies/deploy-staging" \
  -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' \
  -d '{"rules":{"allow":[{"rule_id":"read-ok","tool":"read_file"},{"rule_id":"tests-ok","tool":"run_tests"},{"rule_id":"staging-deploy","tool":"deploy_staging"}],"deny":[{"rule_id":"no-db-drop","tool":"delete_database"}]}}'
echo
# force the gatekeeper to pick up the new policy + key bundle now
curl -s -X POST "http://127.0.0.1:$GK/internal/cache/invalidate" \
  -H "Authorization: Bearer $GATEKEEPER_SVC_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$TID\"}"
echo

echo "=== 4. deploy the agent via API ==="
DEP_JSON=$(curl -s -X POST "http://127.0.0.1:$CP/v1/deployments" \
  -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' \
  -d '{"task_id":"deploy-staging","agent_image":"vouch/agent-demo:latest"}')
DEP_ID=$(python3 -c "import json,sys; print(json.load(sys.stdin)['deployment_id'])" <<<"$DEP_JSON")
echo "deployment: $DEP_ID"

echo "=== 5. runner reconciles (fake docker: agent runs as a subprocess) ==="
RUNNER_DOCKER_FAKE=1 \
CONTROLPLANE_URL="http://127.0.0.1:$CP" RUNNER_TOKEN="$RUNNER_TOKEN" \
GATEKEEPER_AGENT_URL="http://127.0.0.1:$GK/mcp" \
python3 -m services.runner.app --once

echo "=== 6. wait for the agent run, then verify ==="
sleep 8
echo "--- deployment status (control plane) ---"
curl -s "http://127.0.0.1:$CP/v1/deployments/$DEP_ID" \
  -H "Authorization: Bearer $API_KEY"
echo
echo "--- receipts (tenant API key, §4.6) ---"
curl -s "http://127.0.0.1:$RC/v1/receipts?limit=10" \
  -H "Authorization: Bearer $API_KEY" | python3 -c "
import json, sys
for r in json.load(sys.stdin)['items']:
    print(' ', r['seq'], r['decision'], r['tool'], r.get('rule_id'))
"
echo "--- chain verify (tenant API key) ---"
curl -s "http://127.0.0.1:$RC/v1/verify" -H "Authorization: Bearer $API_KEY"
echo
echo
echo "Done. The agent ran 'as a container', every tool call was gated by the"
echo "control-plane policy, and every decision has a signed receipt."
