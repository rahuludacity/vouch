#!/bin/bash
# Vouch 5-minute quickstart: boot the whole stack locally, provision a
# tenant, deploy an agent, watch it get gated, verify the receipt chain.
#
# Prereqs: python3, curl, `pip install pyyaml`. No Docker required — the
# runner uses its fake-docker backend (the agent runs as a subprocess with
# exactly the env the sandbox spec would inject).
#
# One command:  bash quickstart.sh
#
# Services: gatekeeper :9000, receipts :9001, control plane :9002,
#           dashboard :3000, billing :9004 (mock backend, test mode).
set -e
cd "$(dirname "$0")"
REPO="$PWD"
TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMP"' EXIT

GK=9000 RC=9001 CP=9002 UP=9010 DASH=3000 BILL=9004

echo "=== 1. seed service tokens ==="
eval "$(python3 -m services.controlplane.seed_tokens --db "$TMP/cp.db" | grep -v '^#')"
# -> RECEIPT_SVC_TOKEN, RUNNER_TOKEN, GATEKEEPER_SVC_TOKEN, BILLING_SVC_TOKEN

echo "=== 2. boot services ==="
CONTROLPLANE_PORT=$CP CONTROLPLANE_DB="$TMP/cp.db" \
  CONTROLPLANE_INVALIDATE_TOKEN="$GATEKEEPER_SVC_TOKEN" \
  RECEIPT_SVC_URL="http://127.0.0.1:$RC" \
  RECEIPT_FANIN_TOKEN="$RECEIPT_SVC_TOKEN" \
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
BILLING_PORT=$BILL BILLING_DB="$TMP/bill.db" \
  CONTROLPLANE_URL="http://127.0.0.1:$CP" BILLING_SVC_TOKEN="$BILLING_SVC_TOKEN" \
  RECEIPT_SVC_URL="http://127.0.0.1:$RC" RECEIPT_SVC_TOKEN="$RECEIPT_SVC_TOKEN" \
  python3 -m services.billing.app >"$TMP/bill.log" 2>&1 &

wait_for() { # every service must be listening before we proceed
  for _ in $(seq 1 30); do
    if (echo > /dev/tcp/127.0.0.1/$1) 2>/dev/null; then return 0; fi
    sleep 1
  done
  echo "port 127.0.0.1:$1 never came up (see $TMP/*.log)" >&2
  return 1
}
wait_for $CP; wait_for $RC; wait_for $UP; wait_for $GK; wait_for $BILL

echo "=== 3. provision a tenant + write a policy ==="
TENANT_JSON=$(curl -s -X POST "http://127.0.0.1:$CP/v1/tenants" \
  -H 'Content-Type: application/json' -d '{"name":"quickstart"}')
TID=$(python3 -c "import json,sys; print(json.load(sys.stdin)['tenant_id'])" <<<"$TENANT_JSON")
API_KEY=$(python3 -c "import json,sys; print(json.load(sys.stdin)['api_key'])" <<<"$TENANT_JSON")
echo "tenant: $TID   (api key shown once — save it: ${API_KEY:0:16}…)"
curl -s -X PUT "http://127.0.0.1:$CP/v1/policies/deploy-staging" \
  -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' \
  -d '{"rules":{"allow":[{"rule_id":"read-ok","tool":"read_file"},{"rule_id":"tests-ok","tool":"run_tests"},{"rule_id":"staging-ok","tool":"deploy_staging","args":{"build":{"regex":"^[0-9a-f]{6,40}$"}}}],"deny":[{"rule_id":"no-db-drop","tool":"delete_database"}]}}'
echo
curl -s -X POST "http://127.0.0.1:$GK/internal/cache/invalidate" \
  -H "Authorization: Bearer $GATEKEEPER_SVC_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$TID\"}" >/dev/null
echo

echo "=== 4. boot the dashboard (single-operator mode) ==="
DASHBOARD_PORT=$DASH CONTROLPLANE_URL="http://127.0.0.1:$CP" \
  RECEIPT_SVC_URL="http://127.0.0.1:$RC" DASHBOARD_API_KEY="$API_KEY" \
  python3 -m web.dashboard.app >"$TMP/dash.log" 2>&1 &
wait_for $DASH

echo "=== 5. deploy the agent ==="
DEP_JSON=$(curl -s -X POST "http://127.0.0.1:$CP/v1/deployments" \
  -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' \
  -d '{"task_id":"deploy-staging","agent_image":"vouch/agent-demo:latest"}')
DEP_ID=$(python3 -c "import json,sys; print(json.load(sys.stdin)['deployment_id'])" <<<"$DEP_JSON")
echo "deployment: $DEP_ID"

echo "=== 6. runner launches the agent (fake docker) ==="
RUNNER_DOCKER_FAKE=1 \
  CONTROLPLANE_URL="http://127.0.0.1:$CP" RUNNER_TOKEN="$RUNNER_TOKEN" \
  GATEKEEPER_AGENT_URL="http://127.0.0.1:$GK/mcp" \
  python3 -m services.runner.app --once >/dev/null

echo "=== 7. the run: allowed calls pass, the destructive call is blocked ==="
sleep 8
VOUCH_TENANT="$TID" VOUCH_TENANT_ID="$TID" \
  GATEKEEPER_URL="http://127.0.0.1:$GK/mcp" \
  VOUCH_TASK_ID="deploy-staging" VOUCH_AGENT_ID="agent-quickstart" \
  python3 demo/agent_sim.py 2>&1 | grep -v "^  connected" | head -12

echo
echo "=== 8. receipts + chain verification ==="
curl -s "http://127.0.0.1:$RC/v1/receipts?limit=10" \
  -H "Authorization: Bearer $API_KEY" | python3 -c "
import json, sys
for r in json.load(sys.stdin)['items']:
    print('  seq', r['seq'], r['decision'].upper(), r['tool'], '->', r.get('rule_id'))
"
echo "--- verify ---"
curl -s "http://127.0.0.1:$RC/v1/verify" -H "Authorization: Bearer $API_KEY"
echo
echo "--- usage fan-in on /v1/tenants/me ---"
curl -s "http://127.0.0.1:$CP/v1/tenants/me" -H "Authorization: Bearer $API_KEY"
echo
echo
echo "Done. Every decision above has a signed, tamper-evident receipt."
echo "Dashboard: http://127.0.0.1:$DASH  (overview / receipts / policies / keys)"
echo "Next: docs/quickstart.md walks the same flow by hand; sdk/python and"
echo "sdk/js wrap every API used above."
