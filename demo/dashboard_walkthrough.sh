#!/bin/bash
# Phase 4 walkthrough: control plane + receipt service + dashboard, with
# fake-but-valid data (signed receipts minted with the tenant's real HMAC
# key), exercising the dashboard's screens and JSON APIs end to end.
#
# One command:  bash demo/dashboard_walkthrough.sh
# Then open http://127.0.0.1:3000/overview in a browser
# (DASHBOARD_API_KEY is set below, so the demo skips the login screen).
set -e
cd "$(dirname "$0")/.."
REPO="$PWD"
TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMP"' EXIT

CP=9002 RC=9001 DASH=3000

echo "=== 1. seed service tokens ==="
eval "$(python3 -m services.controlplane.seed_tokens --db "$TMP/cp.db" | grep -v '^#')"
# -> RECEIPT_SVC_TOKEN (others unused here)

echo "=== 2. start control plane, receipt service, dashboard ==="
CONTROLPLANE_PORT=$CP CONTROLPLANE_DB="$TMP/cp.db" \
RECEIPT_SVC_URL="http://127.0.0.1:$RC" RECEIPT_FANIN_TOKEN="$RECEIPT_SVC_TOKEN" \
  python3 -m services.controlplane.app >"$TMP/cp.log" 2>&1 &
RECEIPT_PORT=$RC RECEIPT_DB="$TMP/rc.db" RECEIPT_SVC_TOKEN="$RECEIPT_SVC_TOKEN" \
CONTROLPLANE_URL="http://127.0.0.1:$CP" CONTROLPLANE_SVC_TOKEN="$RECEIPT_SVC_TOKEN" \
  python3 -m services.receipts.app >"$TMP/rc.log" 2>&1 &
sleep 1

echo "=== 3. provision tenant + policy + deployment ==="
OUT=$(curl -sf -X POST http://127.0.0.1:$CP/v1/tenants \
  -H 'Content-Type: application/json' -d '{"name":"Walkthrough Inc"}')
TENANT=$(python3 -c "import json,sys; print(json.load(sys.stdin)['tenant_id'])" <<<"$OUT")
API_KEY=$(python3 -c "import json,sys; print(json.load(sys.stdin)['api_key'])" <<<"$OUT")
echo "tenant: $TENANT"
AUTH=(-H "Authorization: Bearer $API_KEY")
curl -sf -X PUT http://127.0.0.1:$CP/v1/policies/deploy-demo \
  -H 'Content-Type: application/json' "${AUTH[@]}" \
  -d '{"rules":{"allow":[{"rule_id":"read-workspace","tool":"read_file","args":{"path":{"prefix":"/workspace/"}}}],"deny":[{"rule_id":"no-destructive","tool":"delete_database"}]}}' > /dev/null
curl -sf -X POST http://127.0.0.1:$CP/v1/deployments \
  -H 'Content-Type: application/json' "${AUTH[@]}" \
  -d '{"task_id":"deploy-demo","agent_image":"vouch/agent-demo:latest"}' > /dev/null
curl -sf -X POST http://127.0.0.1:$CP/v1/api-keys \
  -H 'Content-Type: application/json' "${AUTH[@]}" \
  -d '{"name":"ci"}' > /dev/null
echo "policy, deployment, named API key created"

echo "=== 4. mint signed receipts (real HMAC, real chain) ==="
python3 - "$TMP/cp.db" "$TENANT" "$RECEIPT_SVC_TOKEN" "$RC" <<'EOF'
import hashlib, hmac, json, sqlite3, sys, time, urllib.request
cp_db, tenant_id, svc_token, rc_port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
con = sqlite3.connect(cp_db)
kid, key_hex = con.execute(
    "SELECT kid, key_hex FROM tenant_keys WHERE tenant_id=? AND is_current=1",
    (tenant_id,)).fetchone()
con.close()
key = bytes.fromhex(key_hex)
prev = "GENESIS"
calls = [("read_file", "allow", "read-workspace", {"path": "/workspace/a.txt"}),
         ("delete_database", "deny", "no-destructive", {}),
         ("read_file", "allow", "read-workspace", {"path": "/workspace/b.txt"}),
         ("deploy_staging", "deny", None, {"env": "prod"})]
for i, (tool, decision, rule_id, args) in enumerate(calls, start=1):
    body = {"seq": i, "ts": round(time.time(), 3), "tenant_id": tenant_id,
            "kid": kid, "task_id": "deploy-demo", "agent_id": "agent-demo",
            "tool": tool,
            "args_sha256": hashlib.sha256(
                json.dumps(args, sort_keys=True).encode()).hexdigest(),
            "decision": decision, "reason": None, "rule_id": rule_id,
            "policy_version": 1, "prev_hash": prev}
    body["hash"] = hashlib.sha256(
        prev.encode() + json.dumps(body, sort_keys=True).encode()).hexdigest()
    body["sig"] = hmac.new(
        key, json.dumps(body, sort_keys=True).encode(),
        hashlib.sha256).hexdigest()
    prev = body["hash"]
    req = urllib.request.Request(
        f"http://127.0.0.1:{rc_port}/v1/ingest",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {svc_token}"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        assert r.status == 201, r.status
print(f"ingested {len(calls)} receipts for {tenant_id}")
EOF

echo "=== 5. start dashboard (operator mode: login skipped) ==="
DASHBOARD_PORT=$DASH CONTROLPLANE_URL="http://127.0.0.1:$CP" \
RECEIPT_SVC_URL="http://127.0.0.1:$RC" DASHBOARD_API_KEY="$API_KEY" \
  python3 -m web.dashboard.app >"$TMP/dash.log" 2>&1 &
for _ in $(seq 1 50); do
  curl -sf http://127.0.0.1:$DASH/login >/dev/null 2>&1 && break
  sleep 0.2
done

echo "=== 6. exercise screens + JSON APIs ==="
check() { # check <desc> <url> <must-contain>
  body=$(curl -sf "$2")
  case "$body" in *"$3"*) echo "ok   $1";; *)
    echo "FAIL $1 (missing '$3')"; exit 1;; esac
}
check "overview page"        http://127.0.0.1:$DASH/overview "Walkthrough"
check "receipts page"        http://127.0.0.1:$DASH/receipts "delete_database"
check "receipts verify page" "http://127.0.0.1:$DASH/receipts?verify=1" "Chain intact"
check "policies page"        http://127.0.0.1:$DASH/policies "no-destructive"
check "deployments page"     http://127.0.0.1:$DASH/deployments "agent-demo"
check "keys page"            http://127.0.0.1:$DASH/keys "ci"
check "receipt detail page"  http://127.0.0.1:$DASH/receipts/2 "delete_database"

jcheck() { # jcheck <desc> <url> <jq-ish python expr> <expected>
  val=$(curl -sf "$2" | python3 -c "import json,sys; d=json.load(sys.stdin); print($3)")
  if [ "$val" = "$4" ]; then echo "ok   $1"; else echo "FAIL $1: got '$val' want '$4'"; exit 1; fi
}
jcheck "api overview tenant"  http://127.0.0.1:$DASH/api/overview "d['tenant']['tenant_id']" "$TENANT"
jcheck "api overview usage"   http://127.0.0.1:$DASH/api/overview "d['usage']['actions_denied']" "2"
jcheck "api receipts count"   "http://127.0.0.1:$DASH/api/receipts?limit=50" "len(d['items'])" "4"
jcheck "api receipts filter"  "http://127.0.0.1:$DASH/api/receipts?decision=deny" "len(d['items'])" "2"
jcheck "api verify chain_ok"  http://127.0.0.1:$DASH/api/verify "d['chain_ok']" "True"
jcheck "api policies"         http://127.0.0.1:$DASH/api/policies "sorted(d['tasks'])" "['deploy-demo']"

echo "=== 7. live feed (SSE backlog replay) ==="
timeout 8 curl -sN http://127.0.0.1:$DASH/api/receipts/stream | head -c 400 | grep -q "event: receipt" \
  && echo "ok   sse stream relays receipt events" \
  || { echo "FAIL sse stream"; exit 1; }

echo
echo "WALKTHROUGH COMPLETE — dashboard live at http://127.0.0.1:$DASH/overview"
echo "(this script tears the services down on exit; re-run to explore)"
