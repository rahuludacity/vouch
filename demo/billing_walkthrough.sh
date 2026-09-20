#!/bin/bash
# Phase 5 walkthrough: control plane + receipt service + billing (mock Stripe
# backend — no Stripe key, no real charges, fully offline).
#
#   bash demo/billing_walkthrough.sh
#
# Beats: provision a tenant (Free) -> mock checkout to Pro -> signed webhook
# flips the plan on the control plane -> burn the (demo-shrunk) quota ->
# reconcile suspends the tenant -> cancel via signed webhook -> back to Free
# -> new month -> reconcile lifts billing's own suspension.
set -e
cd "$(dirname "$0")/.."
TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMP"' EXIT

CP=9002 RC=9001 BILL=9004

echo "=== 1. seed service tokens ==="
eval "$(python3 -m services.controlplane.seed_tokens --db "$TMP/cp.db" | grep -v '^#')"
# -> RECEIPT_SVC_TOKEN, BILLING_SVC_TOKEN

echo "=== 2. start control plane, receipt service, billing (mock, offline) ==="
CONTROLPLANE_PORT=$CP CONTROLPLANE_DB="$TMP/cp.db" \
RECEIPT_SVC_URL="http://127.0.0.1:$RC" RECEIPT_FANIN_TOKEN="$RECEIPT_SVC_TOKEN" \
  python3 -m services.controlplane.app >"$TMP/cp.log" 2>&1 &
RECEIPT_PORT=$RC RECEIPT_DB="$TMP/rc.db" RECEIPT_SVC_TOKEN="$RECEIPT_SVC_TOKEN" \
CONTROLPLANE_URL="http://127.0.0.1:$CP" CONTROLPLANE_SVC_TOKEN="$RECEIPT_SVC_TOKEN" \
  python3 -m services.receipts.app >"$TMP/rc.log" 2>&1 &
BILLING_PORT=$BILL BILLING_DB="$TMP/bill.db" \
CONTROLPLANE_URL="http://127.0.0.1:$CP" BILLING_SVC_TOKEN="$BILLING_SVC_TOKEN" \
RECEIPT_SVC_URL="http://127.0.0.1:$RC" RECEIPT_SVC_TOKEN="$RECEIPT_SVC_TOKEN" \
BILLING_QUOTA_FREE=3 BILLING_QUOTA_PRO=5 \
  python3 -m services.billing.app >"$TMP/bill.log" 2>&1 &
sleep 1
for i in $(seq 1 25); do
  curl -sf "http://127.0.0.1:$RC/v1/health" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -sf -H "Authorization: Bearer <redacted>" \
  "http://127.0.0.1:$CP/v1/tenants/me" >/dev/null 2>&1 || true
curl -sf -H "Authorization: Bearer <redacted>" \
  "http://127.0.0.1:$BILL/v1/billing/subscription" >/dev/null 2>&1 || true
echo "all three services up"

echo "=== 3. provision tenant (lands on Free) ==="
OUT=$(curl -sf -X POST http://127.0.0.1:$CP/v1/tenants \
  -H 'Content-Type: application/json' -d '{"name":"Billing Demo Inc"}')
TENANT=$(python3 -c "import json,sys; print(json.load(sys.stdin)['tenant_id'])" <<<"$OUT")
API_KEY=$(python3 -c "import json,sys; print(json.load(sys.stdin)['api_key'])" <<<"$OUT")
AUTH=(-H "Authorization: Bearer $API_KEY")
SVC=(-H "Authorization: Bearer $BILLING_SVC_TOKEN")
ME=$(curl -sf http://127.0.0.1:$CP/v1/tenants/me "${AUTH[@]}")
python3 -c "import json,sys; m=json.load(sys.stdin); print('plan:', m['plan'], '| status:', m['status'])" <<<"$ME"

echo "=== 4. start a Pro checkout (mock — no real charge) ==="
OUT=$(curl -sf -X POST http://127.0.0.1:$BILL/v1/billing/checkout \
  -H 'Content-Type: application/json' "${AUTH[@]}" -d '{"plan":"pro"}')
SID=$(python3 -c "import json,sys; print(json.load(sys.stdin)['session_id'])" <<<"$OUT")
python3 -c "import json,sys; d=json.load(sys.stdin); print('checkout_url:', d['checkout_url'], '| test_mode:', d['test_mode'])" <<<"$OUT"

echo "=== 5. customer pays (mock) -> signed webhook -> plan flips to Pro ==="
curl -sf -X POST "http://127.0.0.1:$BILL/v1/billing/mock-checkout/$SID/complete" \
  "${AUTH[@]}" >/dev/null
ME=$(curl -sf http://127.0.0.1:$CP/v1/tenants/me "${AUTH[@]}")
python3 -c "import json,sys; m=json.load(sys.stdin); print('plan:', m['plan'], '| status:', m['status'])" <<<"$ME"
SUB=$(curl -sf http://127.0.0.1:$BILL/v1/billing/subscription "${AUTH[@]}")
python3 -c "
import json,sys
s=json.load(sys.stdin)
print('subscription view: plan', s['plan'],
      '| quota:', s['quota_actions_per_month'],
      '| actions this month:', s['actions_this_month'])" <<<"$SUB"

echo "=== 6. burn quota (6 actions, demo quota is 5) -> reconcile suspends ==="
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
for seq in range(1, 7):
    body = {"seq": seq, "ts": round(time.time(), 3), "tenant_id": tenant_id,
            "kid": kid, "task_id": "billing-demo", "agent_id": "demo",
            "tool": "read_file",
            "args_sha256": hashlib.sha256(b"{}").hexdigest(),
            "decision": "allow", "reason": None, "rule_id": None,
            "policy_version": 1, "prev_hash": prev}
    body["hash"] = hashlib.sha256(
        prev.encode() + json.dumps(body, sort_keys=True).encode()).hexdigest()
    prev = body["hash"]
    body["sig"] = hmac.new(
        key, json.dumps(body, sort_keys=True).encode(),
        hashlib.sha256).hexdigest()
    req = urllib.request.Request(f"http://127.0.0.1:{rc_port}/v1/ingest",
                                 data=json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {svc_token}",
                                          "Content-Type": "application/json"})
    urllib.request.urlopen(req).read()
print("ingested 6 signed receipts")
EOF
OUT=$(curl -sf -X POST http://127.0.0.1:$BILL/internal/billing/reconcile \
  -H 'Content-Type: application/json' "${SVC[@]}" -d '{}')
python3 -c "
import json,sys
for t in json.load(sys.stdin)['tenants']:
    print('reconcile:', t['tenant_id'][:8], '->', t['action'],
          f\"({t.get('actions')}/{t.get('quota')} actions)\")" <<<"$OUT"
ME=$(curl -sf http://127.0.0.1:$CP/v1/tenants/me "${AUTH[@]}")
python3 -c "
import json,sys
m=json.load(sys.stdin)
print('tenant now:', m['plan'], '/', m['status'],
      '(gatekeeper enforces deny-all from the key-bundle status, §4.3)')" <<<"$ME"

echo "=== 7. customer cancels -> signed subscription.deleted -> back to Free ==="
SUB_ID=$(python3 -c "import json,sys; print(json.load(sys.stdin)['subscription']['stripe_subscription_id'])" <<<"$SUB")
python3 - "$SUB_ID" "$TENANT" <<'EOF'
import hashlib, hmac, json, sys, time, urllib.request
sub_id, tenant_id = sys.argv[1], sys.argv[2]
secret = "whsec_test_mock_do_not_use_in_prod"  # mock backend default
event = {"id": f"evt_demo_cancel_{int(time.time())}",
         "type": "customer.subscription.deleted",
         "data": {"object": {"id": sub_id, "status": "canceled",
                             "metadata": {"tenant_id": tenant_id,
                                          "plan": "pro"}}}}
payload = json.dumps(event).encode()
ts = str(int(time.time()))
mac = hmac.new(secret.encode(), f"{ts}.".encode() + payload,
               hashlib.sha256).hexdigest()
req = urllib.request.Request("http://127.0.0.1:9004/v1/stripe/webhook",
                             data=payload, method="POST",
                             headers={"Content-Type": "application/json",
                                      "Stripe-Signature": f"t={ts},v1={mac}"})
print("webhook:", urllib.request.urlopen(req).read().decode())
EOF
ME=$(curl -sf http://127.0.0.1:$CP/v1/tenants/me "${AUTH[@]}")
python3 -c "import json,sys; m=json.load(sys.stdin); print('plan:', m['plan'], '| status:', m['status'])" <<<"$ME"

echo "=== 8. new month (usage reset) -> reconcile lifts billing's suspension ==="
python3 - "$TMP/rc.db" "$TENANT" <<'EOF'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("DELETE FROM usage_monthly WHERE tenant_id=?", (sys.argv[2],))
con.commit(); con.close()
print("usage reset")
EOF
OUT=$(curl -sf -X POST http://127.0.0.1:$BILL/internal/billing/reconcile \
  -H 'Content-Type: application/json' "${SVC[@]}" -d '{}')
python3 -c "
import json,sys
for t in json.load(sys.stdin)['tenants']:
    print('reconcile:', t['tenant_id'][:8], '->', t['action'])" <<<"$OUT"
ME=$(curl -sf http://127.0.0.1:$CP/v1/tenants/me "${AUTH[@]}")
python3 -c "import json,sys; m=json.load(sys.stdin); print('plan:', m['plan'], '| status:', m['status'])" <<<"$ME"

echo
echo "BILLING WALKTHROUGH: ALL GREEN (mock backend — no real charges)"
