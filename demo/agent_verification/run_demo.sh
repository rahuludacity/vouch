#!/bin/bash
# Vouch agent-verification demo: the three-lane verified-agent gateway.
#
# Story: the Smallville Permit Office form page. A legitimate agent with a
# signed credential chain sails through the verified-agent lane (fast
# passage + a signed, hash-chained receipt in the transparency log), human
# traffic passes unchanged, and a credential-less bot swarm gets the
# status-quo challenge path. "Verify the agent, don't detect the bot."
#
# Prereqs: python3. No Docker, no network beyond localhost, no cloud.
# One command:  bash demo/agent_verification/run_demo.sh
set -e
cd "$(dirname "$0")/../.."
REPO="$PWD"
TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMP"' EXIT
export DEMO_TMP="$TMP"

VP=9005 SP=9011
export SITE_URL="http://127.0.0.1:$SP"

echo "=== 1. setup: keys, credential chain, tenant ==="
python3 demo/agent_verification/setup.py
# shellcheck disable=SC1091
source "$TMP/env.sh"

echo "=== 2. boot verifier (:$VP) + demo site (:$SP) ==="
VERIFIER_PORT=$VP \
VERIFIER_TENANTS_PATH="$TMP/tenants.json" \
VERIFIER_RECEIPTS_PATH="$TMP/transparency.jsonl" \
RECEIPT_SVC_URL="" \
  python3 -m services.verifier.app >"$TMP/verifier.log" 2>&1 &
SITE_PORT=$SP VERIFIER_URL="http://127.0.0.1:$VP" \
SITE_SUBMISSIONS_PATH="$TMP/submissions.jsonl" \
  python3 demo/agent_verification/site.py >"$TMP/site.log" 2>&1 &

for i in $(seq 1 50); do
  curl -sf "http://127.0.0.1:$VP/v1/health" >/dev/null 2>&1 \
    && curl -sf "http://127.0.0.1:$SP/" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -sf "http://127.0.0.1:$VP/v1/health" >/dev/null \
  || { echo "verifier failed to boot"; cat "$TMP/verifier.log"; exit 1; }

echo
echo "=== 3. human lane: plain form post, no credential, unchanged ==="
curl -s -X POST "http://127.0.0.1:$SP/submit" \
  --data-urlencode "name=Ada Lovelace" --data-urlencode "permit=shed" \
  | grep -o "human lane" | head -1
echo "   -> accepted via human lane (verifier never consulted)"

echo
echo "=== 4. verified-agent lane: signed credential chain ==="
python3 demo/agent_verification/agents.py good

echo
echo "=== 5. unverified lane: forged credential -> denied, challenged ==="
python3 demo/agent_verification/agents.py forged

echo
echo "=== 6. unverified lane: credential-less bot swarm -> challenged ==="
python3 demo/agent_verification/agents.py swarm 12

echo
echo "=== 7. lane counters ==="
curl -s "http://127.0.0.1:$SP/stats"; echo

echo
echo "=== 8. transparency log: every verified-agent action receipted ==="
GATEKEEPER_TENANTS_PATH="$TMP/tenants.json" \
GATEKEEPER_RECEIPTS_PATH="$TMP/transparency.jsonl" \
  python3 -m gatekeeper.verify
echo "--- receipts (seq/decision/agent/tool) ---"
python3 - "$TMP/transparency.jsonl" <<'EOF'
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(line)
    args = r.get("reason", "")
    print(f"seq={r['seq']} decision={r['decision']:5} agent={r['agent_id']} tool={r['tool']}")
EOF

echo
echo "DEMO COMPLETE: verified agent sailed through with receipts;"
echo "humans passed unchanged; the bot swarm never reached the form."
