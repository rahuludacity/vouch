#!/bin/bash
# End-to-end demo: upstream MCP server + vouch gatekeeper + simulated agent.
# The gatekeeper speaks real MCP Streamable HTTP; every policy decision is
# receipted under the "demo" tenant's own HMAC key.
set -e
cd "$(dirname "$0")/.."
rm -f receipts.jsonl tenants.json

echo "--- tenant setup ---"
python3 -m gatekeeper.tenants create demo

python3 demo/upstream.py & UP=$!
python3 -m gatekeeper.proxy & PX=$!
sleep 1

echo "================ DEMO ================"
VOUCH_TENANT=demo python3 demo/agent_sim.py
echo
echo "=========== RECEIPT LEDGER ==========="
cat receipts.jsonl
echo
echo "============= VERIFY ================="
python3 -m gatekeeper.verify

kill $UP $PX 2>/dev/null || true
echo
echo "Done. The destructive call never reached the tool server."
echo "Every decision above has a signed, tamper-evident receipt in receipts.jsonl,"
echo "each signed with the demo tenant's own key (see tenants.json)."
