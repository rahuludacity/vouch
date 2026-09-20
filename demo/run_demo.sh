#!/bin/bash
# End-to-end demo: upstream tool server + gatekeeper + simulated agent + verification.
set -e
cd "$(dirname "$0")/.."
rm -f receipts.jsonl

python3 demo/upstream.py & UP=$!
python3 gatekeeper/proxy.py & PX=$!
sleep 1

echo "================ DEMO ================"
python3 demo/agent_sim.py
echo
echo "=========== RECEIPT LEDGER ==========="
cat receipts.jsonl
echo
echo "============= VERIFY ================="
python3 gatekeeper/verify.py

kill $UP $PX 2>/dev/null || true
echo
echo "Done. The destructive call never reached the tool server."
echo "Every decision above has a signed, tamper-evident receipt in receipts.jsonl."
