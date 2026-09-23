#!/bin/bash
# Runs ON the Vouch EC2 box via SSM. Pulls main, redeploys, verifies.
set -e
echo "=== pre-deploy ==="
cd /opt/vouch
echo "before: $(git rev-parse HEAD)"
git fetch origin main
git checkout -q main
git pull --ff-only origin main
echo "after:  $(git rev-parse HEAD)"
echo "=== deploy ==="
bash /opt/vouch/deploy.sh
echo "=== containers ==="
(docker compose ps 2>/dev/null || docker ps) | head -20
echo "=== port check ==="
(ss -tlnp 2>/dev/null | grep -E ':(9005|9011) ' || echo "ports 9005/9011 free")
echo "=== demo endpoint ==="
curl -sk -o /dev/null -w "GET /demo -> %{http_code}\n" https://localhost/demo
