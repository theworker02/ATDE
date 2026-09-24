#!/usr/bin/env bash
# Deploy ATDE catch-node on this host (Linux VPS with Docker).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env — set ATDE_OPS_TOKEN before exposing port 9091."
fi

echo "== Building & starting catch-node =="
docker compose -f deployments/catch-node.yml up -d --build

IP="$(curl -4 -sS --max-time 3 ifconfig.me 2>/dev/null || curl -4 -sS --max-time 3 icanhazip.com 2>/dev/null || echo YOUR_PUBLIC_IP)"

echo
echo "Bait URLs (open these ports in your cloud firewall / ufw):"
echo "  HTTP   http://${IP}:8080/"
echo "  SSH    ${IP}:2222"
echo "  Redis  ${IP}:6379"
echo "  Telnet ${IP}:2323"
echo "  API    http://${IP}:8443/"
echo
echo "Review recorded attacks:"
echo "  Console  http://${IP}:9091/console"
echo "  Verify   bash scripts/verify-catch.sh"
echo "  CLI      docker compose -f deployments/catch-node.yml exec atde /app/atde -mode caught"
echo
echo "Full playbook: docs/CATCH.md"
