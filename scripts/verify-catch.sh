#!/usr/bin/env bash
# Prove the catch pipeline records a simulated attack end-to-end.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BASE="${ATDE_HONEYPOT_URL:-http://127.0.0.1:8080}"
OPS="${ATDE_OPS_URL:-http://127.0.0.1:9091}"
TOKEN="${ATDE_OPS_TOKEN:-}"

echo "== verify-catch against $BASE =="

curl -fsS -o /dev/null -w "landing %{http_code}\n" "$BASE/" || { echo "honeypot not up — start catch-node first"; exit 1; }
curl -fsS -o /dev/null -X POST "$BASE/login" -d 'username=verify&password=catch-me' -w "login %{http_code}\n"
curl -fsS -o /dev/null "$BASE/.env" -w "envbait %{http_code}\n"
curl -fsS -o /dev/null "$BASE/api/v1/debug?cmd=id" -w "rcebait %{http_code}\n"

Q=""
HDR=()
if [[ -n "$TOKEN" ]]; then
  Q="?token=$(python -c "import urllib.parse,os;print(urllib.parse.quote(os.environ['ATDE_OPS_TOKEN']))" 2>/dev/null || echo "$TOKEN")"
  HDR=(-H "X-ATDE-Token: $TOKEN")
fi

echo
echo "== ledger via console API =="
curl -fsS "${HDR[@]}" "$OPS/v1/summary${Q}" | head -c 800
echo
echo
echo "Open console: $OPS/console${Q}"
echo "OK — if hits/unique_ips increased, recording works."
