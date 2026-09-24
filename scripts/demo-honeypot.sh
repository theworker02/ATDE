#!/usr/bin/env bash
# Demo the Atlas honeypot portal (HTTP must already be listening on :8080).
set -euo pipefail
BASE="${ATDE_HONEYPOT_URL:-http://127.0.0.1:8080}"
BASE="${BASE%/}"

hit() {
  echo
  echo "=== $1 ==="
  echo "GET $2"
  curl -sS -m 15 -D - "$2" -o /tmp/atde-hp.out | head -n 8 || true
  head -c 280 /tmp/atde-hp.out 2>/dev/null; echo
}

hit "Landing" "$BASE/"
hit "OpenAPI" "$BASE/openapi.json"
hit "Env canary" "$BASE/.env"
hit "security.txt" "$BASE/.well-known/security.txt"
hit "Synthetic RCE" "$BASE/api/v1/debug?cmd=id"
hit "Admin API (401)" "$BASE/api/v1/admin/users"

echo
echo "=== Impossible login ==="
curl -sS -m 20 -X POST "$BASE/login" -d 'username=admin&password=admin' | head -c 400
echo
echo
echo "Done. Review: go run ./cmd/atde -mode caught"
