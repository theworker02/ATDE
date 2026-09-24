#!/usr/bin/env bash
# One-shot local ATDE bring-up (NATS + build + doctor + hints).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== ATDE quickstart =="

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

echo
echo "[1/4] NATS"
docker compose -f deployments/docker-compose.yml up -d nats

echo
echo "[2/4] Build"
mkdir -p bin
go build -o "bin/atde" ./cmd/atde

echo
echo "[3/4] Doctor"
export NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
set +e
./bin/atde -config configs/config.yaml -mode doctor
DOC=$?
set -e

echo
echo "[4/4] Next steps"
echo "  export ATDE_LIVE=1 NATS_URL=nats://127.0.0.1:4222"
echo "  ./bin/atde -config configs/config.yaml -mode all"
echo "  Console:  http://127.0.0.1:9091/console"
echo "  Demo HP:  bash scripts/demo-honeypot.sh"
echo "  Caught:   ./bin/atde -mode caught"
echo "  Export:   ./bin/atde -mode export -ip <IP>"
echo "  Watch:    ./bin/atde -mode watch"
exit "$DOC"
