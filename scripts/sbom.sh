#!/usr/bin/env bash
# Generate a lightweight SBOM-ish inventory for diligence (no Syft required).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist/sbom-lite.txt}"
mkdir -p "$(dirname "$OUT")"
{
  echo "# ATDE SBOM-lite"
  echo "# generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# version: $(cat "$ROOT/VERSION" 2>/dev/null || echo unknown)"
  echo
  echo "## Go module"
  (cd "$ROOT" && go list -m all)
  echo
  echo "## Packages"
  (cd "$ROOT" && go list ./...)
  echo
  echo "## Approximate LOC (Go)"
  (cd "$ROOT" && find . -name '*.go' -not -path './vendor/*' | xargs wc -l 2>/dev/null | tail -n 1 || true)
} >"$OUT"
echo "wrote $OUT"
