#!/usr/bin/env bash
# Production hardened build (Linux/macOS). Requires: go install mvdan.cc/garble@latest
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p bin
SIG="$(git rev-parse HEAD 2>/dev/null || echo dev)"
export CGO_ENABLED=0
HASH=""
if command -v garble >/dev/null 2>&1; then
  echo "Building with garble (-literals -tiny)..."
  garble -literals -tiny -seed=random build \
    -ldflags="-s -w -X github.com/theworker02/blind-botnet/internal/harden.BuildSignature=${SIG}" \
    -o bin/atde_hardened ./cmd/atde
else
  echo "garble not found; falling back to stripped go build"
  go build -ldflags="-s -w -X github.com/theworker02/blind-botnet/internal/harden.BuildSignature=${SIG}" \
    -o bin/atde_hardened ./cmd/atde
fi
if command -v sha256sum >/dev/null 2>&1; then
  HASH="$(sha256sum bin/atde_hardened | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  HASH="$(shasum -a 256 bin/atde_hardened | awk '{print $1}')"
fi
if [[ -n "${HASH}" ]]; then
  echo "Re-linking with ExpectedBinaryHash=${HASH}"
  if command -v garble >/dev/null 2>&1; then
    garble -literals -tiny -seed=random build \
      -ldflags="-s -w -X github.com/theworker02/blind-botnet/internal/harden.BuildSignature=${SIG} -X github.com/theworker02/blind-botnet/internal/harden.ExpectedBinaryHash=${HASH}" \
      -o bin/atde_hardened ./cmd/atde
  else
    go build \
      -ldflags="-s -w -X github.com/theworker02/blind-botnet/internal/harden.BuildSignature=${SIG} -X github.com/theworker02/blind-botnet/internal/harden.ExpectedBinaryHash=${HASH}" \
      -o bin/atde_hardened ./cmd/atde
  fi
fi
echo "OK -> bin/atde_hardened"
