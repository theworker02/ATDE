#Requires -Version 5
# Deploy ATDE catch-node with Docker (Windows host or remote instructions).
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

if (-not (Test-Path .env)) {
  Copy-Item .env.example .env
  Write-Host "Created .env — set ATDE_OPS_TOKEN before exposing port 9091."
}

Write-Host "== Building & starting catch-node ==" -ForegroundColor Cyan
docker compose -f deployments/catch-node.yml up -d --build

Write-Host ""
Write-Host "Open inbound TCP 8080, 2222, 6379, 2323, 8443 publicly." -ForegroundColor Green
Write-Host "Keep 9091 private (your IP only)."
Write-Host ""
Write-Host "Review:  http://127.0.0.1:9091/console"
Write-Host "Verify:  .\scripts\verify-catch.ps1"
Write-Host "CLI:     docker compose -f deployments/catch-node.yml exec atde /app/atde -mode caught"
Write-Host "Guide:   docs/CATCH.md"
