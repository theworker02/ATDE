#Requires -Version 5
# One-shot local ATDE bring-up for Windows (NATS + build + doctor + hints).
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

Write-Host "== ATDE quickstart ==" -ForegroundColor Cyan

if (-not (Test-Path .env)) {
  Copy-Item .env.example .env
  Write-Host "Created .env from .env.example"
}

Write-Host "`n[1/4] NATS"
docker compose -f deployments/docker-compose.yml up -d nats

Write-Host "`n[2/4] Build"
go build -o bin/atde.exe ./cmd/atde

Write-Host "`n[3/4] Doctor"
$env:NATS_URL = if ($env:NATS_URL) { $env:NATS_URL } else { "nats://127.0.0.1:4222" }
.\bin\atde.exe -config configs\config.yaml -mode doctor
$docExit = $LASTEXITCODE

Write-Host "`n[4/4] Next steps" -ForegroundColor Green
Write-Host "  `$env:ATDE_LIVE=1; `$env:NATS_URL='nats://127.0.0.1:4222'"
Write-Host "  .\bin\atde.exe -config configs\config.yaml -mode all"
Write-Host "  Console:  http://127.0.0.1:9091/console"
Write-Host "  Demo HP:  .\scripts\demo-honeypot.ps1"
Write-Host "  Caught:   .\bin\atde.exe -mode caught"
Write-Host "  Export:   .\bin\atde.exe -mode export -ip <IP>"
Write-Host "  Watch:    .\bin\atde.exe -mode watch"
if ($docExit -ne 0) {
  Write-Host "`nDoctor reported failures — fix NATS/ports before going live." -ForegroundColor Yellow
  exit $docExit
}
