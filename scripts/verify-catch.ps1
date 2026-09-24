#Requires -Version 5
# Prove the catch pipeline records a simulated attack end-to-end.
$ErrorActionPreference = "Stop"
$Base = if ($env:ATDE_HONEYPOT_URL) { $env:ATDE_HONEYPOT_URL.TrimEnd("/") } else { "http://127.0.0.1:8080" }
$Ops  = if ($env:ATDE_OPS_URL) { $env:ATDE_OPS_URL.TrimEnd("/") } else { "http://127.0.0.1:9091" }
$Token = $env:ATDE_OPS_TOKEN

Write-Host "== verify-catch against $Base ==" -ForegroundColor Cyan

function Hit($name, $url, $method = "GET", $body = $null) {
  try {
    if ($method -eq "POST") {
      $r = Invoke-WebRequest -Uri $url -Method POST -Body $body -UseBasicParsing -TimeoutSec 20
    } else {
      $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15
    }
    Write-Host "$name $($r.StatusCode)"
  } catch {
    Write-Host "$name FAILED: $($_.Exception.Message)" -ForegroundColor Yellow
    throw
  }
}

Hit "landing" "$Base/"
Hit "login" "$Base/login" "POST" @{ username = "verify"; password = "catch-me" }
Hit "envbait" "$Base/.env"
Hit "rcebait" "$Base/api/v1/debug?cmd=id"

$headers = @{}
$q = ""
if ($Token) {
  $headers["X-ATDE-Token"] = $Token
  $q = "?token=$([uri]::EscapeDataString($Token))"
}

Write-Host "`n== ledger summary ==" -ForegroundColor Cyan
$sum = Invoke-RestMethod -Uri "$Ops/v1/summary$q" -Headers $headers -TimeoutSec 15
Write-Host ("hits={0} unique_ips={1} max_severity={2}" -f $sum.hits, $sum.unique_ips, $sum.max_severity)
Write-Host "Console: $Ops/console$q" -ForegroundColor Green
if (-not $sum.hits -or $sum.hits -lt 1) {
  Write-Host "No hits recorded — is catch-node running with data volume mounted?" -ForegroundColor Yellow
  exit 1
}
Write-Host "OK — recording works."
