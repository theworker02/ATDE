#Requires -Version 5
# Demo the Atlas honeypot portal (HTTP must already be listening on :8080).
$ErrorActionPreference = "Continue"
$Base = if ($env:ATDE_HONEYPOT_URL) { $env:ATDE_HONEYPOT_URL.TrimEnd("/") } else { "http://127.0.0.1:8080" }

function Show($title, $url) {
  Write-Host "`n=== $title ===" -ForegroundColor Cyan
  Write-Host "GET $url"
  try {
    $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15
    Write-Host "status $($r.StatusCode) length $($r.RawContentLength)"
    ($r.Content.Substring(0, [Math]::Min(280, $r.Content.Length)) -replace "`r|`n", " ")
  } catch {
    Write-Host $_.Exception.Message -ForegroundColor Yellow
  }
}

Show "Landing" "$Base/"
Show "OpenAPI" "$Base/openapi.json"
Show "Env canary" "$Base/.env"
Show "security.txt" "$Base/.well-known/security.txt"
Show "Synthetic RCE" "$Base/api/v1/debug?cmd=id"
Show "Admin API (401)" "$Base/api/v1/admin/users"

Write-Host "`n=== Impossible login ===" -ForegroundColor Cyan
try {
  $body = @{ username = "admin"; password = "admin" }
  $r = Invoke-WebRequest -Uri "$Base/login" -Method POST -Body $body -UseBasicParsing -TimeoutSec 20
  Write-Host "status $($r.StatusCode)"
  if ($r.Content -match "two-factor|authenticator|Invalid|locked|Verification") {
    Write-Host "auth burn OK (no session granted)" -ForegroundColor Green
  } else {
    Write-Host "unexpected body snippet:" ($r.Content.Substring(0, [Math]::Min(200, $r.Content.Length)))
  }
} catch {
  Write-Host $_.Exception.Message
}

Write-Host "`nDone. Review: go run ./cmd/atde -mode caught" -ForegroundColor Green
