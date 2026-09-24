#Requires -Version 5
$Root = Split-Path -Parent $PSScriptRoot
$OutDir = Join-Path $Root "dist"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Out = Join-Path $OutDir "sbom-lite.txt"
$Version = (Get-Content (Join-Path $Root "VERSION") -ErrorAction SilentlyContinue | Select-Object -First 1)
if (-not $Version) { $Version = "unknown" }
$ts = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
Push-Location $Root
try {
  $mods = go list -m all 2>$null
  $pkgs = go list ./... 2>$null
  $loc = (Get-ChildItem -Recurse -Filter *.go | Where-Object { $_.FullName -notmatch '\\vendor\\' } | Get-Content | Measure-Object -Line).Lines
} finally {
  Pop-Location
}
@"
# ATDE SBOM-lite
# generated: $ts
# version: $Version

## Go module
$($mods -join "`n")

## Packages
$($pkgs -join "`n")

## Approximate LOC (Go)
$loc
"@ | Set-Content -Path $Out -Encoding utf8
Write-Host "wrote $Out"
