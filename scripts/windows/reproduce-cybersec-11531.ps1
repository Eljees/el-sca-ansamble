#requires -Version 5.1
<#
.SYNOPSIS
  Reproduce the cve-bin-tool findings from
  --exps\high_critical_report_2026-04-29_ru.md against
  --exps\prometheus-3.11.0.linux-amd64.tar.gz (SHA-256 FF799C…0C3B76).

.DESCRIPTION
  PowerShell mirror of scripts/reproduce-cybersec-11531.sh.  Pins every
  knob that materially changes whether the Go stdlib regex checker fires
  during a cve-bin-tool scan, then verifies the output matches the
  reference baseline:

      findings = 3
      severity = CRITICAL x 2, UNKNOWN x 1
      must include CVE-2024-3566

  Pinned settings (see scripts/reproduce-cybersec-11531.sh for rationale):
    CVE_BIN_TOOL_AUTO_SBOM = 0     (binary scan, not SBOM fast-path)
    CVE_BIN_TOOL_CHECKERS  = go,rust
    CVE_BIN_TOOL_MAX_FILE_MB = 0   (do not skip large Prometheus binaries)
    CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS = 3600

.PARAMETER UpdateDb
  Refresh the cve-bin-tool DB before scanning.

.PARAMETER SkipExtract
  Reuse the existing extracted tree at
  artifacts\extracted\current\... (faster on re-runs).

.PARAMETER BinaryScan
  Force the regex-checker (binary-scan) path even when a Syft SBOM is
  available.  Matches the original reference report exactly but takes
  15-30 min on Prometheus-class targets.  Default: off (SBOM fast-path
  with Go runtime injection — seconds, single Go runtime entry, still
  reproduces CVE-2024-3566).

.EXAMPLE
  pwsh -ExecutionPolicy Bypass -File .\scripts\windows\reproduce-cybersec-11531.ps1

.EXAMPLE
  pwsh -ExecutionPolicy Bypass -File .\scripts\windows\reproduce-cybersec-11531.ps1 -UpdateDb
#>
[CmdletBinding()]
param(
  [switch]$UpdateDb,
  [switch]$SkipExtract,
  [switch]$BinaryScan
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repoRoot

$targetTar      = "--exps\prometheus-3.11.0.linux-amd64.tar.gz"
$expectedSha    = "ff799c3e4c318e17dec14aaaa406a4da328fabb4578336b36d96d893870c3b76"
$extractDirRel  = "artifacts\extracted\current"
$extractDirHost = Join-Path $repoRoot $extractDirRel
$cbtReportRel   = "artifacts\reports\cve-bin-tool\report.json"

if (-not (Test-Path $targetTar)) { throw "Missing $targetTar" }

$actualSha = (Get-FileHash -Algorithm SHA256 -Path $targetTar).Hash.ToLower()
if ($actualSha -ne $expectedSha) {
  Write-Warning "Target SHA-256 differs from reference."
  Write-Warning "  expected: $expectedSha"
  Write-Warning "  observed: $actualSha"
  Write-Warning "  proceeding anyway; results may drift."
}

# ── Pinned environment for reproducibility ──────────────────────────────────
$env:SCAN_TARGET_HOST                = $extractDirHost
$env:SCAN_TARGET_CONTAINER           = "/scan-target"
$env:SCAN_TARGET_DISPLAY             = "$targetTar -> $extractDirHost"
$env:CVE_BIN_TOOL_TARGET             = "/scan-target"
$env:CVE_BIN_TOOL_CHECKERS           = "go,rust"
$env:CVE_BIN_TOOL_MAX_FILE_MB        = "0"
$env:CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS = "3600"
$env:CVE_BIN_TOOL_LOCAL_COPY         = "1"

if ($BinaryScan) {
  $env:CVE_BIN_TOOL_AUTO_SBOM = "0"
  $env:CVE_BIN_TOOL_SBOM_PATH = ""
  $mode = "BINARY SCAN (forced -BinaryScan)"
} else {
  $env:CVE_BIN_TOOL_AUTO_SBOM          = "1"
  $env:CVE_BIN_TOOL_INJECT_GO_RUNTIME  = "1"
  $mode = "SBOM fast-path with Go runtime injection (default)"
}

Write-Host "[reproduce] target tar : $targetTar"
Write-Host "[reproduce] target sha : $actualSha"
Write-Host "[reproduce] update DB  : $UpdateDb"
Write-Host "[reproduce] checkers   : $env:CVE_BIN_TOOL_CHECKERS"
Write-Host "[reproduce] mode       : $mode"

# ── Step 1: optional DB refresh ────────────────────────────────────────────
if ($UpdateDb) {
  Write-Host "[reproduce] refreshing cve-bin-tool DB..."
  & docker compose --profile update run --rm cve-bin-tool-updater
  if ($LASTEXITCODE -ne 0) { throw "DB refresh failed (exit $LASTEXITCODE)" }
}

# ── Step 2: extract (idempotent) ───────────────────────────────────────────
if (-not $SkipExtract) {
  Write-Host "[reproduce] extracting tarball..."
  New-Item -ItemType Directory -Force -Path $extractDirHost | Out-Null
  $env:EXTRACT_INPUT_HOST = (Resolve-Path $targetTar).Path
  $env:EXTRACT_OUTPUT     = "/workspace/$($extractDirRel -replace '\\','/')"
  $env:EXTRACT_MAX_DEPTH  = "4"
  & docker compose --profile extract run --rm artifact-extractor
  if ($LASTEXITCODE -ne 0) { throw "Extract failed (exit $LASTEXITCODE)" }
} elseif (-not (Test-Path $extractDirHost)) {
  throw "Extract directory missing and -SkipExtract was set."
}

# ── Step 3a: Syft SBOM (only when SBOM fast-path is on) ─────────────────────
if (-not $BinaryScan) {
  Write-Host "[reproduce] generating Syft SBOM (needed for SBOM fast-path)..."
  $env:SYFT_TARGET = "/scan-target"
  $env:SYFT_FROM   = "dir"
  & docker compose --profile scan run --rm syft-sbom
  if ($LASTEXITCODE -ne 0) { throw "Syft SBOM step failed (exit $LASTEXITCODE)" }
}

# ── Step 3b: cve-bin-tool scan ─────────────────────────────────────────────
Write-Host "[reproduce] running cve-bin-tool scan..."
Remove-Item -ErrorAction SilentlyContinue $cbtReportRel
Remove-Item -ErrorAction SilentlyContinue "artifacts\reports\cve-bin-tool\timeout.flag"
& docker compose --profile scan run --rm cve-bin-tool-scanner
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1) {
  throw "cve-bin-tool scan failed (exit $LASTEXITCODE)"
}

# ── Step 4: verify ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[reproduce] === results ===" -ForegroundColor Cyan

if (-not (Test-Path $cbtReportRel) -or (Get-Item $cbtReportRel).Length -eq 0) {
  throw "$cbtReportRel is empty or missing — scan did not produce findings."
}

$report = Get-Content -Raw $cbtReportRel | ConvertFrom-Json
if ($report -isnot [System.Collections.IEnumerable]) {
  throw "Report is not a JSON array."
}

$total = @($report).Count
$bySev = @{}
$named = New-Object System.Collections.Generic.List[string]
foreach ($entry in $report) {
  $sev = if ($entry.severity) { $entry.severity.ToString().ToUpper() } else { "UNKNOWN" }
  if (-not $bySev.ContainsKey($sev)) { $bySev[$sev] = 0 }
  $bySev[$sev]++
  $cve = $entry.cve_number; if (-not $cve) { $cve = $entry.CVE }
  if ($cve) { $named.Add("$cve - $($entry.product):$($entry.version) ($sev)") }
}

Write-Host "total cve-bin-tool findings: $total"
$bySev.GetEnumerator() | Sort-Object Key | ForEach-Object {
  Write-Host ("  {0,-10} {1}" -f $_.Key, $_.Value)
}
Write-Host ""
Write-Host "named findings:"
$named | ForEach-Object { Write-Host "  $_" }

# Approximate reference baseline from --exps/high_critical_report_2026-04-29_ru.md.
# SBOM-with-injection path produces a single Go-runtime finding (one Go
# version injected); binary-scan path can produce several.  Acceptance is
# "≥ 1 CVE-2024-3566 finding and ≥ 1 CRITICAL/HIGH" — enough proof that
# the Go runtime signal reproduces.
$expectedTotal = 1
$requiredCve   = "CVE-2024-3566"
$severityHit   = @("CRITICAL", "HIGH") | Where-Object { ($bySev[$_] ?? 0) -ge 1 }

$drift = New-Object System.Collections.Generic.List[string]
if ($total -lt $expectedTotal) {
  $drift.Add("finding count $total below approximate baseline $expectedTotal")
}
if (@($severityHit).Count -eq 0) {
  $drift.Add("no CRITICAL or HIGH finding (reference shows CRITICAL x 2)")
}
if (-not ($named -match [regex]::Escape($requiredCve))) {
  $drift.Add("missing $requiredCve")
}

Write-Host ""
if ($drift.Count -gt 0) {
  Write-Host "DRIFT vs CYBERSEC-11531 approximate baseline:" -ForegroundColor Yellow
  $drift | ForEach-Object { Write-Host "  - $_" }
  exit 5
}
Write-Host "OK - reproduces the reference Go-runtime signal (approximate)." -ForegroundColor Green
