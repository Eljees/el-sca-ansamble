#requires -Version 5.1
<#
.SYNOPSIS
  Run scripts\windows\run-scan.ps1 against multiple targets sequentially,
  tolerate per-target failures, then print a single SUMMARY table.

.DESCRIPTION
  Replaces the ad-hoc PowerShell blob most users paste in chat when they
  need to scan several artifacts in one go.  The wrapper:

    1. Loads a list of {Case, Target} pairs from either a parameter array,
       a CSV file, or a JSON file.
    2. Calls .\scripts\windows\run-scan.ps1 -Target <T> -Clean for each
       entry, wrapped in try/catch so a single failure does NOT abort the
       remaining work.
    3. Tracks per-case status (ok / failed / no-report).
    4. Prints a final SUMMARY with Syft component count, Grype/CVE-bin-tool
       finding counts, and severity breakdown — same numbers the report
       header carries.

  By default DB updates are OFF: -UpdateDbOnce passes -UpdateDb only to the
  first scan in the batch (the only one that needs to refresh DBs; the
  rest reuse the cached state).  Use -UpdateDbEvery for every scan if you
  really mean it — but it will take 5-15 minutes per job.

.PARAMETER Jobs
  Array of hashtables, e.g.
    @(
      @{ Case='CYBERSEC-12103'; Target='D:\__tests\_SCA\CYBERSEC-12103\a.tar.gz' }
      @{ Case='CYBERSEC-12104'; Target='D:\__tests\_SCA\CYBERSEC-12104\b.zip' }
    )

.PARAMETER JobsCsv
  CSV file with columns Case,Target.  Lines starting with `#` are ignored.

.PARAMETER JobsJson
  JSON file containing an array of {case, target} objects.  Compatible with
  the array `-Jobs` would accept.

.PARAMETER UpdateDbOnce
  Pass -UpdateDb to the FIRST scan only (cheapest refresh strategy).

.PARAMETER UpdateDbEvery
  Pass -UpdateDb to every scan.  Discouraged — typically you want one
  refresh and then reuse the cached DBs.

.PARAMETER SkipCaseRewrite
  By default if -CaseId wasn't picked up from the target path the wrapper
  rewrites the `# CYBERSEC-…` header line in the produced Markdown so it
  matches the explicit case from -Jobs.  Pass this switch to skip that.

.EXAMPLE
  .\scripts\windows\batch-scan.ps1 -Jobs @(
    @{ Case='CYBERSEC-12103'; Target='D:\__tests\_SCA\CYBERSEC-12103\avandoc-client-1.0.0.4.tar.gz' }
    @{ Case='CYBERSEC-12104'; Target='D:\__tests\_SCA\CYBERSEC-12104\DMS_AvandocClientServiceSetup1.zip' }
    @{ Case='CYBERSEC-12080'; Target='D:\__tests\_SCA\CYBERSEC-12080\iDocs11c2781f2-android-build-release-signed.zip' }
  )

.EXAMPLE
  # Take the same list from a CSV next to the script:
  .\scripts\windows\batch-scan.ps1 -JobsCsv .\my-batch.csv
#>
[CmdletBinding(DefaultParameterSetName='InlineJobs')]
param(
  [Parameter(ParameterSetName='InlineJobs', Mandatory=$true)]
  [hashtable[]]$Jobs,

  [Parameter(ParameterSetName='CsvJobs', Mandatory=$true)]
  [string]$JobsCsv,

  [Parameter(ParameterSetName='JsonJobs', Mandatory=$true)]
  [string]$JobsJson,

  [switch]$UpdateDbOnce,
  [switch]$UpdateDbEvery,
  [switch]$SkipCaseRewrite,

  # After each successful scan, also produce a compact CYBERSEC-11531-style
  # digest with only Critical/High findings + SHA-256 of the source archive.
  # See scripts/windows/make-high-critical-report.ps1 for the format.
  # Enabled by default — pass -SkipHighCriticalDigest to turn off.
  [switch]$SkipHighCriticalDigest
)

$ErrorActionPreference = "Stop"

# ── Resolve the repo root (assumes script lives in scripts/windows/) ────────
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$runScan  = Join-Path $repoRoot "scripts\windows\run-scan.ps1"
if (-not (Test-Path $runScan)) {
  throw "Cannot find $runScan — wrong layout?"
}

# ── Load jobs from whichever source the user picked ─────────────────────────
function Convert-ToJobs($raw) {
  $out = New-Object System.Collections.Generic.List[hashtable]
  foreach ($item in $raw) {
    if ($item -is [hashtable]) {
      $case   = $item.Case   ; if (-not $case)   { $case   = $item.case }
      $target = $item.Target ; if (-not $target) { $target = $item.target }
    } else {
      $case   = $item.Case   ; if (-not $case)   { $case   = $item.case }
      $target = $item.Target ; if (-not $target) { $target = $item.target }
    }
    if (-not $target) { continue }
    if (-not $case)   { $case = "" }   # let run-scan auto-detect
    $out.Add(@{ Case = [string]$case; Target = [string]$target })
  }
  return $out
}

switch ($PSCmdlet.ParameterSetName) {
  'InlineJobs' { $loaded = Convert-ToJobs $Jobs }
  'CsvJobs' {
    if (-not (Test-Path $JobsCsv)) { throw "JobsCsv not found: $JobsCsv" }
    $rows = Import-Csv -LiteralPath $JobsCsv |
              Where-Object { $_.Case -and -not $_.Case.StartsWith('#') }
    $loaded = Convert-ToJobs $rows
  }
  'JsonJobs' {
    if (-not (Test-Path $JobsJson)) { throw "JobsJson not found: $JobsJson" }
    $arr = Get-Content -Raw -LiteralPath $JobsJson | ConvertFrom-Json
    $loaded = Convert-ToJobs $arr
  }
}

if (-not $loaded -or $loaded.Count -eq 0) {
  throw "No jobs to run."
}

if ($UpdateDbOnce -and $UpdateDbEvery) {
  throw "Pick one: -UpdateDbOnce or -UpdateDbEvery (not both)."
}

# ── Common setup ────────────────────────────────────────────────────────────
Set-Location $repoRoot
if (-not $env:COMPOSE_FILE) {
  $env:COMPOSE_FILE = "docker-compose.yml;docker-compose.windows.override.yml"
}
$today = (Get-Date).ToString('yyyy-MM-dd')

# ── Run loop ────────────────────────────────────────────────────────────────
$results = New-Object System.Collections.Generic.List[object]
$firstJob = $true

foreach ($job in $loaded) {
  $case   = $job.Case
  $target = $job.Target
  if ($case) { $label = $case } else { $label = "(auto-case)" }
  Write-Host ""
  Write-Host ("========== {0}  ({1}) ==========" -f $label, (Split-Path $target -Leaf)) -ForegroundColor Cyan

  $record = [pscustomobject]@{
    Case = $case
    Target = $target
    Status = ""
    ExitCode = $null
    Error = ""
    ReportPath = ""
    Syft = ""
    Grype = ""
    Cbt = ""
    Severity = ""
  }

  if (-not (Test-Path $target)) {
    Write-Host "   ! цель не найдена" -ForegroundColor Red
    $record.Status = "missing-target"
    $results.Add($record)
    continue
  }

  # Hashtable splat — robust against PS parameter-binding quirks where an
  # array splat like @('-CaseId', $val) sometimes gets bound positionally
  # to a different parameter (e.g. -Tool).  With @hash the param names
  # come from the keys, not from string elements, so the binder cannot
  # misclassify them.
  $scanParams = @{
    Target = $target
    Clean  = $true
  }
  if ($case) { $scanParams.CaseId = $case }
  if ($UpdateDbEvery -or ($UpdateDbOnce -and $firstJob)) {
    $scanParams.UpdateDb = $true
  }
  $firstJob = $false

  # try/catch isolates per-job failure so the batch continues.
  $oldEAP = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & $runScan @scanParams
    $record.ExitCode = $LASTEXITCODE
  } catch {
    $record.Status = "exception"
    $record.Error  = $_.Exception.Message
    $record.ExitCode = -1
    Write-Host ("   ! run-scan.ps1 упал: " + $_.Exception.Message) -ForegroundColor Red
  } finally {
    $ErrorActionPreference = $oldEAP
  }

  if (-not $record.Status) {
    if ($record.ExitCode -eq 0) {
      $record.Status = "ok"
    } else {
      $record.Status = "failed"
    }
  }
  if ($record.Status -ne 'ok') {
    Write-Host ("   ! exit " + $record.ExitCode) -ForegroundColor Red
    $results.Add($record)
    continue
  }

  # Locate today's report next to the target and (optionally) rewrite header.
  $base = [IO.Path]::GetFileNameWithoutExtension($target) -replace '\.tar$',''
  $reportPath = Get-ChildItem (Split-Path $target -Parent) `
                  -Filter ("${base}_report_${today}.md") -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($reportPath) {
    $record.ReportPath = $reportPath.FullName
    if (-not $SkipCaseRewrite -and $case) {
      # Only rewrite when our explicit case differs from what's in the file.
      $head = (Get-Content -LiteralPath $reportPath.FullName -TotalCount 1).Trim()
      if ($head -and $head -notmatch [regex]::Escape($case)) {
        (Get-Content -LiteralPath $reportPath.FullName -Raw) `
          -replace '^# CYBERSEC-\S+:', ('# ' + $case + ':') |
          Set-Content -LiteralPath $reportPath.FullName -Encoding UTF8
        Write-Host ("   shapka -> " + $case) -ForegroundColor Green
      }
    }
    # Pull the four headline numbers out of the report body.
    $md = Get-Content -LiteralPath $reportPath.FullName -Raw
    $record.Syft     = ([regex]::Match($md,'Syft components:\s*`(\d+)`')).Groups[1].Value
    $record.Grype    = ([regex]::Match($md,'Grype findings:\s*`(\d+)`')).Groups[1].Value
    $record.Cbt      = ([regex]::Match($md,'cve-bin-tool findings:\s*`(\d+)`')).Groups[1].Value
    $record.Severity = ([regex]::Match($md,'Severity counts:\s*`([^`]+)`')).Groups[1].Value

    # Compact high/critical digest in the CYBERSEC-11531 reference format,
    # written next to the scan report.  Skip with -SkipHighCriticalDigest.
    if (-not $SkipHighCriticalDigest) {
      $hcScript = Join-Path $repoRoot "scripts\windows\make-high-critical-report.ps1"
      if (Test-Path $hcScript) {
        try {
          $hcParams = @{ Target = $target }
          # If this job triggered an explicit DB update, surface that fact in
          # the digest header so triagers don't think we used stale local DBs.
          if ($scanParams.ContainsKey('UpdateDb')) { $hcParams.OnlineDb = $true }
          & $hcScript @hcParams | Out-Null
        } catch {
          Write-Host ("   ! make-high-critical-report.ps1 упал: " + $_.Exception.Message) -ForegroundColor Yellow
        }
      }
    }
  } else {
    $record.Status = "no-report"
    Write-Host ("   ! сегодняшнего отчёта нет в " + (Split-Path $target -Parent)) -ForegroundColor Yellow
  }
  $results.Add($record)
}

# ── SUMMARY ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=========== SUMMARY ===========" -ForegroundColor Cyan
foreach ($r in $results) {
  $color = switch ($r.Status) {
    'ok'             { 'Green' }
    'no-report'      { 'Yellow' }
    'missing-target' { 'Red' }
    'failed'         { 'Red' }
    'exception'      { 'Red' }
    default          { 'White' }
  }
  # PS 5.1 doesn't support `if` as an inline expression inside -f args;
  # use a statement-form assignment instead.
  if ($r.Case) { $caseLabel = $r.Case } else { $caseLabel = '(auto)' }
  $line = "{0,-25} {1,-12} syft={2,4} grype={3,4} cbt={4,4} sev={5}" -f `
            $caseLabel,
            $r.Status,
            $r.Syft,
            $r.Grype,
            $r.Cbt,
            $r.Severity
  Write-Host $line -ForegroundColor $color
}

# Exit codes for CI: 0 if every job ok, 2 if any failed.
$bad = @($results | Where-Object { $_.Status -ne 'ok' })
if ($bad.Count -gt 0) { exit 2 } else { exit 0 }
