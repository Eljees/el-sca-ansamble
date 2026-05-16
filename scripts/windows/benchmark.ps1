<#
.SYNOPSIS
    Wall-clock benchmark for the el-sca-ansamble scan pipeline on Windows.

.DESCRIPTION
    Runs `scripts\windows\run-scan.ps1 -Target <Target>` N times in a row and
    captures per-stage timings.  Used to validate Phase 3 acceleration work:
    Defender exclusions, BuildKit cache, the windows.override compose overlay,
    SBOM fast-path, etc.

    The first run is treated as a cold cache and excluded from the average
    by default (override with -IncludeCold).

    Output: artifacts\provenance\benchmark.json with per-run wall-clock,
    summary average/median, and a snapshot of the active configuration
    (Defender exclusions, COMPOSE_FILE, key env vars) so two benchmarks
    from different days can be compared meaningfully.

.PARAMETER Target
    Path to scan (archive or directory).  Required.

.PARAMETER Runs
    Total number of scan executions.  Default 3.

.PARAMETER IncludeCold
    Include the first (cold-cache) run in the averages.

.PARAMETER ExtraScanArgs
    Extra arguments forwarded verbatim to run-scan.ps1, e.g. "-SbomScan".

.EXAMPLE
    pwsh -File scripts\windows\benchmark.ps1 -Target ".\samples\prometheus.tar.gz" -Runs 3

.NOTES
    Phase 3.7 of PLAN_2026-05-16.md.  Does NOT modify any system state.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]   $Target,
    [ValidateRange(1, 10)]         [int]      $Runs = 3,
                                   [switch]   $IncludeCold,
                                   [string[]] $ExtraScanArgs = @()
)

$ErrorActionPreference = "Stop"

# ── Locate project root (script lives in scripts/windows/) ------------------
$scriptDir   = Split-Path -Parent $PSCommandPath
$projectRoot = (Resolve-Path (Join-Path $scriptDir "..\..\")).Path.TrimEnd('\')
$runScan     = Join-Path $projectRoot "scripts\windows\run-scan.ps1"
if (-not (Test-Path $runScan)) {
    throw "run-scan.ps1 not found at $runScan"
}
if (-not (Test-Path $Target)) {
    throw "Target not found: $Target"
}
$targetResolved = (Resolve-Path $Target).Path

# ── Snapshot relevant configuration ----------------------------------------
function Get-ConfigSnapshot {
    $snap = [ordered]@{
        timestamp_utc       = (Get-Date).ToUniversalTime().ToString("o")
        project_root        = $projectRoot
        target              = $targetResolved
        target_size_mb      = [math]::Round(((Get-Item $targetResolved).Length / 1MB), 2)
        compose_file        = $env:COMPOSE_FILE
        compose_profiles    = $env:COMPOSE_PROFILES
        http_proxy          = $env:HTTP_PROXY
        all_proxy           = $env:ALL_PROXY
        cve_bin_auto_sbom   = $env:CVE_BIN_TOOL_AUTO_SBOM
        cve_bin_max_file_mb = $env:CVE_BIN_TOOL_MAX_FILE_MB
        cve_bin_timeout_s   = $env:CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS
    }
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        $snap['defender_exclusion_paths_count']     = @($mp.ExclusionPath).Count
        $snap['defender_exclusion_processes_count'] = @($mp.ExclusionProcess).Count
    } catch {
        $snap['defender_status'] = "unavailable: $($_.Exception.Message)"
    }
    return $snap
}

# ── Execute --------------------------------------------------------------
$runs = New-Object System.Collections.Generic.List[object]
Write-Host ""
Write-Host "Benchmark target  : $targetResolved" -ForegroundColor Cyan
Write-Host "Runs              : $Runs" -ForegroundColor Cyan
Write-Host "Include cold run  : $IncludeCold" -ForegroundColor Cyan
Write-Host ""

for ($i = 1; $i -le $Runs; $i++) {
    Write-Host ("─" * 60) -ForegroundColor DarkGray
    Write-Host ("Run {0}/{1} starting at {2}" -f $i, $Runs, (Get-Date).ToString("HH:mm:ss")) -ForegroundColor Yellow
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $scanArgs = @("-Target", $targetResolved) + $ExtraScanArgs
        & $runScan @scanArgs
        $exitCode = $LASTEXITCODE
    } catch {
        $exitCode = -1
        Write-Warning "Run $i raised: $($_.Exception.Message)"
    } finally {
        $stopwatch.Stop()
    }
    $secs = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
    Write-Host ("Run {0}/{1} finished: {2}s (exit {3})" -f $i, $Runs, $secs, $exitCode) -ForegroundColor Yellow
    $runs.Add([ordered]@{
        index      = $i
        is_cold    = ($i -eq 1)
        seconds    = $secs
        exit_code  = $exitCode
        started_at = (Get-Date).AddSeconds(-1 * $secs).ToUniversalTime().ToString("o")
    })
}

# ── Summary stats ---------------------------------------------------------
$considered = if ($IncludeCold) { $runs } else { $runs | Where-Object { -not $_.is_cold } }
$successOnly = $considered | Where-Object { $_.exit_code -eq 0 -or $_.exit_code -eq 1 }
$summary = [ordered]@{
    runs_considered = @($considered).Count
    runs_successful = @($successOnly).Count
}
if (@($successOnly).Count -gt 0) {
    $vals  = @($successOnly | ForEach-Object { $_.seconds })
    $sorted = $vals | Sort-Object
    $mid    = [math]::Floor($sorted.Count / 2)
    $median = if ($sorted.Count % 2 -eq 0) { ($sorted[$mid - 1] + $sorted[$mid]) / 2 } else { $sorted[$mid] }
    $summary['min_seconds']    = ($vals | Measure-Object -Minimum).Minimum
    $summary['max_seconds']    = ($vals | Measure-Object -Maximum).Maximum
    $summary['median_seconds'] = [math]::Round($median, 1)
    $summary['avg_seconds']    = [math]::Round((($vals | Measure-Object -Average).Average), 1)
}

# ── Write provenance ------------------------------------------------------
$provDir = Join-Path $projectRoot "artifacts\provenance"
if (-not (Test-Path $provDir)) { New-Item -ItemType Directory -Path $provDir | Out-Null }
$payload = [ordered]@{
    benchmark_kind = "windows-wall-clock"
    config         = Get-ConfigSnapshot
    runs           = $runs
    summary        = $summary
}
$provFile = Join-Path $provDir "benchmark.json"
$payload | ConvertTo-Json -Depth 6 | Set-Content -Path $provFile -Encoding UTF8

Write-Host ""
Write-Host ("─" * 60) -ForegroundColor DarkGray
Write-Host "Summary:" -ForegroundColor Cyan
$summary.GetEnumerator() | ForEach-Object {
    Write-Host ("  {0,-18} {1}" -f $_.Key, $_.Value)
}
Write-Host ""
Write-Host "Provenance: $provFile" -ForegroundColor Cyan
