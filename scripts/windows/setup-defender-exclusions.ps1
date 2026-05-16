<#
.SYNOPSIS
    Registers el-sca-ansamble paths and processes with Windows Defender so SCA
    scans don't double-scan every file under artifacts/ and the Docker VHDX.

.DESCRIPTION
    On Windows Docker Desktop running on WSL2, every read/write to a bind-mounted
    NTFS path passes through Defender's real-time monitor.  Extractor +
    cve-bin-tool + Syft together touch hundreds of thousands of files per scan,
    and Defender adds 2-8x wall-clock overhead.  This script registers stable
    exclusions for:

      * The project root (read-write hot loop during scans).
      * `artifacts/` (extracted binaries, raw scanner JSON, SBOMs).
      * Docker Desktop's WSL ext4 VHDX files (where layers live).
      * Long-running Docker / WSL processes (vmmemWSL, com.docker.backend).

    Idempotent: skips entries that are already excluded.  Writes a JSON
    provenance file to `artifacts\provenance\defender.json` summarising what
    was added (and what was already there).

    REQUIREMENTS
      * PowerShell run as Administrator (Defender APIs are admin-only).
      * Windows Defender enabled (Get-MpPreference must succeed).

.PARAMETER ProjectRoot
    Project root to exclude.  Defaults to the parent of the script's directory
    (i.e. the repo containing `scripts\windows\`).

.PARAMETER DryRun
    Print what *would* be added without changing Defender configuration.

.PARAMETER Remove
    Remove the exclusions this script previously added (for cleanup).  Reads
    the most recent `defender.json` to know what to undo.

.EXAMPLE
    # Standard one-time setup:
    pwsh -ExecutionPolicy Bypass -File .\scripts\windows\setup-defender-exclusions.ps1

.EXAMPLE
    # Preview only:
    pwsh -ExecutionPolicy Bypass -File .\scripts\windows\setup-defender-exclusions.ps1 -DryRun

.NOTES
    Phase 3.1 of PLAN_2026-05-16.md.  See docs/windows-powershell.md (TBD) for
    the broader Windows-acceleration workflow.
#>

[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [switch]$DryRun,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

# ── Resolve project root from script location -------------------------------
if (-not $ProjectRoot) {
    $scriptDir = Split-Path -Parent $PSCommandPath
    $ProjectRoot = (Resolve-Path (Join-Path $scriptDir "..\..\")).Path.TrimEnd('\')
}
if (-not (Test-Path $ProjectRoot)) {
    throw "ProjectRoot not found: $ProjectRoot"
}
Write-Host "[setup-defender] project root: $ProjectRoot" -ForegroundColor Cyan

# ── Admin check -------------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must run elevated (Defender APIs are admin-only). Right-click PowerShell -> Run as Administrator."
}

# ── Defender available ------------------------------------------------------
try {
    $pref = Get-MpPreference -ErrorAction Stop
} catch {
    throw "Get-MpPreference failed: $($_.Exception.Message). Is Windows Defender enabled?"
}

# ── Build exclusion candidate list ------------------------------------------
$artifactsPath = Join-Path $ProjectRoot "artifacts"

# Docker Desktop stores its WSL2 ext4 VHDX in %LOCALAPPDATA%\Docker\wsl\.
# On non-default installs the path may differ; we add only paths that exist.
$dockerWslData   = Join-Path $env:LOCALAPPDATA "Docker\wsl\data"
$dockerWslDistro = Join-Path $env:LOCALAPPDATA "Docker\wsl\distro"

$pathCandidates = @(
    $ProjectRoot
    $artifactsPath
    $dockerWslData
    $dockerWslDistro
) | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique

# Processes that constantly read project / Docker files — Defender real-time
# scan would re-check every block read.
$processCandidates = @(
    "vmmemWSL"
    "com.docker.backend.exe"
    "com.docker.service.exe"
    "wsl.exe"
    "wslhost.exe"
    "wslservice.exe"
    "Docker Desktop.exe"
)

# ── Snapshot current state --------------------------------------------------
$currentPaths     = @($pref.ExclusionPath     | Where-Object { $_ })
$currentProcesses = @($pref.ExclusionProcess  | Where-Object { $_ })

$pathsToAdd     = @($pathCandidates    | Where-Object { $currentPaths     -notcontains $_ })
$processesToAdd = @($processCandidates | Where-Object { $currentProcesses -notcontains $_ })

# ── Remove mode -------------------------------------------------------------
if ($Remove) {
    $provFile = Join-Path $artifactsPath "provenance\defender.json"
    if (-not (Test-Path $provFile)) {
        throw "Cannot find $provFile — nothing recorded to remove."
    }
    $prov = Get-Content $provFile -Raw | ConvertFrom-Json
    Write-Host "[setup-defender] removing exclusions recorded in $provFile" -ForegroundColor Yellow
    foreach ($p in @($prov.added_paths)) {
        if ($currentPaths -contains $p) {
            Write-Host "  - path:    $p"
            if (-not $DryRun) { Remove-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue }
        }
    }
    foreach ($proc in @($prov.added_processes)) {
        if ($currentProcesses -contains $proc) {
            Write-Host "  - process: $proc"
            if (-not $DryRun) { Remove-MpPreference -ExclusionProcess $proc -ErrorAction SilentlyContinue }
        }
    }
    Write-Host "[setup-defender] removal complete." -ForegroundColor Green
    return
}

# ── Add exclusions ----------------------------------------------------------
Write-Host ""
Write-Host "Will add:" -ForegroundColor Cyan
if ($pathsToAdd.Count -eq 0)     { Write-Host "  (no new paths — already excluded)" -ForegroundColor DarkGray }
foreach ($p in $pathsToAdd)      { Write-Host "  + path:    $p" -ForegroundColor Green }
if ($processesToAdd.Count -eq 0) { Write-Host "  (no new processes — already excluded)" -ForegroundColor DarkGray }
foreach ($p in $processesToAdd)  { Write-Host "  + process: $p" -ForegroundColor Green }

if ($pathsToAdd.Count -eq 0 -and $processesToAdd.Count -eq 0) {
    Write-Host "[setup-defender] nothing to do." -ForegroundColor DarkGray
} elseif ($DryRun) {
    Write-Host "[setup-defender] DryRun — no changes applied." -ForegroundColor Yellow
} else {
    foreach ($p in $pathsToAdd)     { Add-MpPreference -ExclusionPath    $p -Force }
    foreach ($p in $processesToAdd) { Add-MpPreference -ExclusionProcess $p -Force }
    Write-Host "[setup-defender] applied." -ForegroundColor Green
}

# ── Provenance --------------------------------------------------------------
$provDir = Join-Path $artifactsPath "provenance"
if (-not (Test-Path $provDir)) { New-Item -ItemType Directory -Path $provDir | Out-Null }
$provPayload = [ordered]@{
    timestamp_utc          = (Get-Date).ToUniversalTime().ToString("o")
    project_root           = $ProjectRoot
    dry_run                = [bool]$DryRun
    added_paths            = @($pathsToAdd)
    added_processes        = @($processesToAdd)
    already_excluded_paths = @($pathCandidates    | Where-Object { $currentPaths     -contains $_ })
    already_excluded_procs = @($processCandidates | Where-Object { $currentProcesses -contains $_ })
    skipped_missing_paths  = @(@($ProjectRoot, $artifactsPath, $dockerWslData, $dockerWslDistro) `
                                | Where-Object { $_ -and -not (Test-Path $_) })
    defender_version       = (Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureVersion -ErrorAction SilentlyContinue)
}
$provFile = Join-Path $provDir "defender.json"
$provPayload | ConvertTo-Json -Depth 5 | Set-Content -Path $provFile -Encoding UTF8
Write-Host "[setup-defender] provenance written: $provFile" -ForegroundColor Cyan
