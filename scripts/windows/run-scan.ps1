param(
  # Path to the file or directory to scan (required)
  [Parameter(Mandatory=$true)]
  [string]$Target,

  # Case identifier to print in the final report. Auto-detected from Target path
  # when omitted, e.g. CYBERSEC-12080.
  [string]$CaseId = "",

  # docker compose profile for scanning
  [string]$Profile = "scan",

  # Run only specific tool (default: all)
  [ValidateSet("all","syft","grype","trivy","cve-bin-tool")]
  [string]$Tool = "all",

  # Target format — auto-detected by default; set explicitly for APK / Windows installers
  # auto   = standard pipeline (tar.gz, zip with sources, docker image, etc.)
  # apk    = Android APK  — uses apk-analyzer container, then grype on generated SBOM
  # win    = Windows NSIS/MSI installer — uses win-analyzer container, then cve-bin-tool on extracted binaries
  [ValidateSet("auto","apk","win")]
  [string]$Format = "auto",

  # Also pull fresh DB before scanning (disabled by default — requires network/proxy)
  [switch]$UpdateDb,

  # Unpack archive before scanning
  [switch]$Extract,
  [int]$ExtractMaxDepth = 0,

  # Clean artifacts/ before this run (recommended between scans)
  [switch]$Clean,

  # Feed Syft-generated SBOM to cve-bin-tool instead of full binary scan.
  # Much faster (~30s vs 10+ min) but requires correct syft-format support in
  # cve-bin-tool v3.4. Disabled by default until verified working.
  [switch]$SbomScan,

  # cve-bin-tool scan timeout in seconds (default 1800 = 30 min)
  [int]$CveBinToolTimeout = 1800,

  # cve-bin-tool checker filter.
  # ""    = auto-detect from binary type (default — Go targets get language-only checkers)
  # "all" = run all 365 binary checkers (slow but thorough)
  # "go"  = Go language checker only (fast, ~2 min vs 30+ min for Go binaries)
  # "go,rust,python,javascript" = custom comma-separated list
  [string]$CveBinToolCheckers = "",

  # Save a per-run snapshot: artifacts | near-source | auto
  [ValidateSet("artifacts","near-source","auto")]
  [string]$ArtifactMode = $(if ($env:EL_SCA_ARTIFACT_MODE) { $env:EL_SCA_ARTIFACT_MODE } else { "auto" })
)

$ErrorActionPreference = "Stop"

# ── Helpers ───────────────────────────────────────────────────────────────────

function Import-LocalEnv {
  $envFile = Join-Path (Get-Location).Path ".env.local"
  if (-not (Test-Path $envFile)) { return }
  foreach ($line in Get-Content $envFile) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line.TrimStart().StartsWith("#"))    { continue }
    $parts = $line -split "=", 2
    if ($parts.Count -ne 2) { continue }
    [Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), "Process")
  }
}

function Enable-WindowsComposeOverlay {
  $repoRoot = (Get-Location).Path
  $baseCompose = Join-Path $repoRoot "docker-compose.yml"
  $windowsOverlay = Join-Path $repoRoot "docker-compose.windows.override.yml"
  if (-not (Test-Path $baseCompose) -or -not (Test-Path $windowsOverlay)) { return }
  if ($env:COMPOSE_FILE) { return }
  $env:COMPOSE_FILE = "docker-compose.yml;docker-compose.windows.override.yml"
  Write-Host "[compose] Windows overlay enabled: docker-compose.windows.override.yml" -ForegroundColor DarkCyan
}

function Invoke-ComposeChecked {
  param(
    [Parameter(Mandatory=$true)][string[]]$Args,
    [int[]]$SuccessExitCodes = @(0)
  )
  & docker compose @Args
  if ($SuccessExitCodes -notcontains $LASTEXITCODE) {
    throw "docker compose failed (exit $LASTEXITCODE): $($Args -join ' ')"
  }
}

function Invoke-CveBinToolScannerChecked {
  param([Parameter(Mandatory=$true)][string[]]$Args)
  # cve-bin-tool exits with 1 when CVEs are found (success state), 0 when none found.
  Invoke-ComposeChecked -Args $Args -SuccessExitCodes @(0, 1)
}

function Invoke-DbStatus {
  param(
    [Parameter(Mandatory=$true)][string]$DbTool,
    [Parameter(Mandatory=$true)][string]$DbPath
  )
  & docker compose run --rm db-admin db-status $DbTool --path $DbPath --warning-age 24h
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "db-status for $DbTool returned exit code $LASTEXITCODE"
  }
}

function Get-DbStatusJson {
  # Internal helper: runs db-status quietly, returns parsed object.
  param(
    [Parameter(Mandatory=$true)][string]$DbTool,
    [Parameter(Mandatory=$true)][string]$DbPath,
    [string]$WarningAge = "24h"
  )
  try {
    $json = & docker compose run --rm --no-TTY db-admin db-status $DbTool --path $DbPath --warning-age $WarningAge 2>$null
    if (-not $json) { return $null }
    return ($json -join "`n") | ConvertFrom-Json -ErrorAction Stop
  } catch {
    return $null
  }
}

function Initialize-ComposePlaceholders {
  param([Parameter(Mandatory=$true)][string]$PlaceholderPath)
  if (-not $env:SCAN_TARGET_HOST)    { $env:SCAN_TARGET_HOST = $PlaceholderPath }
  if (-not $env:EXTRACT_INPUT_HOST)  { $env:EXTRACT_INPUT_HOST = $PlaceholderPath }
  if (-not $env:SCAN_TARGET_DISPLAY) { $env:SCAN_TARGET_DISPLAY = $PlaceholderPath }
  if (-not $env:REPORT_OUTPUT)       { $env:REPORT_OUTPUT = "/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md" }
}

function Show-DbFreshnessBanner {
  param(
    [string]$Title = "DATABASE FRESHNESS"
  )
  $tools = @(
    @{ Name='Trivy';        Tool='trivy';        Path='/var/lib/resilient-db/trivy' }
    @{ Name='Grype';        Tool='grype';        Path='/var/lib/resilient-db/grype/active' }
    @{ Name='cve-bin-tool'; Tool='cve-bin-tool'; Path='/root/.cache/cve-bin-tool' }
  )

  $rows = @()
  foreach ($t in $tools) {
    $s = Get-DbStatusJson -DbTool $t.Tool -DbPath $t.Path -WarningAge '24h'
    $rows += [pscustomobject]@{
      Name      = $t.Name
      Exists    = if ($s) { [bool]$s.exists } else { $false }
      Age       = if ($s -and $s.age_hours) { [double]$s.age_hours } else { $null }
      Warning   = if ($s) { [bool]$s.warning } else { $true }
      Message   = if ($s) { [string]$s.message } else { 'db-status failed' }
    }
  }

  $anyStale  = ($rows | Where-Object { $_.Warning -or -not $_.Exists }).Count -gt 0
  $headColor = if ($anyStale) { 'Red' } else { 'Green' }

  $bar = ('━' * 70)
  Write-Host ''
  Write-Host $bar -ForegroundColor $headColor
  Write-Host (' ' + $Title) -ForegroundColor $headColor
  Write-Host $bar -ForegroundColor $headColor
  foreach ($r in $rows) {
    if (-not $r.Exists) {
      $line  = '{0,-14} MISSING       — DB never built; run with -UpdateDb' -f $r.Name
      $color = 'Red'
    } elseif ($r.Warning) {
      $age   = if ($null -ne $r.Age) { ('{0,6:N1} h old' -f $r.Age) } else { '   ? h old' }
      $line  = '{0,-14} {1}  STALE — older than 24h, RUN UPDATE' -f $r.Name, $age
      $color = 'Yellow'
    } else {
      $age   = ('{0,6:N1} h old' -f $r.Age)
      $line  = '{0,-14} {1}  OK' -f $r.Name, $age
      $color = 'Green'
    }
    Write-Host (' ' + $line) -ForegroundColor $color
  }
  Write-Host $bar -ForegroundColor $headColor
  if ($anyStale) {
    Write-Host ''
    Write-Host ' ⚠  HOW TO REFRESH DATABASES' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '   Whole pipeline + DB refresh in one go:'
    Write-Host '     .\scripts\windows\run-scan.ps1 -Target <PATH> -Clean -UpdateDb' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '   Just refresh DBs (no scan):'
    Write-Host '     .\scripts\windows\update-trivy.ps1'      -ForegroundColor Cyan
    Write-Host '     .\scripts\windows\update-grype.ps1'      -ForegroundColor Cyan
    Write-Host '     .\scripts\windows\update-cve-bin-tool.ps1' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '   NVD API keys live in .env.local (NVD_API_KEY, NVD_API_KEY_FALLBACK)'
    Write-Host '   Update first runs without -UpdateDb take 5-10 minutes (NVD download).'
    Write-Host $bar -ForegroundColor $headColor
  }
  Write-Host ''
}

# ── Pre-flight checks ─────────────────────────────────────────────────────────

docker --version     | Out-Null
docker compose version | Out-Null
Import-LocalEnv
Enable-WindowsComposeOverlay

if (-not (Test-Path $Target)) {
  throw "Target does not exist: $Target"
}

# ── Derive output paths from target filename ──────────────────────────────────

$TargetResolved = (Resolve-Path $Target).Path
$TargetDir      = Split-Path $TargetResolved -Parent
$RawName        = [System.IO.Path]::GetFileName($TargetResolved)
$TargetKind     = if ((Get-Item $TargetResolved).PSIsContainer) { "dir" } else { "file" }
$TargetLower    = $TargetResolved.ToLower()
$IsStandaloneApk = $TargetLower.EndsWith(".apk")

if ([string]::IsNullOrWhiteSpace($CaseId)) {
  $caseMatch = [regex]::Match($TargetResolved, "CYBERSEC-\d+", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if ($caseMatch.Success) {
    $CaseId = $caseMatch.Value.ToUpperInvariant()
  } else {
    $CaseId = "CYBERSEC-UNKNOWN"
  }
}

# Strip known archive extensions (compound ones first)
$BaseName = $RawName
$knownExts = @(
  '.tar.gz', '.tar.bz2', '.tar.xz', '.tar.zst',
  '.tar', '.tgz', '.zip', '.gz', '.bz2', '.xz', '.zst',
  '.jar', '.war', '.ear', '.apk', '.ipa'
)
foreach ($ext in $knownExts) {
  if ($BaseName.ToLower().EndsWith($ext)) {
    $BaseName = $BaseName.Substring(0, $BaseName.Length - $ext.Length)
    break
  }
}

$Date       = Get-Date -Format "yyyy-MM-dd"
$ReportMd   = Join-Path $TargetDir "${BaseName}_report_${Date}.md"
$ReportHtml = Join-Path $TargetDir "${BaseName}_report_${Date}.html"
$ArtifactsDir = Join-Path (Get-Location).Path "artifacts"

# Compose renders the whole file even for db-admin helper calls. Seed harmless
# placeholders early so the pre-scan DB freshness banner can render reliably.
Initialize-ComposePlaceholders -PlaceholderPath $TargetResolved

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host " SCA Pipeline" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host " Case    : $CaseId"         -ForegroundColor White
Write-Host " Target  : $TargetResolved" -ForegroundColor White
Write-Host " MD out  : $ReportMd"       -ForegroundColor Gray
Write-Host " HTML out: $ReportHtml"     -ForegroundColor Gray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# Show DB freshness BEFORE scan: stale DB = stale findings.  If -UpdateDb was
# passed we still show it (afterwards it'll be re-shown with new ages).
Show-DbFreshnessBanner -Title 'DATABASE FRESHNESS (PRE-SCAN)'

# Loud warning when -UpdateDb is requested: this is an explicit opt-in that
# reaches out to NVD / GHCR / AWS / Anchore, takes 5-15 minutes on the
# first run, and is the source of most "scan hangs" support tickets.  The
# user already saw the freshness banner above, so this is a deliberate
# second pause-point.
if ($UpdateDb) {
  Write-Host ""
  Write-Host "⚠  -UpdateDb requested" -ForegroundColor Yellow
  Write-Host "    Will refresh trivy / grype / cve-bin-tool databases from upstream."
  Write-Host "    Expect 5-15 minutes on the first run (NVD JSON-mirror ≈ 2 GB)."
  Write-Host "    To skip and use the existing (cached) DBs, re-run WITHOUT -UpdateDb."
  Write-Host "    To make sure NVD calls have credentials, fill NVD_API_KEY in .env.local."
  Write-Host ""
}

# ── Clean artifacts from previous run ────────────────────────────────────────

if ($Clean) {
  Write-Host "[clean] Removing previous artifacts..." -ForegroundColor Yellow
  # First try Docker-based cleanup: a Linux container sees the volume mount as
  # plain ext4/9P paths, so it can delete files whose names are illegal on NTFS
  # (e.g. trailing-dot directories that innoextract creates from NSIS installers
  # like `app.\AvandocClient.cmd`).  PowerShell's Remove-Item chokes on those.
  $dockerCleanOK = $false
  try {
    $cleanSh = "find /cleanme -type f ! -name .gitkeep -delete 2>/dev/null; find /cleanme -mindepth 1 -type d -empty -delete 2>/dev/null; true"
    & docker run --rm -v "${ArtifactsDir}:/cleanme" alpine sh -c $cleanSh
    if ($LASTEXITCODE -eq 0) { $dockerCleanOK = $true }
  } catch {
    # Fall through to PowerShell cleanup.
  }

  if (-not $dockerCleanOK) {
    Write-Host "[clean]   docker-based clean unavailable, falling back to PowerShell (may skip NTFS-illegal names)" -ForegroundColor DarkYellow
    Get-ChildItem -Path $ArtifactsDir -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -ne ".gitkeep" } |
      ForEach-Object {
        try   { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop }
        catch { & cmd /c del /f /q "$($_.FullName)" *>$null }
      }
    Get-ChildItem -Path $ArtifactsDir -Recurse -Directory -ErrorAction SilentlyContinue |
      Sort-Object { $_.FullName.Length } -Descending |
      Where-Object { (Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0 } |
      ForEach-Object {
        try   { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop }
        catch { & cmd /c rd /s /q "$($_.FullName)" *>$null }
      }
  }

  # Orphan cve-bin-tool output files left in workspace root (these have normal names).
  Get-ChildItem -Path (Get-Location).Path -Filter "output.cve-bin-tool.*.json" -File -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
  Write-Host "[clean] Done." -ForegroundColor Yellow
  Write-Host ""
}

# Always remove stale SBOM files so Syft writes fresh ones.
# Windows bind-mounts can leave the file handle open between container runs,
# preventing overwrite. Explicit delete before the run avoids stale data.
$SbomDir = Join-Path $ArtifactsDir "sbom"
foreach ($sbomFile in @("syft.json","cyclonedx.json","spdx.json")) {
  $p = Join-Path $SbomDir $sbomFile
  if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue }
}

# ── Render Trivy flags (only needed for auto/standard pipeline) ───────────────

$trivyFlags = ""
if ($Format -eq "auto") {
  $trivyFlags = python -m resilient_updates.cli render-flags trivy
  if ($LASTEXITCODE -ne 0) { throw "failed to render trivy flags" }
}

# ── Environment for containers ────────────────────────────────────────────────

$env:SCAN_TARGET_HOST      = $TargetResolved
$env:SCAN_TARGET_CONTAINER = "/scan-target"
$env:SCAN_TARGET_DISPLAY   = $TargetResolved
$env:EXTRACT_INPUT_HOST    = $TargetResolved
$env:SYFT_TARGET           = "/scan-target"
$env:SYFT_FROM             = "dir"
$env:TRIVY_TARGET          = "/scan-target"
$env:CVE_BIN_TOOL_TARGET               = "/scan-target"
$env:CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS = [string]$CveBinToolTimeout
$env:CVE_BIN_TOOL_CHECKERS              = $CveBinToolCheckers
# SBOM fast-path — only when -SbomScan flag is explicitly passed
if ($SbomScan) {
  $env:CVE_BIN_TOOL_SBOM_PATH   = "/workspace/artifacts/sbom/cyclonedx.json"
  $env:CVE_BIN_TOOL_SBOM_FORMAT = "cyclonedx"
  Write-Host " SbomScan: ENABLED (cve-bin-tool will read cyclonedx.json)" -ForegroundColor DarkCyan
} else {
  $env:CVE_BIN_TOOL_SBOM_PATH   = ""
  $env:CVE_BIN_TOOL_SBOM_FORMAT = ""
}
# Internal container path for the primary report (picked up by report-collector)
$env:REPORT_OUTPUT = "/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md"

# Archive targets need extraction before the standard dir-based scan.
if (-not $Extract -and $TargetKind -eq "file") {
  $archiveExts = @(".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".zip", ".rpm", ".deb")
  $targetLower = $TargetResolved.ToLower()
  if ($archiveExts | Where-Object { $targetLower.EndsWith($_) }) {
    $Extract = $true
    Write-Host " Extract : enabled automatically for archive target" -ForegroundColor Yellow
  }
}

# ── Auto-detect format if not specified ──────────────────────────────────────

if ($Format -eq "auto") {
  $ext = [System.IO.Path]::GetExtension($TargetResolved).ToLower()
  if ($ext -eq ".apk") {
    $Format = "apk"
  } elseif ($ext -in @(".msi", ".exe")) {
    $Format = "win"
  } elseif ($ext -eq ".zip") {
    # Peek inside the ZIP: if it contains an .apk or .msi/.exe, set format accordingly
    try {
      Add-Type -AssemblyName System.IO.Compression.FileSystem
      $zip = [System.IO.Compression.ZipFile]::OpenRead($TargetResolved)
      $entries = $zip.Entries | Select-Object -ExpandProperty FullName
      $zip.Dispose()
      if ($entries | Where-Object { $_.EndsWith(".apk") }) { $Format = "apk" }
      elseif ($entries | Where-Object { $_ -match "\.(msi|exe)$" }) { $Format = "win" }
    } catch { <# ignore #> }
  }
  if ($Format -ne "auto") {
    Write-Host " Format  : $Format (auto-detected)" -ForegroundColor Yellow
  }
}

# APK analyzer handles its own extraction internally — skip generic extractor
# (otherwise artifact-extractor unpacks the outer ZIP AND the APK-as-ZIP, leaving
#  no .apk file for apk-analyzer to find)
if ($Format -eq "apk") {
  if ($IsStandaloneApk) {
    $Extract = $false
    Write-Host " Extract : disabled for standalone APK (apk-analyzer extracts internally)" -ForegroundColor DarkGray
  } else {
    $Extract = $true
    Write-Host " Extract : enabled for APK archive wrapper" -ForegroundColor Yellow
  }
}

# ── Extract (optional) ────────────────────────────────────────────────────────

if ($Extract) {
  $repoRoot     = (Get-Location).Path
  $extractRel   = "artifacts\extracted\current"
  $extractHost  = Join-Path $repoRoot $extractRel
  New-Item -ItemType Directory -Force -Path $extractHost | Out-Null

  $env:EXTRACT_INPUT_HOST = $env:SCAN_TARGET_HOST
  $env:EXTRACT_OUTPUT     = "/workspace/$($extractRel -replace '\\','/')"
  $env:EXTRACT_MAX_DEPTH  = [string]$ExtractMaxDepth

  Invoke-ComposeChecked -Args @("--profile","extract","run","--rm","artifact-extractor")

  $env:SCAN_TARGET_HOST    = (Resolve-Path $extractHost).Path
  $env:SCAN_TARGET_DISPLAY = "$TargetResolved -> $env:SCAN_TARGET_HOST"
  $env:SYFT_TARGET         = "/scan-target"
  $env:SYFT_FROM           = "dir"
}

# ── Specialized format pipelines ─────────────────────────────────────────────

if ($Format -eq "apk") {
  Write-Host "[apk] Running APK analyzer…" -ForegroundColor Cyan
  Invoke-ComposeChecked -Args @("--profile","apk","run","--rm","apk-analyzer")

  # After APK analysis, run grype on the generated SBOM + cve-bin-tool on native libs
  Write-Host "[apk] Running grype on generated SBOM…" -ForegroundColor Cyan
  $env:SYFT_TARGET = "/workspace/artifacts/sbom/syft.json"
  $env:SYFT_FROM   = "sbom"

  if ($UpdateDb) {
    Invoke-ComposeChecked -Args @("--profile","update","run","--rm","grype-updater")
    Invoke-ComposeChecked -Args @("--profile","update","run","--rm","grype-db-importer")
  }
  Invoke-DbStatus -DbTool "grype" -DbPath "/var/lib/resilient-db/grype/active"
  Invoke-ComposeChecked -Args @("--profile",$Profile,"run","--rm","grype-scanner")

  # cve-bin-tool on extracted native libs (if any)
  $nativeDir = Join-Path $ArtifactsDir "extracted\apk-native"
  if (Test-Path $nativeDir) {
    $nativeFiles = Get-ChildItem $nativeDir -Recurse -Filter "*.so" -ErrorAction SilentlyContinue
    if ($nativeFiles.Count -gt 0) {
      Write-Host "[apk] Running cve-bin-tool on $($nativeFiles.Count) native .so files…" -ForegroundColor Cyan
      $env:CVE_BIN_TOOL_TARGET = "/workspace/artifacts/extracted/apk-native"
      $env:SCAN_TARGET_HOST    = (Resolve-Path $nativeDir).Path
      Invoke-DbStatus -DbTool "cve-bin-tool" -DbPath "/root/.cache/cve-bin-tool"
      Invoke-CveBinToolScannerChecked -Args @("--profile",$Profile,"run","--rm","cve-bin-tool-scanner")
    }
  }

} elseif ($Format -eq "win") {
  Write-Host "[win] Running Windows installer analyzer…" -ForegroundColor Cyan
  Invoke-ComposeChecked -Args @("--profile","win","run","--rm","win-analyzer")

  # Run grype on generated SBOM (PE version info → CPE matching)
  Write-Host "[win] Running grype on generated SBOM…" -ForegroundColor Cyan
  $env:SYFT_TARGET = "/workspace/artifacts/sbom/syft.json"
  $env:SYFT_FROM   = "sbom"

  if ($UpdateDb) {
    Invoke-ComposeChecked -Args @("--profile","update","run","--rm","grype-updater")
    Invoke-ComposeChecked -Args @("--profile","update","run","--rm","grype-db-importer")
    Invoke-ComposeChecked -Args @("--profile","update","run","--rm","cve-bin-tool-updater")
  }
  Invoke-DbStatus -DbTool "grype"        -DbPath "/var/lib/resilient-db/grype/active"
  Invoke-DbStatus -DbTool "cve-bin-tool" -DbPath "/root/.cache/cve-bin-tool"
  Invoke-ComposeChecked -Args @("--profile",$Profile,"run","--rm","grype-scanner")

  # cve-bin-tool binary scan on extracted files
  $winExtractDir = Join-Path $ArtifactsDir "extracted\win-installer"
  if (Test-Path $winExtractDir) {
    $cveScanHost      = (Resolve-Path $winExtractDir).Path
    $cveScanContainer = "/workspace/artifacts/extracted/win-installer"
    $forceDirectScan  = $false

    $winAnalysisTxt = Join-Path $ArtifactsDir "reports\win\win_analysis.txt"
    if (Test-Path $winAnalysisTxt) {
      $m = Select-String -Path $winAnalysisTxt -Pattern 'Binaries\s*:\s*(\d+)\s+total' -AllMatches -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($m -and $m.Matches.Count -gt 0 -and [int]$m.Matches[0].Groups[1].Value -eq 0) {
        $forceDirectScan = $true
        Write-Host "[win] 0 PE binaries detected; switching to direct installer fallback..." -ForegroundColor Yellow
      }
    }

    if ($forceDirectScan) {
      $cveScanHost      = $TargetResolved
      $cveScanContainer = "/scan-target"
      Write-Host "[win] Running cve-bin-tool on installer file fallback..." -ForegroundColor Cyan
    } else {
      Write-Host "[win] Running cve-bin-tool on extracted installer contents..." -ForegroundColor Cyan
    }
    $env:CVE_BIN_TOOL_TARGET = $cveScanContainer
    $env:SCAN_TARGET_HOST    = $cveScanHost
    Invoke-CveBinToolScannerChecked -Args @("--profile",$Profile,"run","--rm","cve-bin-tool-scanner")
  }

} else {

# ── Standard scan ──────────────────────────────────────────────────────────────────────

switch ($Tool) {
  "all" {
    if ($UpdateDb) {
      Invoke-ComposeChecked -Args @("--profile","update","run","--rm","-e","TRIVY_RENDERED_FLAGS=$trivyFlags","trivy-updater")
      Invoke-ComposeChecked -Args @("--profile","update","run","--rm","grype-updater")
      Invoke-ComposeChecked -Args @("--profile","update","run","--rm","grype-db-importer")
      Invoke-ComposeChecked -Args @("--profile","update","run","--rm","cve-bin-tool-updater")
    }
    Invoke-DbStatus -DbTool "trivy"        -DbPath "/var/lib/resilient-db/trivy"
    Invoke-DbStatus -DbTool "grype"        -DbPath "/var/lib/resilient-db/grype/active"
    Invoke-DbStatus -DbTool "cve-bin-tool" -DbPath "/root/.cache/cve-bin-tool"
    Invoke-ComposeChecked -Args @("--profile",$Profile,"run","--rm","syft-sbom")
    Invoke-ComposeChecked -Args @("--profile",$Profile,"run","--rm","-e","TRIVY_RENDERED_FLAGS=$trivyFlags","trivy-scanner")
    Invoke-ComposeChecked -Args @("--profile",$Profile,"run","--rm","grype-scanner")
    Invoke-CveBinToolScannerChecked -Args @("--profile",$Profile,"run","--rm","cve-bin-tool-scanner")
  }
  "syft" {
    Invoke-ComposeChecked -Args @("--profile",$Profile,"run","--rm","syft-sbom")
  }
  "grype" {
    if ($UpdateDb) {
      Invoke-ComposeChecked -Args @("--profile","update","run","--rm","grype-updater")
      Invoke-ComposeChecked -Args @("--profile","update","run","--rm","grype-db-importer")
    }
    Invoke-DbStatus -DbTool "grype" -DbPath "/var/lib/resilient-db/grype/active"
    Invoke-ComposeChecked -Args @("--profile",$Profile,"run","--rm","syft-sbom")
    Invoke-ComposeChecked -Args @("--profile",$Profile,"run","--rm","grype-scanner")
  }
  "trivy" {
    if ($UpdateDb) {
      Invoke-ComposeChecked -Args @("--profile","update","run","--rm","-e","TRIVY_RENDERED_FLAGS=$trivyFlags","trivy-updater")
    }
    Invoke-DbStatus -DbTool "trivy" -DbPath "/var/lib/resilient-db/trivy"
    Invoke-ComposeChecked -Args @("--profile",$Profile,"run","--rm","-e","TRIVY_RENDERED_FLAGS=$trivyFlags","trivy-scanner")
  }
  "cve-bin-tool" {
    if ($UpdateDb) {
      Invoke-ComposeChecked -Args @("--profile","update","run","--rm","cve-bin-tool-updater")
    }
    Invoke-DbStatus -DbTool "cve-bin-tool" -DbPath "/root/.cache/cve-bin-tool"
    Invoke-CveBinToolScannerChecked -Args @("--profile",$Profile,"run","--rm","cve-bin-tool-scanner")
  }
}

} # end if ($Format -eq "auto") else branch

# ── Collect reports ───────────────────────────────────────────────────────────

$env:CASE_ID = $CaseId
Invoke-ComposeChecked -Args @("--profile","report","run","--rm","report-collector")

# Generate Markdown report next to source file
python -m resilient_updates.cli collect-report `
  --reports-dir artifacts `
  --target      $env:SCAN_TARGET_HOST `
  --display-target $env:SCAN_TARGET_DISPLAY `
  --case-id     $CaseId `
  --output      $ReportMd | Out-Host
if ($LASTEXITCODE -ne 0) { throw "Markdown report generation failed (exit $LASTEXITCODE)" }

# Generate HTML report next to source file
python scripts/report_html.py `
  --artifacts-dir artifacts `
  --target        $env:SCAN_TARGET_DISPLAY `
  --output        $ReportHtml
if ($LASTEXITCODE -ne 0) {
  Write-Warning "HTML report generation failed — skipping"
}

# Snapshot per-run evidence into a project-timestamp directory.  Default `auto`
# saves next to the source when possible and falls back to artifacts\runs.
$archiveArgs = @(
  "-m", "resilient_updates.cli", "archive-run",
  "--artifacts-dir", $ArtifactsDir,
  "--target-host", $TargetResolved,
  "--target-container", $env:SCAN_TARGET_HOST,
  "--case-id", $CaseId,
  "--mode", $ArtifactMode,
  "--stage", "final",
  "--status", "done"
)
if ($env:EL_SCA_ARCHIVE_EXTRACTED_TREE -match '^(1|true|yes|on)$') {
  $archiveArgs += "--include-extracted-tree"
}
try {
  python @archiveArgs | Out-Host
} catch {
  Write-Warning "archive-run failed: $($_.Exception.Message)"
}

# ── Done ──────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host " Reports ready:" -ForegroundColor Green
Write-Host "   MD  : $ReportMd"   -ForegroundColor White
Write-Host "   HTML: $ReportHtml" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host ""

# Re-show DB freshness AFTER the scan so the final state stays on screen.
Show-DbFreshnessBanner -Title 'DATABASE FRESHNESS (POST-SCAN)'
