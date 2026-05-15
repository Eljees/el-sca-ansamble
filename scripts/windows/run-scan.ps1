param(
  # Path to the file or directory to scan (required)
  [Parameter(Mandatory=$true)]
  [string]$Target,

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

  # Also pull fresh DB before scanning
  [switch]$UpdateDb,

  # Unpack archive before scanning
  [switch]$Extract,
  [int]$ExtractMaxDepth = 4,

  # Clean artifacts/ before this run (recommended between scans)
  [switch]$Clean
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

function Invoke-ComposeChecked {
  param([Parameter(Mandatory=$true)][string[]]$Args)
  & docker compose @Args
  if ($LASTEXITCODE -ne 0) {
    throw "docker compose failed (exit $LASTEXITCODE): $($Args -join ' ')"
  }
}

function Invoke-CveBinToolChecked {
  param([Parameter(Mandatory=$true)][string[]]$Args)
  & docker compose @Args
  # cve-bin-tool exits with 1 when CVEs are found (success state), 0 when none found
  if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1) {
    throw "cve-bin-tool failed (exit $LASTEXITCODE): $($Args -join ' ')"
  }
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

# ── Pre-flight checks ─────────────────────────────────────────────────────────

docker --version     | Out-Null
docker compose version | Out-Null
Import-LocalEnv

if (-not (Test-Path $Target)) {
  throw "Target does not exist: $Target"
}

# ── Derive output paths from target filename ──────────────────────────────────

$TargetResolved = (Resolve-Path $Target).Path
$TargetDir      = Split-Path $TargetResolved -Parent
$RawName        = [System.IO.Path]::GetFileName($TargetResolved)
$TargetKind     = if ((Get-Item $TargetResolved).PSIsContainer) { "dir" } else { "file" }

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

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host " SCA Pipeline" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host " Target  : $TargetResolved" -ForegroundColor White
Write-Host " MD out  : $ReportMd"       -ForegroundColor Gray
Write-Host " HTML out: $ReportHtml"     -ForegroundColor Gray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# ── Clean artifacts from previous run ────────────────────────────────────────

if ($Clean) {
  Write-Host "[clean] Removing previous artifacts..." -ForegroundColor Yellow
  Get-ChildItem -Path $ArtifactsDir -Recurse -File |
    Where-Object { $_.Name -ne ".gitkeep" } |
    Remove-Item -Force
  Write-Host "[clean] Done." -ForegroundColor Yellow
  Write-Host ""
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
$env:SYFT_TARGET           = "/scan-target"
$env:SYFT_FROM             = "dir"
$env:TRIVY_TARGET          = "/scan-target"
$env:CVE_BIN_TOOL_TARGET   = "/scan-target"
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
      Invoke-CveBinToolChecked -Args @("--profile",$Profile,"run","--rm","cve-bin-tool-scanner")
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
    Write-Host "[win] Running cve-bin-tool binary scan on extracted installer contents…" -ForegroundColor Cyan
    $env:CVE_BIN_TOOL_TARGET = "/workspace/artifacts/extracted/win-installer"
    $env:SCAN_TARGET_HOST    = (Resolve-Path $winExtractDir).Path
    Invoke-CveBinToolChecked -Args @("--profile",$Profile,"run","--rm","cve-bin-tool-scanner")
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
    Invoke-CveBinToolChecked -Args @("--profile",$Profile,"run","--rm","cve-bin-tool-scanner")
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
    Invoke-CveBinToolChecked -Args @("--profile",$Profile,"run","--rm","cve-bin-tool-scanner")
  }
}

} # end if ($Format -eq "auto") else branch

# ── Collect reports ───────────────────────────────────────────────────────────

Invoke-ComposeChecked -Args @("--profile","report","run","--rm","report-collector")

# Generate Markdown report next to source file
python -m resilient_updates.cli collect-report `
  --reports-dir artifacts `
  --target      $env:SCAN_TARGET_HOST `
  --display-target $env:SCAN_TARGET_DISPLAY `
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

# ── Done ──────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host " Reports ready:" -ForegroundColor Green
Write-Host "   MD  : $ReportMd"   -ForegroundColor White
Write-Host "   HTML: $ReportHtml" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host ""
