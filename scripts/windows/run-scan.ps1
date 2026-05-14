param(
  [string]$Target = "D:\!ya_drive_sync\YandexDisk\rostel\to_analyze\_to_verify_logic_CYBERSEC-11531\test\prometheus-3.11.0.linux-amd64.tar.gz_extracted\prometheus-3.11.0.linux-amd64\prometheus-3.11.0.linux-amd64",
  [string]$Profile = "scan",
  [ValidateSet("all","syft","grype","trivy","cve-bin-tool")]
  [string]$Tool = "all",
  [string]$ReportOutput = "D:\!ya_drive_sync\YandexDisk\rostel\to_analyze\_to_verify_logic_CYBERSEC-11531\test\cve_analysis_report_2026-05-13_ru.generated.md",
  [switch]$UpdateDb,
  [switch]$Extract,
  [string]$ExtractOutput = "artifacts\extracted\current",
  [int]$ExtractMaxDepth = 4
)

$ErrorActionPreference = "Stop"

function Import-LocalEnv {
  $envFile = Join-Path (Get-Location).Path ".env.local"
  if (-not (Test-Path $envFile)) {
    return
  }
  foreach ($line in Get-Content $envFile) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line.TrimStart().StartsWith("#")) { continue }
    $parts = $line -split "=", 2
    if ($parts.Count -ne 2) { continue }
    $name = $parts[0].Trim()
    $value = $parts[1].Trim()
    [Environment]::SetEnvironmentVariable($name, $value, "Process")
  }
}

function Invoke-ComposeChecked {
  param(
    [Parameter(Mandatory=$true)]
    [string[]]$Args
  )
  & docker compose @Args
  if ($LASTEXITCODE -ne 0) {
    throw "docker compose failed with exit code ${LASTEXITCODE}: $($Args -join ' ')"
  }
}

docker --version | Out-Null
docker compose version | Out-Null
Import-LocalEnv
if (-not (Test-Path $Target)) {
  throw "Target path does not exist: $Target"
}
$trivyFlags = python -m resilient_updates.cli render-flags trivy
if ($LASTEXITCODE -ne 0) {
  throw "failed to render trivy flags"
}
$env:SCAN_TARGET_HOST = (Resolve-Path $Target).Path
$env:SCAN_TARGET_CONTAINER = "/scan-target"
$env:SCAN_TARGET_DISPLAY = $env:SCAN_TARGET_HOST
$env:SYFT_TARGET = "/scan-target"
$env:SYFT_FROM = "dir"
$env:TRIVY_TARGET = "/scan-target"
$env:CVE_BIN_TOOL_TARGET = "/scan-target"
$env:REPORT_OUTPUT = "/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md"

if ($Extract) {
  $repoRoot = (Get-Location).Path
  if ([System.IO.Path]::IsPathRooted($ExtractOutput)) {
    throw "ExtractOutput must be relative to the repository so Docker can write it through the workspace bind mount: $ExtractOutput"
  }
  $extractHost = Join-Path $repoRoot $ExtractOutput
  New-Item -ItemType Directory -Force -Path $extractHost | Out-Null
  $env:EXTRACT_INPUT_HOST = $env:SCAN_TARGET_HOST
  $env:EXTRACT_OUTPUT = "/workspace/$($ExtractOutput -replace '\\','/')"
  $env:EXTRACT_MAX_DEPTH = [string]$ExtractMaxDepth
  Invoke-ComposeChecked -Args @("--profile", "extract", "run", "--rm", "artifact-extractor")
  $env:SCAN_TARGET_HOST = (Resolve-Path $extractHost).Path
  $env:SCAN_TARGET_DISPLAY = "$Target -> $env:SCAN_TARGET_HOST"
}

function Invoke-DbStatus {
  param(
    [Parameter(Mandatory=$true)]
    [string]$Tool,
    [Parameter(Mandatory=$true)]
    [string]$Path
  )
  & docker compose run --rm db-admin db-status $Tool --path $Path --warning-age 24h
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "db-status check for $Tool returned exit code $LASTEXITCODE"
  }
}

switch ($Tool) {
  "all" {
    if ($UpdateDb) {
      Invoke-ComposeChecked -Args @("--profile", "update", "run", "--rm", "-e", "TRIVY_RENDERED_FLAGS=$trivyFlags", "trivy-updater")
      Invoke-ComposeChecked -Args @("--profile", "update", "run", "--rm", "grype-updater")
      Invoke-ComposeChecked -Args @("--profile", "update", "run", "--rm", "grype-db-importer")
      Invoke-ComposeChecked -Args @("--profile", "update", "run", "--rm", "cve-bin-tool-updater")
    }
    Invoke-DbStatus -Tool "trivy" -Path "/var/lib/resilient-db/trivy"
    Invoke-DbStatus -Tool "grype" -Path "/var/lib/resilient-db/grype/active"
    Invoke-DbStatus -Tool "cve-bin-tool" -Path "/root/.cache/cve-bin-tool"
    Invoke-ComposeChecked -Args @("--profile", $Profile, "run", "--rm", "syft-sbom")
    Invoke-ComposeChecked -Args @("--profile", $Profile, "run", "--rm", "-e", "TRIVY_RENDERED_FLAGS=$trivyFlags", "trivy-scanner")
    Invoke-ComposeChecked -Args @("--profile", $Profile, "run", "--rm", "grype-scanner")
    Invoke-ComposeChecked -Args @("--profile", $Profile, "run", "--rm", "cve-bin-tool-scanner")
  }
  "syft" { Invoke-ComposeChecked -Args @("--profile", $Profile, "run", "--rm", "syft-sbom") }
  "grype" {
    if ($UpdateDb) {
      Invoke-ComposeChecked -Args @("--profile", "update", "run", "--rm", "grype-updater")
      Invoke-ComposeChecked -Args @("--profile", "update", "run", "--rm", "grype-db-importer")
    }
    Invoke-DbStatus -Tool "grype" -Path "/var/lib/resilient-db/grype/active"
    Invoke-ComposeChecked -Args @("--profile", $Profile, "run", "--rm", "syft-sbom")
    Invoke-ComposeChecked -Args @("--profile", $Profile, "run", "--rm", "grype-scanner")
  }
  "trivy" {
    if ($UpdateDb) {
      Invoke-ComposeChecked -Args @("--profile", "update", "run", "--rm", "-e", "TRIVY_RENDERED_FLAGS=$trivyFlags", "trivy-updater")
    }
    Invoke-DbStatus -Tool "trivy" -Path "/var/lib/resilient-db/trivy"
    Invoke-ComposeChecked -Args @("--profile", $Profile, "run", "--rm", "-e", "TRIVY_RENDERED_FLAGS=$trivyFlags", "trivy-scanner")
  }
  "cve-bin-tool" {
    if ($UpdateDb) {
      Invoke-ComposeChecked -Args @("--profile", "update", "run", "--rm", "cve-bin-tool-updater")
    }
    Invoke-DbStatus -Tool "cve-bin-tool" -Path "/root/.cache/cve-bin-tool"
    Invoke-ComposeChecked -Args @("--profile", $Profile, "run", "--rm", "cve-bin-tool-scanner")
  }
}

Invoke-ComposeChecked -Args @("--profile", "report", "run", "--rm", "report-collector")
python -m resilient_updates.cli collect-report --reports-dir artifacts --target $env:SCAN_TARGET_HOST --display-target $env:SCAN_TARGET_DISPLAY --output $ReportOutput | Out-Host
if ($LASTEXITCODE -ne 0) {
  throw "report generation failed with exit code $LASTEXITCODE"
}
