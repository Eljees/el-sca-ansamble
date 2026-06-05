param(
  [string]$Target = "alpine:latest",
  [string]$Mode = "update"
)

$ErrorActionPreference = "Stop"
function Import-LocalEnv {
  $envFile = Join-Path (Get-Location).Path ".env.local"
  if (-not (Test-Path $envFile)) { return }
  foreach ($line in Get-Content $envFile) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line.TrimStart().StartsWith("#")) { continue }
    $parts = $line -split "=", 2
    if ($parts.Count -ne 2) { continue }
    [Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), "Process")
  }
}
function Initialize-ComposePlaceholders {
  $placeholder = (Get-Location).Path
  if (-not $env:SCAN_TARGET_HOST)    { $env:SCAN_TARGET_HOST = $placeholder }
  if (-not $env:EXTRACT_INPUT_HOST)  { $env:EXTRACT_INPUT_HOST = $placeholder }
  if (-not $env:SCAN_TARGET_DISPLAY) { $env:SCAN_TARGET_DISPLAY = $placeholder }
  if (-not $env:REPORT_OUTPUT)       { $env:REPORT_OUTPUT = "/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md" }
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
Initialize-ComposePlaceholders
New-Item -ItemType Directory -Force -Path "artifacts/reports/trivy","artifacts/provenance","artifacts/cache/trivy" | Out-Null
$flags = python -m resilient_updates.cli render-flags trivy
if ($LASTEXITCODE -ne 0) {
  throw "failed to render trivy flags"
}
Invoke-ComposeChecked -Args @("run", "--rm", "-e", "TRIVY_TARGET=$Target", "-e", "TRIVY_RENDERED_FLAGS=$flags", "trivy-updater", $Mode, $Target)
