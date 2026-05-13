param(
  [string]$Target = "D:\!ya_drive_sync\YandexDisk\rostel\to_analyze\_to_verify_logic_CYBERSEC-11531\test\prometheus-3.11.0.linux-amd64.tar.gz_extracted\prometheus-3.11.0.linux-amd64\prometheus-3.11.0.linux-amd64",
  [string]$Profile = "scan",
  [string]$Tool = "grype",
  [string]$ReportOutput = "D:\!ya_drive_sync\YandexDisk\rostel\to_analyze\_to_verify_logic_CYBERSEC-11531\test\cve_analysis_report_2026-05-13_ru.generated.md"
)

$ErrorActionPreference = "Stop"
function Invoke-ComposeChecked {
  param(
    [Parameter(Mandatory=$true)]
    [string[]]$Args
  )
  & docker compose @Args
  if ($LASTEXITCODE -ne 0) {
    throw "docker compose failed with exit code $LASTEXITCODE: $($Args -join ' ')"
  }
}

docker --version | Out-Null
docker compose version | Out-Null
if (-not (Test-Path $Target)) {
  throw "Target path does not exist: $Target"
}
$env:SCAN_TARGET_HOST = (Resolve-Path $Target).Path
$env:SCAN_TARGET_CONTAINER = "/scan-target"
$env:SCAN_TARGET_DISPLAY = $env:SCAN_TARGET_HOST
$env:SYFT_TARGET = "/scan-target"
$env:SYFT_FROM = "dir"
$env:TRIVY_TARGET = "/scan-target"
$env:CVE_BIN_TOOL_TARGET = "/scan-target"
$env:REPORT_OUTPUT = "/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md"
Invoke-ComposeChecked -Args @("--profile", $Profile, "run", "--rm", "syft-sbom")
Invoke-ComposeChecked -Args @("--profile", $Profile, "run", "--rm", "grype-scanner")
Invoke-ComposeChecked -Args @("--profile", "report", "run", "--rm", "report-collector")
python -m resilient_updates.cli collect-report --reports-dir artifacts --target $env:SCAN_TARGET_HOST --display-target $env:SCAN_TARGET_DISPLAY --output $ReportOutput | Out-Host
if ($LASTEXITCODE -ne 0) {
  throw "report generation failed with exit code $LASTEXITCODE"
}
