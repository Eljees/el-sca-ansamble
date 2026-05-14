param(
  [string]$Target = "alpine:latest",
  [string]$Mode = "update"
)

$ErrorActionPreference = "Stop"
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
New-Item -ItemType Directory -Force -Path "artifacts/reports/trivy","artifacts/provenance","artifacts/cache/trivy" | Out-Null
$flags = python -m resilient_updates.cli render-flags trivy
if ($LASTEXITCODE -ne 0) {
  throw "failed to render trivy flags"
}
Invoke-ComposeChecked -Args @("run", "--rm", "-e", "TRIVY_TARGET=$Target", "-e", "TRIVY_RENDERED_FLAGS=$flags", "trivy-updater", $Mode, $Target)
