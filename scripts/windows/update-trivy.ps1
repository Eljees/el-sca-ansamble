param(
  [string]$Target = "alpine:latest",
  [string]$Mode = "update"
)

$ErrorActionPreference = "Stop"
docker --version | Out-Null
docker compose version | Out-Null
New-Item -ItemType Directory -Force -Path "artifacts/reports/trivy","artifacts/provenance","artifacts/cache/trivy" | Out-Null
docker compose run --rm -e TRIVY_TARGET=$Target trivy-updater /bin/sh /workspace/scripts/update_trivy.sh $Mode $Target
