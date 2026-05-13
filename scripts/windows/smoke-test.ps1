param(
  [string]$Target = "alpine:latest",
  [string]$From = "registry",
  [string]$Profile = "scan"
)

$ErrorActionPreference = "Stop"
docker --version | Out-Null
docker compose version | Out-Null
New-Item -ItemType Directory -Force -Path "artifacts/reports","artifacts/provenance","artifacts/sbom","artifacts/cache","artifacts/mirror" | Out-Null
docker compose --profile default --profile update --profile scan --profile test-failover --profile offline --profile report config | Out-Null
python -m resilient_updates.cli validate-config | Out-Null
pytest -q
Write-Host "Smoke test completed for profile $Profile with target $Target from $From"
