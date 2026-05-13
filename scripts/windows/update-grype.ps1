param()

$ErrorActionPreference = "Stop"
docker --version | Out-Null
docker compose version | Out-Null
New-Item -ItemType Directory -Force -Path "artifacts/internal/grype","artifacts/provenance" | Out-Null
docker compose run --rm grype-updater update grype
