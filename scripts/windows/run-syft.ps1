param(
  [string]$Target = "alpine:latest",
  [string]$From = "registry"
)

$ErrorActionPreference = "Stop"
docker --version | Out-Null
docker compose version | Out-Null
New-Item -ItemType Directory -Force -Path "artifacts/sbom" | Out-Null
docker compose run --rm -e SYFT_TARGET=$Target -e SYFT_FROM=$From syft-sbom /bin/sh /workspace/scripts/run_syft.sh $Target $From /workspace/artifacts/sbom
