<#
.SYNOPSIS
  Deploy a LIGHT bundle on a target host: load images, restore DBs, set strict offline.
.DESCRIPTION
  Expects el-sca-images-light.tar and the db-image *.tar.gz files in -BundleDir.
  Configures .env for strict offline + cve-bin-tool skip, loads images, restores
  the Grype/Trivy DBs into volumes, and activates the Grype snapshot.
  Requires Docker; needs NO network.
.EXAMPLE
  .\scripts\windows\deploy-light.ps1 -BundleDir D:\incoming
#>
param([string]$BundleDir = "")
$ErrorActionPreference = "Stop"
# Default to the in-repo LFS bundle/ (shipped via Git LFS); fall back to cwd.
if (-not $BundleDir) {
  if (Test-Path "bundle\el-sca-images-light.tar") { $BundleDir = "bundle" } else { $BundleDir = (Get-Location) }
}

Write-Host "==> [1/4] configuring .env (strict offline + skip cve-bin-tool)"
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
$envText = Get-Content .env -Raw
if ($envText -notmatch "(?m)^\s*COMPOSE_FILE=") {
  Add-Content .env "COMPOSE_FILE=docker-compose.yml:docker-compose.offline.yml"
}
if ($envText -notmatch "(?m)^\s*EL_SCA_SKIP_CVEBT=") {
  Add-Content .env "EL_SCA_SKIP_CVEBT=1"
}

Write-Host "==> [2/4] loading images"
docker load -i (Join-Path $BundleDir "el-sca-images-light.tar")

Write-Host "==> [3/4] restoring Grype + Trivy DB volumes"
New-Item -ItemType Directory -Force -Path incoming | Out-Null
Copy-Item (Join-Path $BundleDir "*.tar.gz") incoming\ -Force
$env:SCAN_TARGET_HOST = "/tmp/x"
docker compose --profile db-bundle run --rm db-importer

Write-Host "==> [4/4] activating Grype snapshot"
docker compose --profile airgap run --rm grype-db-importer

Write-Host ""
Write-Host "done — fully offline, no downloads on scan."
Write-Host "Start the GUI:  python -m resilient_updates.cli dashboard --repo-root . --port 8088"
