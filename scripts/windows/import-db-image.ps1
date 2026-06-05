<#
.SYNOPSIS
  Restore vulnerability DBs from a data image on a fresh host (Windows).
.DESCRIPTION
  Mirrors scripts/import_db_image.sh: pulls the data image, unpacks /db-bundle
  into ./incoming, restores volumes via compose db-importer, activates Grype.
.EXAMPLE
  .\scripts\windows\import-db-image.ps1
  .\scripts\windows\import-db-image.ps1 -Image registry.example/group/db-data:20260605
#>
param(
  [string]$Image = $env:DB_IMAGE
)
$ErrorActionPreference = "Stop"
if (-not $Image) {
  $Image = "registry.gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble/db-data:latest"
}
# Compose interpolates the whole file (incl. the ${SCAN_TARGET_HOST:?} guard)
# before selecting a profile — set a harmless value so db-bundle commands run.
if (-not $env:SCAN_TARGET_HOST) { $env:SCAN_TARGET_HOST = "/tmp/el-sca-db-bundle-noscan" }

New-Item -ItemType Directory -Force -Path incoming | Out-Null

Write-Host "==> [1/4] pulling $Image"
docker pull $Image

Write-Host "==> [2/4] extracting bundle into ./incoming"
docker run --rm -v "${PWD}/incoming:/out" $Image sh -c "cp -v /db-bundle/*.tar.gz /out/"

Write-Host "==> [3/4] restoring DB volumes via compose db-importer"
docker compose --profile db-bundle run --rm db-importer

Write-Host "==> [4/4] activating Grype snapshot"
docker compose --profile airgap run --rm grype-db-importer

Write-Host "done. DB volumes populated — the stack can scan with bundled databases."
