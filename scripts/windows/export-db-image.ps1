<#
.SYNOPSIS
  Snapshot the current vulnerability DBs into a data image (Windows).
.DESCRIPTION
  Mirrors scripts/export_db_image.sh: runs the compose db-exporter, builds
  Dockerfile.db-data from ./artifacts/db-image, optionally pushes to the registry.
.EXAMPLE
  .\scripts\windows\export-db-image.ps1 -Push
  .\scripts\windows\export-db-image.ps1 -Image registry.example/group/db-data -Tag 20260605 -Push
#>
param(
  [string]$Image = $env:DB_IMAGE,
  [string]$Tag   = (Get-Date -Format "yyyyMMdd"),
  [switch]$Push
)
$ErrorActionPreference = "Stop"
if (-not $Image) {
  $Image = "registry.gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble/db-data"
}
# Compose interpolates the whole file (incl. the ${SCAN_TARGET_HOST:?} guard)
# before selecting a profile — set a harmless value so db-bundle commands run.
if (-not $env:SCAN_TARGET_HOST) { $env:SCAN_TARGET_HOST = "/tmp/el-sca-db-bundle-noscan" }

Write-Host "==> [1/3] exporting DB volumes via compose db-exporter"
docker compose --profile db-bundle run --rm db-exporter

Write-Host "==> [2/3] building data image ${Image}:${Tag} (+ :latest)"
docker build -f Dockerfile.db-data -t "${Image}:${Tag}" -t "${Image}:latest" artifacts/db-image

if ($Push) {
  Write-Host "==> [3/3] pushing ${Image}:${Tag} and :latest"
  docker push "${Image}:${Tag}"
  docker push "${Image}:latest"
} else {
  Write-Host "==> [3/3] skipped push (add -Push to upload)"
}
Write-Host "done: ${Image}:${Tag}"
