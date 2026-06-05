<#
.SYNOPSIS
  Build & save a LIGHT handoff bundle: Trivy + Grype + Syft, WITHOUT cve-bin-tool.
.DESCRIPTION
  Produces, in -Out (default: current dir):
    el-sca-images-light.tar              all stack images except cve-bin-tool
    artifacts\db-image\grype-db.tar.gz   Grype DB
    artifacts\db-image\trivy-cache.tar.gz Trivy DB
    artifacts\db-image\grype-cache.tar.gz (optional — regenerated on target)
  Run on a machine WITH network + Docker.  Pair with deploy-light.ps1 on the target.
.EXAMPLE
  .\scripts\windows\pack-light.ps1
#>
param([string]$Out = (Get-Location))
$ErrorActionPreference = "Stop"
$env:SCAN_TARGET_HOST = "/tmp/x"   # satisfies the ${SCAN_TARGET_HOST:?} compose guard
$profiles = @("--profile", "scan", "--profile", "report", "--profile", "db-bundle")

Write-Host "==> [1/4] building local images (no cve-bin-tool)"
docker compose --profile scan --profile report build artifact-extractor report-collector stack-info db-admin

Write-Host "==> [2/4] pulling public images (trivy / grype / syft / python / alpine)"
docker compose @profiles pull --ignore-buildable

Write-Host "==> [3/4] saving stack images (excluding cve-bin-tool)"
$imgs = docker compose @profiles config --images | Sort-Object -Unique | Where-Object { $_ -notmatch "cve-bin-tool" }
$imgs | ForEach-Object { Write-Host "    $_" }
docker save $imgs -o (Join-Path $Out "el-sca-images-light.tar")

Write-Host "==> [4/4] exporting Grype + Trivy DBs"
docker compose --profile db-bundle run --rm db-exporter
# drop the empty cve-bin-tool placeholders produced by db-exporter
Remove-Item -ErrorAction SilentlyContinue `
  artifacts\db-image\cve-bin-tool-cache.tar.gz, artifacts\db-image\internal-mirror-data.tar.gz

$tar = Join-Path $Out "el-sca-images-light.tar"
Write-Host ""
Write-Host "done."
Write-Host ("  images : {0:N2} GB  ({1})" -f ((Get-Item $tar).Length / 1GB), $tar)
Write-Host "  DBs    : artifacts\db-image\grype-db.tar.gz, trivy-cache.tar.gz (+ optional grype-cache.tar.gz)"
Write-Host ""
Write-Host "Ship the repo + el-sca-images-light.tar + the db-image\*.tar.gz, then run deploy-light.ps1 on the target."
