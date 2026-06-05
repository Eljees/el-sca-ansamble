<#
.SYNOPSIS
  Build the LIGHT bundle (Trivy + Grype + Syft, no cve-bin-tool) straight into
  bundle/ so it ships INSIDE the repo via Git LFS.
.DESCRIPTION
  Writes bundle/el-sca-images-light.tar + bundle/grype-db.tar.gz +
  bundle/trivy-cache.tar.gz.  After this:
    git lfs install
    git add -A && git commit -m "ship bundle" && git push gitlab master
  A clone then brings everything; deploy with scripts/windows/deploy-light.ps1.
  Run on a machine WITH network + Docker.
#>
param([string]$Out = "bundle")
$ErrorActionPreference = "Stop"
$env:SCAN_TARGET_HOST = "/tmp/x"   # satisfies the ${SCAN_TARGET_HOST:?} compose guard
$env:COMPOSE_PROJECT_NAME = "el-sca-ansamble"   # stable image prefix for the bundle
$profiles = @("--profile", "scan", "--profile", "report", "--profile", "db-bundle")
New-Item -ItemType Directory -Force -Path $Out | Out-Null

Write-Host "==> [1/5] building local images (no cve-bin-tool)"
docker compose --profile scan --profile report build artifact-extractor report-collector stack-info db-admin

Write-Host "==> [2/5] pulling public images (trivy / grype / syft / python / alpine)"
docker compose @profiles pull --ignore-buildable

Write-Host "==> [3/5] saving stack images (excluding cve-bin-tool) -> $Out"
$imgs = docker compose @profiles config --images | Sort-Object -Unique | Where-Object { $_ -notmatch "cve-bin-tool" }
$imgs | ForEach-Object { Write-Host "    $_" }
docker save $imgs -o (Join-Path $Out "el-sca-images-light.tar")

Write-Host "==> [4/5] exporting Grype + Trivy DBs"
docker compose --profile db-bundle run --rm db-exporter

Write-Host "==> [5/5] collecting DBs into $Out"
Copy-Item artifacts\db-image\grype-db.tar.gz, artifacts\db-image\trivy-cache.tar.gz $Out -Force
# grype-cache is regenerated on the target from grype-db; ship it too if you want
# faster first scan: Copy-Item artifacts\db-image\grype-cache.tar.gz $Out -Force

$tar = Join-Path $Out "el-sca-images-light.tar"
Write-Host ""
Write-Host ("done.  bundle ready in {0}\  ({1:N2} GB images + Grype/Trivy DBs)" -f $Out, ((Get-Item $tar).Length / 1GB))
Write-Host "Next:  git lfs install; git add -A; git commit -m 'ship bundle'; git push gitlab master"
