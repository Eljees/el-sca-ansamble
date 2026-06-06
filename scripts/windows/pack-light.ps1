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
param([string]$Out = "bundle", [switch]$WithCveBinTool)
$ErrorActionPreference = "Stop"
$env:SCAN_TARGET_HOST = "/tmp/x"   # satisfies the ${SCAN_TARGET_HOST:?} compose guard
$env:COMPOSE_PROJECT_NAME = "el-sca-ansamble"   # stable image prefix for the bundle
$profiles = @("--profile", "scan", "--profile", "report", "--profile", "db-bundle")
New-Item -ItemType Directory -Force -Path $Out | Out-Null

Write-Host "==> [1/5] building local images"
$buildSvcs = @("artifact-extractor", "report-collector", "stack-info", "db-admin")
if ($WithCveBinTool) {
  # Ship cve-bin-tool too: build its scanner image so the bundle is complete
  # (cve.db alone is useless without the image that reads it).
  $buildSvcs += "cve-bin-tool-scanner"
}
docker compose --profile scan --profile report build @buildSvcs

Write-Host "==> [2/5] pulling public images (trivy / grype / syft / python / alpine)"
docker compose @profiles pull --ignore-buildable

if ($WithCveBinTool) {
  Write-Host "==> [3/5] saving stack images (incl. cve-bin-tool) -> $Out"
  $imgs = docker compose @profiles config --images | Sort-Object -Unique
} else {
  Write-Host "==> [3/5] saving stack images (excluding cve-bin-tool) -> $Out"
  $imgs = docker compose @profiles config --images | Sort-Object -Unique | Where-Object { $_ -notmatch "cve-bin-tool" }
}
$imgs | ForEach-Object { Write-Host "    $_" }
docker save $imgs -o (Join-Path $Out "el-sca-images-light.tar")

Write-Host "==> [4/5] exporting Grype + Trivy DBs"
docker compose --profile db-bundle run --rm db-exporter

Write-Host "==> [5/5] collecting DBs into $Out"
$dbfiles = @("grype-db.tar.gz", "trivy-cache.tar.gz")
if ($WithCveBinTool) {
  # Ship the cve-bin-tool SCAN db (cve-bin-tool-cache holds cve.db).  The 45 GB
  # internal-mirror-data (json-mirror source) is NOT shipped — the scanner only
  # needs cve.db.  Build a slim NVD-only cve.db first (see docs) to keep it small.
  $dbfiles += "cve-bin-tool-cache.tar.gz"
  Write-Host "    + cve-bin-tool-cache (cve.db) — internal-mirror-data (45GB) NOT included"
}
Copy-Item ($dbfiles | ForEach-Object { "artifacts\db-image\$_" }) $Out -Force
# grype-cache is regenerated on the target from grype-db; ship it too if you want
# faster first scan: Copy-Item artifacts\db-image\grype-cache.tar.gz $Out -Force

Write-Host "==> splitting files >480MB into .partNNN (GitLab LFS rejects big objects with HTTP 413)"
$chunk = 480MB
Get-ChildItem (Join-Path $Out "*.tar"), (Join-Path $Out "*.tar.gz") -ErrorAction SilentlyContinue |
  Where-Object { $_.Length -gt $chunk } | ForEach-Object {
    $f = $_.FullName; $fs = [IO.File]::OpenRead($f); $buf = New-Object byte[] $chunk; $i = 0
    while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) {
      $part = "{0}.part{1:D3}" -f $f, $i
      $o = [IO.File]::OpenWrite($part); $o.Write($buf, 0, $n); $o.Close(); $i++
    }
    $fs.Close(); Remove-Item $f; Write-Host ("    {0} -> {1} parts" -f $_.Name, $i)
  }
Write-Host ""
Write-Host "done.  bundle ready in $Out\ (large files split into <500MB parts; deploy reassembles)."
Write-Host "Next:  git lfs install; git add -A; git commit -m 'ship bundle'; git push gitlab master"
