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
  # Windows uses ';' as the COMPOSE_FILE path separator (Linux uses ':').
  Add-Content .env "COMPOSE_FILE=docker-compose.yml;docker-compose.offline.yml"
}
if ($envText -notmatch "(?m)^\s*EL_SCA_SKIP_CVEBT=") {
  # Skip cve-bin-tool only if its DB is NOT in the bundle (no cve-bin-tool-cache).
  $cvebt = (Test-Path (Join-Path $BundleDir "cve-bin-tool-cache.tar.gz")) -or
           ((Get-ChildItem (Join-Path $BundleDir "cve-bin-tool-cache.tar.gz.part*") -ErrorAction SilentlyContinue) | Measure-Object).Count -gt 0
  Add-Content .env ("EL_SCA_SKIP_CVEBT=" + $(if ($cvebt) { "0" } else { "1" }))
}
# Pin the project name so compose finds the bundled el-sca-ansamble-* images and
# the restored el-sca-ansamble_* volumes regardless of the clone folder name.
# Without this, a folder called e.g. "el-sca-test" makes compose look for
# "el-sca-test-*" images, not find them, and try to BUILD (which fails offline).
if ($envText -notmatch "(?m)^\s*COMPOSE_PROJECT_NAME=") {
  Add-Content .env "COMPOSE_PROJECT_NAME=el-sca-ansamble"
}

# Reassemble any split bundle files (<name>.partNNN -> <name>); large files are
# chunked under ~500 MB so GitLab LFS accepts them (HTTP 413 on big objects).
foreach ($base in @("el-sca-images-light.tar", "grype-db.tar.gz", "trivy-cache.tar.gz", "cve-bin-tool-cache.tar.gz")) {
  $full = Join-Path $BundleDir $base
  $parts = Get-ChildItem "$full.part*" -ErrorAction SilentlyContinue | Sort-Object Name
  if ((-not (Test-Path $full)) -and $parts) {
    Write-Host "==> reassembling $base from $($parts.Count) parts"
    $out = [IO.File]::OpenWrite($full)
    foreach ($p in $parts) { $b = [IO.File]::ReadAllBytes($p.FullName); $out.Write($b, 0, $b.Length) }
    $out.Close()
  }
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
