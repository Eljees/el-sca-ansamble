# Download the NVD 2.0 JSON CVE data feeds on the HOST (uses your normal
# network / VPN (the same path your browser uses to reach nvd.nist.gov), into
# artifacts/nvd-feeds/.  The cve-bin-tool feed importer then reads them locally
# (no proxy/curl needed inside the container):
#
#   1) powershell -ExecutionPolicy Bypass -File scripts/fetch_nvd_feeds.ps1
#   2) set in .env:  CVE_BIN_TOOL_FEED_BASE=file:///workspace/artifacts/nvd-feeds
#   3) update the cve-bin-tool DB from the GUI (or `--profile update up cve-bin-tool-updater`)
#
# Quick smoke test: scripts/fetch_nvd_feeds.ps1 -StartYear 2024
[CmdletBinding()]
param(
    [int]$StartYear = 2002,
    [int]$EndYear = (Get-Date).Year,
    [switch]$SkipModified,
    [string]$OutDir = "artifacts/nvd-feeds"
)

$ErrorActionPreference = "Stop"
$base = "https://nvd.nist.gov/feeds/json/cve/2.0"
$ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$names = @()
for ($y = $StartYear; $y -le $EndYear; $y++) { $names += "nvdcve-2.0-$y" }
if (-not $SkipModified) { $names += "nvdcve-2.0-modified" }

Write-Host "Downloading $($names.Count) NVD 2.0 feeds -> $OutDir"
$ok = 0
foreach ($n in $names) {
    $url = "$base/$n.json.gz"
    $dst = Join-Path $OutDir "$n.json.gz"
    try {
        Invoke-WebRequest -Uri $url -OutFile $dst -UserAgent $ua -UseBasicParsing -TimeoutSec 300
        $sz = [math]::Round((Get-Item $dst).Length / 1MB, 2)
        Write-Host ("  OK  {0}  ({1} MB)" -f $n, $sz)
        $ok++
    }
    catch {
        Write-Warning ("  FAIL {0}: {1}" -f $n, $_.Exception.Message)
    }
}
Write-Host "Done: $ok/$($names.Count) feeds in $OutDir"
if ($ok -eq 0) { Write-Error "No feeds downloaded - check VPN/proxy/network." }
