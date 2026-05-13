param()

$ErrorActionPreference = "Stop"
$root = (Resolve-Path ".").Path
Get-ChildItem -Path $root -Recurse -Force -Directory -Filter "__pycache__" | ForEach-Object {
  Remove-Item -LiteralPath $_.FullName -Recurse -Force
}
$pytestCache = Join-Path $root ".pytest_cache"
if (Test-Path $pytestCache) {
  Remove-Item -LiteralPath $pytestCache -Recurse -Force
}
$zip = Join-Path $root "artifacts\scanner-artifacts.zip"
if (Test-Path $zip) {
  Remove-Item -LiteralPath $zip -Force
}
Write-Host "Generated files cleaned"
