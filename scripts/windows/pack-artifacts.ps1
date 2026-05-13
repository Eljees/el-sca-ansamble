param(
  [string]$Destination = "artifacts/scanner-artifacts.zip"
)

$ErrorActionPreference = "Stop"
if (Test-Path $Destination) { Remove-Item -Force $Destination }
Compress-Archive -Path "artifacts/reports","artifacts/provenance","artifacts/sbom","artifacts/mirror" -DestinationPath $Destination
Write-Host "Packed artifacts to $Destination"
