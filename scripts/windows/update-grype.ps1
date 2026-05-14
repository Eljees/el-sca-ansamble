param()

$ErrorActionPreference = "Stop"
function Invoke-ComposeChecked {
  param(
    [Parameter(Mandatory=$true)]
    [string[]]$Args
  )
  & docker compose @Args
  if ($LASTEXITCODE -ne 0) {
    throw "docker compose failed with exit code ${LASTEXITCODE}: $($Args -join ' ')"
  }
}

docker --version | Out-Null
docker compose version | Out-Null
New-Item -ItemType Directory -Force -Path "artifacts/provenance" | Out-Null
Invoke-ComposeChecked -Args @("run", "--rm", "grype-updater", "update", "grype")
Invoke-ComposeChecked -Args @("run", "--rm", "grype-db-importer")
