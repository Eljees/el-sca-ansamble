param(
  [string]$Root = "D:\!ya_drive_sync\YandexDisk\rostel\to_analyze\__projects",
  [string]$OutputRoot = "artifacts\extracted\projects",
  [int]$MaxDepth = 4,
  [int]$Limit = 0
)

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

function ConvertTo-SafeName {
  param([string]$Value)
  $safe = $Value -replace '[^A-Za-z0-9._-]', '_'
  if ([string]::IsNullOrWhiteSpace($safe)) { return "artifact" }
  return $safe.Trim("._")
}

if (-not (Test-Path $Root)) {
  throw "Root path does not exist: $Root"
}

docker --version | Out-Null
docker compose version | Out-Null

$extensions = @(".zip", ".tar", ".tgz", ".gz", ".zst", ".xz", ".bz2", ".rpm", ".deb", ".7z", ".rar")
$archives = @(Get-ChildItem -Path $Root -Recurse -File |
  Where-Object {
    $name = $_.Name.ToLowerInvariant()
    -not $name.EndsWith(".sha256.txt") -and
    ($extensions | Where-Object { $name.EndsWith($_) })
  } |
  Sort-Object FullName)

if ($Limit -gt 0) {
  $archives = @($archives | Select-Object -First $Limit)
}

$repoRoot = (Get-Location).Path
$index = 0
foreach ($archive in $archives) {
  $index += 1
  $caseName = Split-Path (Split-Path $archive.FullName -Parent) -Leaf
  if ($archive.FullName -match '\\(CYBERSEC-[0-9]+)\\') {
    $caseName = $Matches[1]
  }
  $safeCase = ConvertTo-SafeName $caseName
  $safeArtifact = ConvertTo-SafeName $archive.BaseName
  $relativeOutput = Join-Path $OutputRoot (Join-Path $safeCase "$('{0:D3}' -f $index)_$safeArtifact")
  $hostOutput = Join-Path $repoRoot $relativeOutput
  New-Item -ItemType Directory -Force -Path $hostOutput | Out-Null

  $env:EXTRACT_INPUT_HOST = $archive.FullName
  $env:EXTRACT_OUTPUT = "/workspace/$($relativeOutput -replace '\\','/')"
  $env:EXTRACT_MAX_DEPTH = [string]$MaxDepth

  Write-Host "[$index/$($archives.Count)] Extracting $($archive.FullName)"
  Invoke-ComposeChecked -Args @("--profile", "extract", "run", "--rm", "artifact-extractor")
}

Write-Host "Extraction complete. Output root: $OutputRoot"
