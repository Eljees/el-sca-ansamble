<#
.SYNOPSIS
  bootstrap.ps1 — развернуть комплекс «в несколько команд» на чистой Windows-машине.

.DESCRIPTION
  После `git clone` достаточно:
    .\scripts\windows\bootstrap.ps1 -UpdateDb     # полный ввод в строй (с базами)
  или по шагам:
    .\scripts\windows\bootstrap.ps1               # подготовка + сборка + smoke
    затем обновить базы через дашборд или MCP update_db.

  Шаги (идемпотентно): docker check → .env из .env.example → compose config -q
  → volume-init → build → (опц.) обновление баз → smoke.

.PARAMETER UpdateDb
  Сразу обновить базы всех сканеров после сборки.

.PARAMETER NoBuild
  Пропустить сборку образов.
#>
[CmdletBinding()]
param(
    [switch]$UpdateDb,
    [switch]$NoBuild
)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\..")

function Step([string]$msg) { Write-Host "`n-- $msg --" -ForegroundColor Cyan }

Step "1/7 Проверка docker"
docker --version
docker compose version

Step "2/7 Конфигурация (.env)"
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host ".env создан из .env.example (отредактируйте при необходимости)"
} else {
    Write-Host ".env уже существует — не трогаю"
}

# Compose интерполирует `${SCAN_TARGET_HOST:?}` даже для config/build.
if (-not $env:SCAN_TARGET_HOST)  { $env:SCAN_TARGET_HOST = "." }
if (-not $env:EXTRACT_INPUT_HOST) { $env:EXTRACT_INPUT_HOST = "." }

Step "3/7 Валидация compose-схемы"
docker compose config -q
if ($LASTEXITCODE -ne 0) { throw "docker compose config failed" }
Write-Host "compose: OK"

Step "4/7 volume-init (права томов под uid 1001)"
docker compose --profile volinit run --rm volume-init
if ($LASTEXITCODE -ne 0) { Write-Warning "volume-init не прошёл — возможны ошибки прав" }

if (-not $NoBuild) {
    Step "5/7 Сборка локальных образов"
    docker compose --profile scan --profile update --profile extract --profile report build
    if ($LASTEXITCODE -ne 0) { throw "docker compose build failed" }
} else {
    Step "5/7 Сборка пропущена (-NoBuild)"
}

if ($UpdateDb) {
    Step "6/7 Обновление баз"
    bash scripts/update-db.sh all
    if ($LASTEXITCODE -ne 0) { Write-Warning "часть баз не обновилась — повторите ./scripts/update-db.sh all" }
} else {
    Step "6/7 Базы НЕ обновлялись (потом: bash scripts/update-db.sh all или кнопка в дашборде)"
}

Step "7/7 Smoke-проверка"
docker compose config --services | ForEach-Object { "  - $_" }
docker compose ps

Write-Host "`nКомплекс готов. Дальше:" -ForegroundColor Green
Write-Host "  скан:    .\scripts\windows\run-scan.ps1 -Target C:\path\to\artifact.tar.gz"
Write-Host "  монитор: python -m resilient_updates.cli monitor --watch 5"
Write-Host "  дашборд: python -m resilient_updates.cli dashboard   # http://127.0.0.1:8080"
