# Windows / PowerShell — практика работы со стеком

Документ для тех, кто запускает el-sca-ansamble с Windows-десктопа: Docker Desktop + WSL2 backend + PowerShell 7+. Если у вас Linux-хост, смотрите `docs/operations.md` и `scripts/README.md`.

---

## 1. Минимальный набор пред-условий

| Компонент | Минимум | Как поставить |
|---|---|---|
| Windows 10 21H2 / Windows 11 | — | — |
| PowerShell | 7.4+ (Core) | `winget install --id Microsoft.PowerShell` |
| Docker Desktop | 4.30+, WSL2 backend | `winget install --id Docker.DockerDesktop` |
| WSL2 + Ubuntu (для ext4 hot path) | Ubuntu 22.04+ | `wsl --install -d Ubuntu` |
| Python 3.12 (для локальных тестов вне контейнера) | 3.12+ | `winget install --id Python.Python.3.12` |
| Git for Windows | свежий | `winget install --id Git.Git` |

После установки перезайдите в Windows-аккаунт, чтобы группа `docker-users` встала на пользователя.

---

## 2. Первый запуск

```powershell
# Клонируем (NTFS — пусть так, ускорения переключаем шагом ниже)
git clone https://example.invalid/el-sca-ansamble.git
cd el-sca-ansamble

# Конфигурация
Copy-Item .env.example .env
# В блокноте/VS Code заполните: NVD_API_KEY (опц.), SCAN_TARGET_HOST и прокси при необходимости.

# Применить Defender exclusions (один раз, требует elevated)
Start-Process pwsh -Verb runAs -ArgumentList @(
  '-ExecutionPolicy','Bypass',
  '-File',".\scripts\windows\setup-defender-exclusions.ps1"
)

# Проверка структуры
docker compose config -q
python -m resilient_updates.cli validate-config
```

`validate-config` должен ответить `{"status":"ok"}`. Если ругается на `proxy.chains` — см. `docs/network-design.md`.

---

## 3. Полный скан

```powershell
# Объект анализа лежит в .env как SCAN_TARGET_HOST или явно передаётся:
.\scripts\windows\run-scan.ps1 -Target "D:\samples\prometheus.tar.gz" -Clean
```

Опции `run-scan.ps1`:

| Параметр | Зачем | Дефолт |
|---|---|---|
| `-Target <path>` | файл / директория / архив для анализа | (обязателен) |
| `-CaseId <id>` | идентификатор кейса в шапке отчёта; если не задан, берётся из пути `CYBERSEC-\d+` | auto |
| `-Profile <name>` | docker-compose profile | `scan` |
| `-Tool <all\|syft\|grype\|trivy\|cve-bin-tool>` | гонять только один сканер | `all` |
| `-Format <auto\|apk\|win>` | специализированный pipeline | `auto` |
| `-UpdateDb` | сначала обновить БД | off |
| `-Extract` | распаковать архив до скана | автодетект для архивов |
| `-Clean` | удалить предыдущие артефакты | off |
| `-SbomScan` | подсунуть `cyclonedx.json` в cve-bin-tool вместо binary scan | off |
| `-CveBinToolTimeout <sec>` | таймаут cve-bin-tool scan | `1800` |

После завершения отчёт лежит рядом с целью: `<target_basename>_report_<date>.md` + HTML.

---

## 4. Скан только одной части пайплайна

```powershell
# Один Trivy на ту же цель
.\scripts\windows\run-scan.ps1 -Target "D:\samples\app.zip" -Tool trivy

# Только обновление баз
docker compose --profile update up --abort-on-container-exit

# Только Syft (без CVE-матчинга)
.\scripts\windows\run-scan.ps1 -Target "D:\samples\src\" -Tool syft
```

---

## 5. Прокси и SOCKS

Базовый сценарий — v2rayN/Xray на хосте, порт 10808 или 1080:

```powershell
# Один раз — снизу пропишите в .env:
#   ALL_PROXY=socks5h://host.docker.internal:1080
#   NO_PROXY=localhost,127.0.0.1,grype-static
# и сохраните.

# Перепроверка из контейнера:
docker run --rm --add-host=host.docker.internal:host-gateway `
  -e ALL_PROXY=socks5h://host.docker.internal:1080 `
  curlimages/curl:latest `
  curl -fsS https://www.google.com/generate_204 -o NUL -w "HTTP %{http_code}`n"
```

Расширенная цепочка (sidecar Xray + tinyproxy) — `docs/network-design.md`. Минимум для активации:

```powershell
$env:COMPOSE_PROFILES = "scan,update,proxy"
docker compose up -d proxy-xray tinyproxy
docker compose run --rm db-admin proxy-status
```

---

## 6. Windows-оптимизация (Phase 3)

```powershell
# Включить Windows-overlay
$env:COMPOSE_FILE = "docker-compose.yml;docker-compose.windows.override.yml"

# Бенчмарк до/после (фиксирует Defender exclusions, COMPOSE_FILE и пр.)
.\scripts\windows\benchmark.ps1 -Target "D:\samples\prometheus.tar.gz" -Runs 3
Get-Content .\artifacts\provenance\benchmark.json
```

Краткий разбор оптимизаций:

- **Defender exclusions** — `setup-defender-exclusions.ps1`. Без них Defender пересканивает каждый файл, который extractor/cve-bin-tool открывают через WSL2 bind mount.
- **Overlay `windows.override`** — tmpfs `/tmp` (4 GB у `cve-bin-tool-scanner`), `extracted-staging` named volume на ext4 внутри WSL VHDX.
- **BuildKit cache** — apt-cache и pip-cache переиспользуются между `docker build`.
- **CVE_BIN_TOOL_PARALLEL** — зарезервирован на будущее; в cve-bin-tool 3.4 это no-op, потому что binary scan уже использует внутренний CPU-count Pool.
- **CVE_BIN_TOOL_AUTO_SBOM** — если syft уже сгенерировал `cyclonedx.json`/`spdx.json`, cve-bin-tool читает его как SBOM (секунды вместо ≈ 30 мин на больших Go-бинарях).
- **CVE_BIN_TOOL_LOCAL_COPY** — `cp -a` цели в `/tmp/cbt-scan-local` (tmpfs) перед binary scan: устраняет 9P round-trip overhead для каждой `read()`-операции.
- **CVE_BIN_TOOL_MAX_FILE_MB** — пропускаем монолиты > 256 MB (regex-backtracking budget).

---

## 7. Типичные ошибки и фиксы

| Симптом | Причина | Решение |
|---|---|---|
| `service "X" is not running` | используется не тот profile | `$env:COMPOSE_PROFILES = "scan,update"`; перезапустить |
| `Volume "trivy-cache" not found` | compose v1 fallback или старая schema | обновить Docker Desktop ≥ 4.30; не использовать `docker-compose` (с дефисом) |
| `127.0.0.1` недоступен из контейнера | путаница с `host.docker.internal` | в `.env`: `ALL_PROXY=socks5h://host.docker.internal:1080` |
| `cve-bin-tool` 0 findings, но `timeout.flag` есть | scan не дошёл до конца | поднять `CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS` или включить `-SbomScan` |
| Defender exclusions «применились», но скан всё равно медленный | политика домена перекрывает | `Get-MpPreference` покажет — есть ли наши пути в `ExclusionPath` |
| `Permission denied` при write в `artifacts/` | UID контейнера ≠ владельцу NTFS | `LOCAL_UID=1000` / `LOCAL_GID=1000` в `.env` — но на Windows это игнорируется WSL2 |

---

## 8. Daily workflow в PowerShell

```powershell
# 1. Один раз в день / по требованию: обновить БД
.\scripts\windows\update-grype.ps1
.\scripts\windows\update-trivy.ps1
.\scripts\windows\update-cve-bin-tool.ps1

# 2. Скан очередной цели
.\scripts\windows\run-scan.ps1 -Target "D:\incoming\new-app.tar.gz" -Clean

# 3. Перед коммитом
docker compose config -q                                # compose schema
python -m resilient_updates.cli validate-config         # YAML
python -m pytest -q                                     # тесты
ruff check . ; ruff format --check .                    # python lint
```

---

## 9. CI: что запустится на push

См. `.github/workflows/ci.yml`. PowerShell-часть пайплайна (`PSScriptAnalyzer` через `.\PSScriptAnalyzerSettings.psd1`) гоняется на ubuntu-latest через `pwsh` — переносить настройки между локальным и CI runner не требуется.
