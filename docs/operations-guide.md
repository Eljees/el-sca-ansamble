# Руководство по эксплуатации: обновление баз и полное сканирование

Этот документ — точный, повторяемый алгоритм для:
1. Запуска прокси-цепочки
2. Обновления баз всех сканеров (trivy, grype, cve-bin-tool, syft)
3. Полного сканирования артефакта
4. Устранения типовых сбоев

---

## Предварительные требования

| Компонент | Что нужно |
|---|---|
| Docker Desktop (Windows) | ≥ 4.x, WSL2 backend, запущен |
| xray-core / v2rayN / sing-box | Запущен на **хосте**, слушает SOCKS5 на `127.0.0.1:10808` |
| el-sca-ansamble | Клонирован, `.env` заполнен (см. ниже) |
| Python | miniforge3 / conda, `pip install -e .` в корне репо |

> **Важно:** `127.0.0.1:10808` — это то, что слышит хост. Контейнеры обращаются к нему через `host.docker.internal:10808`. Порт зашит в `configs/xray/config.json` как `"address": "host.docker.internal", "port": 10808`.
> Если ваш прокси слушает другой порт — обновите конфиг xray в контейнере или запустите route-doctor (см. раздел «Автовыбор маршрута»).

---

## Файл `.env` — ключевые переменные

```dotenv
# Прокси для Docker-контейнеров
HTTP_PROXY=http://tinyproxy:8888
HTTPS_PROXY=http://tinyproxy:8888
ALL_PROXY=socks5h://proxy-xray:1080
NO_PROXY=localhost,127.0.0.1,grype-static,proxy-xray,tinyproxy

# cve-bin-tool: использовать локальные NVD-файлы, не скачивать
CVE_BIN_TOOL_UPDATE_MODES=feed
CVE_BIN_TOOL_FEED_BASE=file:///workspace/artifacts/nvd-feeds
CVE_BIN_TOOL_UPDATE_TIMEOUT_SECONDS=7200
CVE_BIN_TOOL_DB_POLICY=degraded-ok
CVE_BIN_TOOL_ENRICH_PROXY=http://proxy-xray:8118
CVE_BIN_TOOL_ENRICH_DISABLE=GAD REDHAT OSV
CVE_BIN_TOOL_SEED_AUX=0
CVE_BIN_TOOL_FEED_ENRICH=0
EL_SCA_SKIP_CVEBT=0

# Trivy: дополнительные источники БД
TRIVY_RENDERED_FLAGS=--db-repository ghcr.io/aquasecurity/trivy-db:2 --db-repository public.ecr.aws/aquasecurity/trivy-db:2 --java-db-repository ghcr.io/aquasecurity/trivy-java-db:1 --checks-bundle-repository ghcr.io/aquasecurity/trivy-checks:0
```

Файл `.env.local` (создайте если нет, не в git) — для секретов:
```dotenv
NVD_API_KEY=<ваш ключ с nvd.nist.gov>
NVD_API_KEY_FALLBACK=<резервный ключ>
```

---

## Шаг 1 — Запустить прокси-цепочку

```powershell
cd D:\dev\el-sca-ansamble

# Поднять tinyproxy + proxy-xray (HTTP→SOCKS5→xray-на-хосте→интернет)
docker compose --profile proxy up -d
```

**Проверка:**
```powershell
docker compose ps tinyproxy proxy-xray
# Оба должны быть Up (healthy или running)

# Тест сквозного доступа через прокси-цепочку
docker run --rm --network el-sca-ansamble_scanner-net `
  -e HTTPS_PROXY=http://tinyproxy:8888 `
  curlimages/curl:latest `
  curl -sI https://github.com --proxy http://tinyproxy:8888 | head -3
# Ожидаем: HTTP/2 200 или 301
```

**Архитектура цепочки:**
```
сканер → tinyproxy:8888 (HTTP CONNECT) → proxy-xray:1080 (SOCKS5) → host:10808 (xray) → интернет
```

---

## Шаг 2 — Обновить базы всех сканеров

### 2a. Trivy

```powershell
cd D:\dev\el-sca-ansamble
docker compose --profile proxy up -d          # если не запущены
docker compose run --rm trivy-updater
```

Ожидаемый результат: `trivy-cache` volume содержит `trivy.db` (~1 ГБ).

**Проверка:**
```powershell
docker run --rm -v el-sca-ansamble_trivy-cache:/data alpine `
  sh -c "find /data -name 'trivy.db' -exec ls -lh {} \;"
# должен показать файл, дата — сегодня
```

### 2b. Grype

```powershell
docker compose run --rm grype-updater
# После окончания:
docker compose run --rm grype-db-importer
```

Ожидаемый результат: `grype-db` volume содержит `db.tar.zst`.

**Проверка:**
```powershell
docker run --rm -v el-sca-ansamble_grype-db:/data alpine `
  sh -c "ls -lh /data/"
```

### 2c. cve-bin-tool (NVD feed из файлов)

Предварительно нужны NVD-файлы в `artifacts/nvd-feeds/`:

```powershell
# Скачать все годовые фиды NVD (2002–текущий год) через прокси
# Выполнять в PowerShell из корня репо
$years = 2002..(Get-Date).Year
foreach ($year in $years) {
    $url  = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$year.json.gz"
    $dest = "artifacts\nvd-feeds\nvdcve-2.0-$year.json.gz"
    if (-not (Test-Path $dest)) {
        Write-Host "Downloading $year..."
        Invoke-WebRequest -Uri $url -OutFile $dest -Proxy "http://127.0.0.1:10808"
    }
}
```

После загрузки файлов — запустить обновление БД:

```powershell
docker compose run --rm cve-bin-tool-updater
```

**Проверка:**
```powershell
docker run --rm -v el-sca-ansamble_cve-bin-tool-cache:/root/.cache/cve-bin-tool `
  alpine sh -c "ls -lh /root/.cache/cve-bin-tool/"
# Должен быть cve.db (400–500 МБ)
```

**Проверка количества записей:**
```powershell
docker compose run --rm --entrypoint="" cve-bin-tool-scanner `
  sh -c "cve-bin-tool --version 2>&1; python -c \"
import sqlite3, os
db = os.path.expanduser('~/.cache/cve-bin-tool/cve.db')
c = sqlite3.connect(db)
print('NVD entries:', c.execute('SELECT COUNT(*) FROM nvd_db').fetchone()[0])
c.close()
\""
# Ожидаем: 350,000+ entries
```

### 2d. Syft — обновление не требуется

Syft — бинарный инструмент для генерации SBOM. База данных не нужна. Версия зафиксирована в `versions.env`.

---

## Шаг 3 — Запустить полное сканирование (Windows)

```powershell
cd D:\dev\el-sca-ansamble

# Очистить предыдущие артефакты и создать final/ с правами
docker run --rm -v "${PWD}\artifacts:/workspace/artifacts" alpine sh -c "
  find /workspace/artifacts -type f ! -name .gitkeep -delete 2>/dev/null
  find /workspace/artifacts -mindepth 1 -type d -empty -delete 2>/dev/null
  mkdir -p /workspace/artifacts/reports/final
  chmod -R 777 /workspace/artifacts
  echo done"

# Запустить сканирование
$target    = "D:\dev\_SCA\CYBERSEC-XXXXX\artifact.tar.gz"
$caseId    = "CYBERSEC-XXXXX"
$logFile   = "$env:TEMP\scan-$caseId.log"
$errFile   = "$env:TEMP\scan-$caseId.err"

$proc = Start-Process powershell.exe -ArgumentList @(
  '-NonInteractive', '-NoProfile', '-ExecutionPolicy', 'Bypass',
  '-File', 'scripts\windows\run-scan.ps1',
  '-Target', $target,
  '-Extract'
) -RedirectStandardOutput $logFile `
  -RedirectStandardError  $errFile `
  -WorkingDirectory (Get-Location).Path `
  -PassThru
Write-Host "PID: $($proc.Id)  Log: $logFile"
```

> **Параметр `-Extract`** нужен для tar.gz/zip артефактов; без него передавайте директорию.

### Мониторинг прогресса

```powershell
# Следить за контейнерами
while ($true) {
    $ps = docker ps --filter "name=el-sca" --format "{{.Names}}: {{.Status}}" 2>&1
    Write-Host (Get-Date -Format "HH:mm:ss") $ps
    Start-Sleep 10
}

# Смотреть логи конкретного контейнера
docker logs --tail 20 -f <container-name>
```

Последовательность этапов:
```
artifact-extractor  →  syft-sbom  →  trivy-scanner  →  grype-scanner  →  cve-bin-tool-scanner  →  report-collector
```

### После завершения: сгенерировать финальные отчёты

Если `run-scan.ps1` завершился, но Python-отчёты не созданы:

```powershell
cd D:\dev\el-sca-ansamble

$target   = "D:\dev\_SCA\CYBERSEC-XXXXX\artifact.tar.gz"
$caseId   = "CYBERSEC-XXXXX"
$date     = Get-Date -Format "yyyy-MM-dd"
$outBase  = "D:\dev\_SCA\$caseId\artifact_report_$date"

python -m resilient_updates.cli collect-report `
  --reports-dir artifacts `
  --target      $target `
  --case-id     $caseId `
  --output      "$outBase.md"

python scripts/report_html.py `
  --artifacts-dir artifacts `
  --target        $target `
  --output        "$outBase.html"
```

---

## Шаг 4 — Интерпретация результатов

### Ключевые файлы после сканирования

```
D:\dev\_SCA\<CASE>\
├── artifact_report_YYYY-MM-DD.md          # Сводный Markdown-отчёт
├── artifact_report_YYYY-MM-DD.html        # HTML-навигатор (index)
├── artifact_report_YYYY-MM-DD_grype.html
├── artifact_report_YYYY-MM-DD_trivy.html
├── artifact_report_YYYY-MM-DD_cve-bin-tool.html
└── artifact_report_YYYY-MM-DD_syft.html

D:\dev\el-sca-ansamble\artifacts\
├── sbom\
│   ├── cyclonedx.json   # SBOM для cve-bin-tool (1–10 МБ)
│   ├── spdx.json
│   └── syft.json
├── reports\
│   ├── grype\report.json
│   ├── trivy\report.json
│   └── cve-bin-tool\report.json
└── summary.json         # Краткая сводка: counts, policy, failures
```

### Ожидаемые результаты по типу артефакта

| Тип артефакта | grype | trivy | cve-bin-tool | Примечания |
|---|---|---|---|---|
| Go-бинарь (ELF) | ++ | 0 | ++ | trivy filesystem не видит ELF; cve-bin-tool видит через SBOM |
| Java-приложение (WAR/ZIP) | + | ++ | ++ | Все три инструмента покрывают JAR-зависимости |
| Контейнерный образ (OCI) | ++ | ++ | + | Trivy и grype специализированы для образов |
| Python-пакет | ++ | ++ | + | requirements.txt/pyproject.toml |

**Trivy = 0 findings для Go-бинарей — это нормально.** Trivy в режиме `filesystem` сканирует манифесты зависимостей (go.mod, pom.xml, package.json), а не ELF-бинари. Prometheus и подобные Go-приложения поставляются без go.mod → Trivy не находит ничего по дизайну.

### Поле `policy_decision`

| Значение | Значение |
|---|---|
| `pass` | CRITICAL/HIGH = 0 (или ниже порога) |
| `fail: CRITICAL=N>0` | Есть критические уязвимости, требует рассмотрения |
| `degraded-ok` | БД неполная, результат приблизительный |
| `no-policy` | Политика не сконфигурирована |

---

## Типовые сбои и способы устранения

### Ошибка: `mkdir: cannot create directory 'artifacts/reports/final': Permission denied`

Контейнер `report-collector` запускается от не-root, Docker Desktop на Windows не позволяет создать папку через bind-mount.

**Решение:**
```powershell
docker run --rm -v "${PWD}\artifacts:/workspace/artifacts" alpine `
  chmod -R 777 /workspace/artifacts/reports/
# Затем перезапустить report-collector:
docker compose --env-file .env --env-file versions.env `
  --profile report run --rm `
  -e SCAN_CASE_ID=CYBERSEC-XXXXX report-collector
```

### Ошибка: `_disable_sources_to_args` → скрипт падает без вывода

**Симптом:** `cve-bin-tool-updater` завершается с exit 1, нет вывода об ошибке.

**Причина:** Старая версия скрипта содержала:
```sh
[ -n "$_ds_csv" ] && printf -- '--disable-data-source %s' "$_ds_csv"
```
При пустом `$_ds_csv` команда `[ -n "" ]` возвращает exit 1, и `set -eu` убивает скрипт.

**Исправление** (уже применено в репо, `scripts/update_cve_bin_tool.sh`):
```sh
if [ -n "$_ds_csv" ]; then
  printf -- '--disable-data-source %s' "$_ds_csv"
fi
```

### Ошибка: `cve-bin-tool-updater` сообщает `status: failed, reason: update started`

**Симптом:** Файл `artifacts/cve-bin-tool-update-status.json` содержит `"status": "failed"`, но БД существует.

**Причина:** Предыдущий контейнер был убит (SIGKILL/SIGTERM) до записи `activation.json`. БД при этом может быть корректной.

**Диагностика:**
```powershell
# Проверить реальное состояние БД
docker run --rm -v el-sca-ansamble_cve-bin-tool-cache:/root/.cache/cve-bin-tool `
  alpine sh -c "ls -lh /root/.cache/cve-bin-tool/"
# Если cve.db > 400 МБ — БД в норме, статус-файл врёт
```

**Решение:** Запустить обновление ещё раз: `docker compose run --rm cve-bin-tool-updater`. Либо продолжить сканирование (политика `degraded-ok` в `.env` позволяет это).

### Ошибка: db-admin сообщает `MISSING` для cve-bin-tool

**Это ложное срабатывание на Windows.** `db-admin` в Windows-override (`docker-compose.windows.override.yml`) не монтирует `cve-bin-tool-cache` volume по правильному пути. Сам сканер при этом правильно монтирует том и использует БД. Игнорируйте это предупреждение при запуске через `run-scan.ps1`.

### Ошибка: `mcp__el-sca-docker__run_scan_async` не видит Windows-путь

**Симптом:** MCP-инструмент получает `d:\dev\...`, но bash-скрипт не может его разрешить.

**Решение:** Всегда используйте `Start-Process` с `run-scan.ps1` вместо MCP-инструмента `run_scan_async` для Windows-путей:
```powershell
$proc = Start-Process powershell.exe -ArgumentList @(
  '-NonInteractive', '-NoProfile', '-ExecutionPolicy', 'Bypass',
  '-File', 'scripts\windows\run-scan.ps1',
  '-Target', 'D:\dev\_SCA\...',
  '-Extract'
) -RedirectStandardOutput $logFile -RedirectStandardError $errFile `
  -WorkingDirectory "D:\dev\el-sca-ansamble" -PassThru
```

### Ошибка: Docker volumes с неправильными именами

Trivy использует volume `el-sca-ansamble_trivy-cache` (не `trivy-db`).

```powershell
# Список всех el-sca volumes:
docker volume ls --filter "name=el-sca"

# Корректные имена (на Docker Desktop Windows):
# el-sca-ansamble_trivy-cache       — trivy DB (~1 ГБ)
# el-sca-ansamble_grype-db          — grype DB
# el-sca-ansamble_cve-bin-tool-cache — cve-bin-tool DB
```

---

## Быстрый чеклист: от нуля до отчёта

```
[ ] 1. xray/v2rayN запущен на хосте, SOCKS5 на 127.0.0.1:10808
[ ] 2. Docker Desktop запущен
[ ] 3. cd D:\dev\el-sca-ansamble
[ ] 4. docker compose --profile proxy up -d
        → tinyproxy и proxy-xray Up
[ ] 5. docker compose run --rm trivy-updater
        → artifacts/provenance/trivy.json: activation_status=active
[ ] 6. docker compose run --rm grype-updater && docker compose run --rm grype-db-importer
        → el-sca-ansamble_grype-db volume непустой
[ ] 7. (Скачать NVD feeds если нет)
        docker compose run --rm cve-bin-tool-updater
        → el-sca-ansamble_cve-bin-tool-cache: cve.db > 400 МБ
[ ] 8. Очистить artifacts/ + chmod 777
[ ] 9. Start-Process run-scan.ps1 -Target <path> -Extract
        → Мониторинг: docker ps --filter "name=el-sca"
        → Ждать исчезновения всех run-контейнеров
[10. ] python -m resilient_updates.cli collect-report ... → .md
[11. ] python scripts/report_html.py ... → .html
[12. ] Открыть <artifact>_report_YYYY-MM-DD.html
```

---

## Встроить в логику контейнеров

Для автоматизации полного цикла (обновление + сканирование) используйте:

```sh
# Linux/CI — один вызов
./scripts/run-scan.sh \
  --target /path/to/artifact.tar.gz \
  --extract \
  --update-db \
  --case-id CYBERSEC-XXXXX

# Windows — запустить через PowerShell
pwsh -File scripts\windows\run-scan.ps1 `
  -Target "D:\path\to\artifact.tar.gz" `
  -Extract `
  -UpdateDb `
  -CaseId "CYBERSEC-XXXXX"
```

Флаг `--update-db` / `-UpdateDb` запускает route-doctor перед обновлением баз, автоматически выбирая рабочий маршрут (tinyproxy, proxy-xray, хостовый прокси или direct).

---

## Результаты сканирований 2026-06-11

### CYBERSEC-11531: Prometheus 3.11.0

- Артефакт: `prometheus-3.11.0.linux-amd64.tar.gz` (Go-бинарь)
- Syft components: 434 SBOM-компонентов
- **Grype**: 145 совпадений
- **cve-bin-tool**: 67 находок (golang.go 1.23.0 / 1.26.1 + ecies.go)
- **Trivy**: 0 (ожидаемо для Go-бинаря без манифестов)
- Policy: `fail: CRITICAL>0`

### CYBERSEC-11603: WSO2 Micro Integrator 4.6.0

- Артефакт: `makarov-i-686402.tar.gz` → `wso2mi-4.6.0.zip` (Java-приложение)
- Syft components: 434 SBOM-компонентов
- **Grype**: 1 совпадение
- **cve-bin-tool**: 58 находок (CRITICAL=14, HIGH=16, MEDIUM=19)
- **Trivy**: 0
- Policy: `fail: CRITICAL=14>0`

> Примечание: часть CRITICAL в cve-bin-tool (mobileiron, formtools, onlyoffice) — вероятные ложные срабатывания по совпадению имён Maven/npm-зависимостей с другими продуктами. Требует ручной верификации.
