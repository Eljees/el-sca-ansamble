# Operations

Bring up the stack:

```powershell
docker compose up stack-info
docker compose --profile update up --build
docker compose --profile scan up --build
```

Linux shell:

```sh
docker compose up stack-info
docker compose --profile update up --build
docker compose --profile scan up --build
```

Validate config and health:

```powershell
python -m resilient_updates.cli validate-config
python -m resilient_updates.cli healthcheck
```

Look at provenance:

```powershell
python -m resilient_updates.cli provenance
```

Generate a combined Markdown report:

```powershell
python -m resilient_updates.cli collect-report --reports-dir artifacts --output artifacts\reports\final\cve_analysis_report_generated_ru.md
```

`Markdown` is the text report format used for the final human-readable SCA summary.

Pre-pull scanner images when registry timeouts are expected:

```powershell
docker pull anchore/syft:v1.20.0
docker pull anchore/grype:v0.82.0
docker pull aquasec/trivy:0.64.1
```

Clean generated files:

```powershell
.\scripts\windows\clean-generated.ps1
```

Offline mode depends on prewarmed caches or internal mirrors. For Grype, that means a valid active directory or a last-known-good snapshot. For cve-bin-tool, export/import artifacts should already exist.

---

## Сканирование архивного файла (extract → scan)

Для получения результатов, сопоставимых с историческими (`--exps/`), необходимо сначала разархивировать
объект анализа, а затем запустить сканеры на его содержимом. Прямое сканирование `.tar.gz` / `.rpm` / `.deb`
без распаковки даёт 0 компонентов в Syft и, соответственно, 0 совпадений в Grype.
`scripts/windows/run-scan.ps1` теперь включает `-Extract` автоматически для архивных целей, но флаг
по-прежнему можно передать явно, если хочется зафиксировать поведение.

### Windows (PowerShell) — `run-scan.ps1`

Основной параметр `-Target` обязателен, остальные опциональны. Отчёты создаются
рядом с целевым файлом по схеме `{FILENAME}_report_{DATE}.md/.html`.

```powershell
# Стандартный скан (авто-extract для архивов, авто-определение формата)
.\scripts\windows\run-scan.ps1 -Target "D:\path\to\prometheus-3.11.0.linux-amd64.tar.gz" -Clean

# Android APK (внутри ZIP)
.\scripts\windows\run-scan.ps1 -Target "D:\path\to\app.zip" -Format apk -Clean

# Windows NSIS/MSI установщик
.\scripts\windows\run-scan.ps1 -Target "D:\path\to\Setup.exe" -Format win -Clean

# С обновлением БД перед сканом (требует сеть/прокси)
.\scripts\windows\run-scan.ps1 -Target "D:\path\to\archive.tar.gz" -UpdateDb -Clean

# Только Grype (пропустить Trivy и cve-bin-tool)
.\scripts\windows\run-scan.ps1 -Target "D:\path\to\target" -Tool grype -Clean

# SBOM fast-path для cve-bin-tool (экспериментально, см. ниже)
.\scripts\windows\run-scan.ps1 -Target "D:\path\to\target" -SbomScan -Clean

# Увеличенный таймаут cve-bin-tool (по умолчанию 1800 сек)
.\scripts\windows\run-scan.ps1 -Target "D:\path\to\big-binary" -CveBinToolTimeout 3600 -Clean
```

**Все параметры `run-scan.ps1`:**

| Параметр | Тип | По умолчанию | Описание |
|---|---|---|---|
| `-Target` | string | **обязателен** | Путь к файлу или директории |
| `-Profile` | string | `scan` | Docker Compose профиль |
| `-Tool` | ValidateSet | `all` | `all\|syft\|grype\|trivy\|cve-bin-tool` |
| `-Format` | ValidateSet | `auto` | `auto\|apk\|win` |
| `-UpdateDb` | switch | off | Обновить CVE-базы (требует сеть) |
| `-Extract` | switch | auto | Распаковать архив перед сканом |
| `-Clean` | switch | off | Удалить предыдущие артефакты |
| `-SbomScan` | switch | off | cve-bin-tool читает syft.json вместо бинарного скана |
| `-CveBinToolTimeout` | int | `1800` | Таймаут cve-bin-tool в секундах |

### Linux / macOS — `run-scan.sh`

```sh
# Стандартный скан
./scripts/run-scan.sh -t /path/to/prometheus-3.11.0.linux-amd64.tar.gz -c

# Android APK
./scripts/run-scan.sh -t /path/to/app.zip --format apk -c

# Windows installer
./scripts/run-scan.sh -t /path/to/Setup.exe --format win -c

# С обновлением БД
./scripts/run-scan.sh -t /path/to/archive.tar.gz -u -c

# Только Grype, увеличенный таймаут
./scripts/run-scan.sh -t /path/to/target --tool grype --timeout 3600 -c
```

Флаг `-c/--clean` удаляет артефакты предыдущего прогона, `-u/--update-db` требует
активный прокси/сеть. Остальные флаги совпадают с PowerShell-версией.

### Linux / Shell (legacy)

```sh
# Полный цикл через старый скрипт (устарел, используйте run-scan.sh)
CASE_ID=CYBERSEC-11531 ./scripts/scan_archive.sh /path/to/prometheus-3.11.0.linux-amd64.tar.gz

# С обновлением БД:
UPDATE_DB=1 CASE_ID=CYBERSEC-11531 ./scripts/scan_archive.sh /path/to/archive.tar.gz

# Кастомная директория вывода extraction:
EXTRACT_OUTPUT_REL=artifacts/extracted/my-run \
  CASE_ID=CYBERSEC-99999 \
  ./scripts/scan_archive.sh /path/to/archive.rpm
```

### Почему 0 findings без `-Extract`

Syft в режиме `--from dir` перечисляет манифесты пакетных менеджеров (go.sum, package-lock.json, etc.).
Бинарный дистрибутив Prometheus — это архив с Go-бинарями без манифестов в корне.
Syft находит компоненты через **binary cataloger** только если получает распакованные ELF-файлы.
После `extract`: содержимое tar.gz становится доступным как директория → Syft находит ~429 компонентов
→ Grype матчит их против БД → результат совпадает с историческим.

### Диагностика нулевых результатов

Если отчёт показывает `Syft components: 0`:

1. Проверьте `Consistency warnings` в отчёте — там будет явное предупреждение.
2. Убедитесь, что `artifacts/extracted/current/` не пустая директория.
3. Проверьте `artifacts/extracted/current/extraction_manifest.json` — поле `status` и `extracted_count`.
4. Если `extracted_count: 0` — архив не распознан экстрактором (проверьте формат файла).
5. Если директория заполнена, но Syft всё равно 0 — объект может не содержать Go/npm/rpm/deb
   компонентов (например, нативное C-приложение без известных менеджеров пакетов).

---

## Настройка прокси

Стек поддерживает HTTP, HTTPS и SOCKS5 прокси без хардкодинга — всё задаётся через переменные окружения.

### Быстрый старт (SOCKS5 на локальной машине)

Скопируйте `.env.example` → `.env` и заполните:

```dotenv
ALL_PROXY=socks5h://host.docker.internal:1080
NO_PROXY=localhost,127.0.0.1,grype-static
```

`host.docker.internal` — имя хоста Docker-контейнеров для выхода на Windows/Linux машину. Оно прописано в `extra_hosts` каждого сетевого сервиса в `docker-compose.yml`, поэтому дополнительных правок не требуется.

### Переменные окружения

| Переменная | Назначение |
|---|---|
| `HTTP_PROXY` / `http_proxy` | Прокси для HTTP-запросов |
| `HTTPS_PROXY` / `https_proxy` | Прокси для HTTPS-запросов |
| `NO_PROXY` / `no_proxy` | Хосты, исключённые из проксирования (через запятую) |
| `ALL_PROXY` / `all_proxy` | Резервный прокси для обоих протоколов; поддерживает SOCKS5 |

Нижний регистр нужен для совместимости с `curl`, `wget` и Go `net/http` внутри Docker-образов.

### Корпоративный HTTP/HTTPS прокси

```dotenv
HTTP_PROXY=http://proxy.corp.example:3128
HTTPS_PROXY=http://proxy.corp.example:3128
NO_PROXY=localhost,127.0.0.1,grype-static,.corp.example
```

### Переопределение только для Python-слоя (resilient_updates CLI)

Если Python-код должен ходить через другой прокси, чем Docker-контейнеры, задайте секцию `proxy:` в `configs/feed_sources.yaml`:

```yaml
proxy:
  http: "socks5h://host.docker.internal:1080"
  https: "socks5h://host.docker.internal:1080"
  no_proxy: "localhost,127.0.0.1,grype-static"
```

Поддерживаемые схемы: `http`, `https`, `socks4`, `socks4a`, `socks5`, `socks5h`.

### Что происходит без прокси

Если переменные не заданы — `requests.Session` работает без прокси. `ALL_PROXY` подхватывается автоматически даже без явного задания в `feed_sources.yaml`.
