# Operations

For the exact repeatable remote-machine sequence with proxy/VPN routing, DB refresh, and GUI verification, see [`docs/remote-analysis.md`](remote-analysis.md).

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
docker pull anchore/grype:v0.112.0
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
Для APK-обёрток в `.zip` extraction тоже остаётся включённым, чтобы `apk-analyzer` видел реальный
`.apk` внутри распакованной директории. Для standalone `.apk` generic extraction не нужен.

### Windows (PowerShell) — `run-scan.ps1`

Основной параметр `-Target` обязателен, остальные опциональны. Отчёты создаются
рядом с целевым файлом по схеме `{FILENAME}_report_{DATE}.md/.html`.

```powershell
# Стандартный скан (авто-extract для архивов, авто-определение формата)
.\scripts\windows\run-scan.ps1 -Target "D:\path\to\prometheus-3.11.0.linux-amd64.tar.gz" -Clean

# Android APK (внутри ZIP)
.\scripts\windows\run-scan.ps1 -Target "D:\path\to\app.zip" -Format apk -Clean

# Явно задать номер кейса в шапке отчёта
.\scripts\windows\run-scan.ps1 -Target "D:\path\to\app.zip" -CaseId CYBERSEC-12080 -Clean

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
| `-CaseId` | string | auto | Идентификатор кейса в итоговом отчёте; если не задан, берётся из пути `CYBERSEC-\d+` |
| `-Profile` | string | `scan` | Docker Compose профиль |
| `-Tool` | ValidateSet | `all` | `all\|syft\|grype\|trivy\|cve-bin-tool` |
| `-Format` | ValidateSet | `auto` | `auto\|apk\|win` |
| `-UpdateDb` | switch | off | Обновить CVE-базы (требует сеть) |
| `-Extract` | switch | auto | Распаковать архив перед сканом |
| `-Clean` | switch | off | Удалить предыдущие артефакты |
| `-SbomScan` | switch | off | cve-bin-tool читает `cyclonedx.json` вместо бинарного скана |
| `-CveBinToolTimeout` | int | `1800` | Таймаут cve-bin-tool в секундах |
| `-ArtifactMode` | ValidateSet | `auto` | Куда сохранять snapshot прогона: `artifacts`, `near-source`, `auto` |

Если `-CaseId` / `--case-id` не задан, runner пытается взять номер из пути к цели по
шаблону `CYBERSEC-\d+`. Если такого фрагмента нет, в отчёте будет `CYBERSEC-UNKNOWN`;
референсный `CYBERSEC-11531` больше не используется как дефолт.

### Linux / macOS — `run-scan.sh`

```sh
# Стандартный скан
./scripts/run-scan.sh -t /path/to/prometheus-3.11.0.linux-amd64.tar.gz -c

# Android APK
./scripts/run-scan.sh -t /path/to/app.zip --format apk --case-id CYBERSEC-12080 -c

# Windows installer
./scripts/run-scan.sh -t /path/to/Setup.exe --format win -c

# С обновлением БД
./scripts/run-scan.sh -t /path/to/archive.tar.gz -u -c

# Только Grype, увеличенный таймаут
./scripts/run-scan.sh -t /path/to/target --tool grype --timeout 3600 -c
```

Флаг `-c/--clean` удаляет артефакты предыдущего прогона, `-u/--update-db` требует
активный прокси/сеть. Остальные флаги совпадают с PowerShell-версией.

После каждого успешного прогона runner сохраняет snapshot evidence:

- MD/HTML отчёты остаются рядом с исходным файлом;
- `MANIFEST.json`, `checkpoint.json`, SBOM, raw reports, provenance и логи
  копируются в `<project>-<timestamp>/`;
- режим `auto` пишет рядом с исходником, если это возможно, иначе в
  `artifacts/runs/`;
- полный `artifacts/extracted/current` не копируется по умолчанию; включайте
  `EL_SCA_ARCHIVE_EXTRACTED_TREE=1` только для тяжёлого debug/resume-сценария.

Для длинных прогонов есть и периодические checkpoints: dashboard/host runner
по `EL_SCA_CHECKPOINT_INTERVAL_SECONDS` (по умолчанию 3600) пересохраняет
`checkpoint.json` и актуальный snapshot evidence в `run_dir`. Монитор
(`python -m resilient_updates.cli monitor`, `GET /api/monitor`, GUI-панель
«Монитор · контейнеры и прогресс») показывает текущий этап, контейнеры и
последний сохранённый snapshot.

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

### Batch: несколько артефактов за один запуск

Когда нужно прогнать пачку кейсов подряд — не копируйте foreach из чата,
используйте `batch-scan.ps1` (Phase 5.15). Он сам делает `try/catch` на
каждой цели, пишет цветную сводку, ставит `-CaseId` правильно и опционально
обновляет БД ровно один раз.

```powershell
.\scripts\windows\batch-scan.ps1 -Jobs @(
  @{ Case='CYBERSEC-12103'; Target='D:\__tests\_SCA\CYBERSEC-12103\avandoc-client-1.0.0.4.tar.gz' }
  @{ Case='CYBERSEC-12104'; Target='D:\__tests\_SCA\CYBERSEC-12104\DMS_AvandocClientServiceSetup1.zip' }
  @{ Case='CYBERSEC-12080'; Target='D:\__tests\_SCA\CYBERSEC-12080\iDocs11c2781f2-android-build-release-signed.zip' }
) -UpdateDbOnce
```

Или загрузить список из CSV/JSON — удобно для CI:

```powershell
.\scripts\windows\batch-scan.ps1 -JobsCsv .\batches\daily.csv
.\scripts\windows\batch-scan.ps1 -JobsJson .\batches\daily.json
```

Формат CSV: первая строка `Case,Target`, дальше пары. Строки, начинающиеся
с `#` в колонке `Case`, игнорируются. JSON — массив объектов вида
`[{"case":"…","target":"…"}, …]`.

Логика:

- Без `-UpdateDbOnce`/`-UpdateDbEvery` — обновление БД полностью выключено,
  используется уже установленный кэш (см. DB freshness banner в начале
  каждого `run-scan`).
- `-UpdateDbOnce` — `-UpdateDb` уходит только в **первый** job; остальные
  пользуются свежим кэшем. Это самый дешёвый способ освежить базы.
- `-UpdateDbEvery` — `-UpdateDb` на каждом job. Не рекомендуется (по
  5–15 минут на job), оставлено для строгой повторяемости.
- Exit code: `0` если все ok, `2` если хотя бы один job упал. Удобно для
  CI / scheduled-tasks.

#### High/Critical digest рядом с каждым отчётом

После каждого успешного job `batch-scan.ps1` (5.33) автоматически зовёт
`scripts\windows\make-high-critical-report.ps1` (5.32) и пишет рядом со
сканер-отчётом компактный документ `*_high_critical_<DATE>_ru.md` в
формате эталона CYBERSEC-11531: SHA-256 архива, краткая методика,
severity totals, и поимённый список Critical + High (с группировкой
High по сканеру). Этот digest предназначен для прикрепления к тикетам
и отправки заинтересованным сторонам — он короче полного scan-отчёта
и не требует знаний о структуре пайплайна.

Отключить шаг можно `-SkipHighCriticalDigest`. POSIX-зеркало —
`scripts/make-high-critical-report.sh`, флаг для `batch-scan.sh` —
`--skip-high-critical-digest`.

Запустить digest standalone (без re-scan) против уже существующих
отчётов:

```powershell
.\scripts\windows\make-high-critical-report.ps1 -Jobs @(
  @{ Target='D:\__tests\_SCA\CYBERSEC-12103\avandoc-client-1.0.0.4.tar.gz' }
  @{ Target='D:\__tests\_SCA\CYBERSEC-12104\DMS_AvandocClientServiceSetup1.zip' }
  @{ Target='D:\__tests\_SCA\CYBERSEC-12080\iDocs11c2781f2-android-build-release-signed.zip' }
)
```

Если последний прогон шёл с `-UpdateDb`, передайте `-OnlineDb` — digest
явно отметит, что базы были принудительно обновлены перед прогоном.

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
