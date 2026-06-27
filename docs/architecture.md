# Архитектура el-sca-ansamble

## Что это и зачем

el-sca-ansamble — контейнерный оркестратор для SCA (Software Composition Analysis): автоматизированного поиска уязвимостей в бинарных артефактах, пакетах и зависимостях.

Главный принцип: **wrapper-first, не fork**. Логика отказоустойчивости, fallback между источниками баз и сборка итогового отчёта реализованы во внешнем Python-пакете `resilient_updates`, а сами сканеры (Trivy, Grype, Syft, cve-bin-tool) запускаются upstream-образами без модификаций.

---

## Компоненты и их роли

### Сканеры

| Компонент | Роль | Что создаёт |
|---|---|---|
| **Syft** | Генерация SBOM | `artifacts/sbom/syft.json`, `cyclonedx.json`, `spdx.json` |
| **Grype** | Matching CVE по SBOM | `artifacts/reports/grype/report.json` |
| **Trivy** | Независимый vulnerability scan | `artifacts/reports/trivy/report.json` |
| **cve-bin-tool** | Бинарный scan + NVD/OSV данные | `artifacts/reports/cve-bin-tool/report.json` |
| **artifact-extractor** | Рекурсивная распаковка архивов | `artifacts/extracted/current/` + `extraction_manifest.json` |

### Python-оркестратор (`resilient_updates`)

Пакет живёт в `resilient_updates/` и запускается как `python -m resilient_updates.cli <команда>`.

| Модуль | Что делает |
|---|---|
| `cli.py` | Точка входа, все команды CLI; `_probe_layer` принимает `RetryPolicy` напрямую (A_OBS-1) |
| `fallback.py` | HTTP-запросы с fallback по источникам, retry, классификация ошибок, прокси |
| `config.py` | Загрузка и валидация `feed_sources.yaml` |
| `source_policy.py` | Построение приоритетного списка источников для каждого инструмента |
| `reporting.py` | Сборка финального Markdown-отчёта из raw JSON |
| `healthcheck.py` | Проверка доступности источников; `_health_summary` принимает `RetryPolicy` напрямую (A_OBS-2) |
| `provenance.py` | Запись provenance JSON |
| `atomic_publish.py` | Атомарная активация новой DB (rename, не copy) |
| `artifact_store.py` | Управление last-known-good снапшотами |
| `cve_db_audit.py` | Аудит качества cve-bin-tool DB |
| `extractor.py` | Python-обёртка над artifact-extractor контейнером |
| `proxy_chain.py` | Маршрутизация через named-chain прокси (tinyproxy / xray / vpn) + failover |
| `scanner_diff.py` | Сравнение двух прогонов: added/removed components и findings |
| `enrichment.py` | EPSS + CISA KEV обогащение findings |
| `run_summary.py` | Сборка `summary.json`/`status.json`/`db_snapshot.json`/`run_manifest.json` |
| `manifest.py` | Единый `MANIFEST.json` со ссылками на все артефакты прогона |
| `_io.py` | Общие hash- и JSON-утилиты для четырёх модулей выше |
| `_retry.py` | `RetryPolicy` dataclass — единая точка истины для retry/backoff |
| `_logging.py` | Setup root logger; `LOG_LEVEL` + `LOG_FORMAT=json` из env |
| `orchestrator.py` | `JobRegistry` — фоновые задачи update/scan, SSE-поток для GUI, последовательный запуск `run --rm` шагов (ADR-0007) |
| `dashboard.py` | FastAPI-приложение: GUI, SSE, `/api/route-plan`, `/api/proxy-chain` (ADR-0006) |
| `route_plan.py` | Зондирование egress изнутри `scanner-net`; выбор маршрута per-tool; кэш плана 5 мин (ADR-0007 P2) |
| `update_doctor.py` | `update-doctor` — матрица достижимости `(tool, layer) × chain` без сайд-эффектов (ADR-0007 P1) |
| `nvd_feed_import.py` | Локальная копия NVD api2-парсера cve-bin-tool 3.4 с двумя фиксами + network fallback если локальные фиды пусты |
| `scan.py` | Unified scan pipeline builder (ADR-0005): plan builder + `--dry-run`; реальный запуск через subprocess |
| `vex.py` | Получение VEX-документов через fallback-pipeline и атомарная публикация в кэш Trivy (ADR-0003) |
| `run_layout.py` | Per-run артефактная директория, `checkpoint.json`, периодические снапшоты в ходе скана |
| `pipeline_state.py` | Атомарный чекпоинт `artifacts/pipeline_state.json`: begin/stage-start/stage-end/finish; resume-логика (`completed_stages`, `should_skip`); `summarize` для монитора |
| `monitor.py` | Монитор комплекса: `gather_status` (compose ps + pipeline + DB + лог), `render_text`; consumer'ы — CLI `monitor`, `GET /api/monitor`, MCP `monitor` |

#### CLI subcommands

`python -m resilient_updates.cli <команда>` — актуальный список на 2026-06-12:

| Команда | Назначение |
|---|---|
| `validate-config` | Проверить `feed_sources.yaml` на валидность схемы |
| `healthcheck` | Опросить все источники и записать provenance |
| `provenance` | Распечатать собранную provenance из `artifacts/provenance/` |
| `db-status` | Текущее состояние всех DB (возраст, источник, источник-кандидат) |
| `audit` | Аудит cve-bin-tool DB (sources, counts, age) |
| `activate` | Принудительная активация выбранного DB-кандидата |
| `seed` | Заполнение `internal-mirror` (EPSS / RSD / OSV ecosystems) |
| `collect-report` | Сборка финального Markdown-отчёта |
| `extract` | Распаковка через `artifact-extractor` контейнер |
| `render-flags` | Рендеринг Trivy CLI-флагов из YAML-конфига |
| `write-run-summary` | Деривация sidecar JSON-ов (summary/status/db_snapshot/run_manifest) |
| `scan` | Запуск unified scan pipeline (ADR-0005); `--dry-run` печатает план без запуска |
| `dashboard` | Запуск FastAPI GUI (ADR-0006) |
| `update-doctor` | Матрица достижимости источников обновлений через все цепочки (ADR-0007 P1) |
| `route-plan` | Зондирование egress + `--write-xray` генерация конфига xray-сайдкара (ADR-0007 P2) |
| `update <tool>` | Обновление DB для trivy / grype / cve-bin-tool |
| `proxy-status` | Healthcheck всех proxy-цепочек, запись `artifacts/provenance/proxy.json` |
| `run-state` | Управление чекпоинтами пайплайна: `begin|stage-start|stage-end|stage-skip|finish|show|should-skip` |
| `monitor` | Статус контейнеров + текущий этап + DB-свежесть; `--watch N` — автообновление, `--json` |
| `scanner-diff` | Сравнение двух `artifacts/` директорий |
| `manifest` | Сборка корневого `MANIFEST.json` со ссылками на все артефакты прогона |
| `archive-run` | Копирование артефактов прогона в per-run директорию (`artifacts/runs/<name>/`) |

---

## Потоки данных

### Полный цикл: обновление → скан → отчёт

```
[feed_sources.yaml]
       │
       ▼
resilient_updates.cli update grype
  └─ attempt_sources() ──► [источник 1] / [fallback 2] / [last-known-good]
       │
       ▼
grype-db volume  ←──── grype-updater container
       │
       ▼
grype-static (HTTP 8080) ◄── grype-db-importer
       │
       ├─── [входной архив] ──► artifact-extractor ──► artifacts/extracted/current/
       │                                                         │
       ▼                                                         ▼
syft-sbom ──────────────────────────────────────────────► artifacts/sbom/syft.json
       │
       ├──► grype-scanner ──► artifacts/reports/grype/report.json
       │
       ├──► trivy-scanner ──► artifacts/reports/trivy/report.json
       │
       └──► cve-bin-tool-scanner ──► artifacts/reports/cve-bin-tool/report.json
                                                    │
                                                    ▼
                                          report-collector
                                          (collect_reports.sh +
                                           resilient_updates collect-report)
                                                    │
                                                    ▼
                                    artifacts/reports/final/
                                    cve_analysis_report_generated_ru.md
```

### Grype DB: путь от источника до скана

Grype требует специфичного формата DB и не умеет сам делать fallback между источниками. Поэтому wrapper реализует это за него:

```
[upstream_update_urls в feed_sources.yaml]
       │
       ▼
grype-updater (resilient_updates update grype)
  ├─ скачать listing.json с каждого источника (по приоритету)
  ├─ скачать db.archive
  ├─ проверить sha256 checksum
  ├─ проверить возраст (max_allowed_built_age)
  └─ атомарно активировать: temp → active (rename)
       │
       ▼
grype-db volume / active/
       │
       ▼
grype-db-importer: grype db import /active/db.tar.zst
       │
       ▼
grype-cache volume (runtime cache)
       │
       ▼
grype-static: python -m http.server 8080 (раздаёт из active/)
       │
       ▼
grype-scanner: GRYPE_DB_UPDATE_URL=http://grype-static:8080
               GRYPE_DB_AUTO_UPDATE=false
```

---

## Docker Compose профили

Состояние профилей на 2026-06-27 (источник истины — `docker-compose.yml`, 25 сервисов, 17 профилей):

| Профиль | Для чего | Сервисы |
|---|---|---|
| `default` | Базовый набор для голого `docker compose up` (без updater-ов) | stack-info, trivy-scanner, grype-db-importer, grype-static, grype-scanner, syft-sbom, artifact-extractor, cve-bin-tool-scanner, db-admin, report-collector |
| `update` | Обновление баз | trivy-updater, grype-updater, grype-db-importer, cve-bin-tool-updater, db-admin, report-collector |
| `scan` | Сканирование артефакта | trivy-scanner, grype-scanner, grype-static, syft-sbom, artifact-extractor, cve-bin-tool-scanner, db-admin, report-collector |
| `extract` | Только распаковка | artifact-extractor |
| `report` | Только сборка финального Markdown / HTML | db-admin, report-collector |
| `offline` | Сканирование без сети (только локальные DB) | grype-db-importer, grype-static, grype-scanner, syft-sbom, artifact-extractor, trivy-scanner, cve-bin-tool-scanner, db-admin, report-collector |
| `airgap` | Жёсткий air-gap (никаких updater-ов вообще) | то же, что `offline`, без `*-updater` |
| `test-failover` | Failover-тесты | mock-feed-server, grype-updater, grype-static, db-admin, report-collector |
| `apk` | Специализированный APK pipeline | apk-analyzer |
| `win` | Специализированный Windows-installer pipeline | win-analyzer |
| `osv` | Дополнительный OSV-Scanner over SBOM | osv-scanner |
| `proxy` | Sidecar proxy chain (tinyproxy + xray) | proxy-xray, tinyproxy |
| `vpn` | WireGuard-туннель для случаев VPN-only зеркал | wireguard |
| `dashboard` | FastAPI-дашборд для просмотра прогонов и provenance (ADR-0006) | dashboard |
| `db-bundle` | Экспорт/импорт DB-бандлов (оффлайн передача баз) | db-exporter, db-importer |
| `route` | Зондирование egress и выбор маршрута per-tool (ADR-0007 P1.5) | route-doctor |
| `volinit` | Предварительная инициализация named volumes с нужными правами | volume-init |

Сервис `dashboard` собирается из `Dockerfile.resilient-updater` и поднимает
FastAPI-приложение (`resilient_updates.dashboard`) поверх каталога `artifacts/`.

Сервисы `grype-static` и `grype-scanner` связаны напрямую внутри
Docker-сети `scanner-net` и не нуждаются в прокси.

См. `docs/audit/40-tooling-docs.md` section 3 — там зафиксирована
история, что эта таблица раньше показывала только 6 профилей из 12.

---

## CI/CD

Конвейер описан в `.github/workflows/ci.yml` (GitHub Actions) и `.gitlab-ci.yml` (GitLab CI).
GitLab зеркалирует GitHub: те же jobs, те же правила блокировки. Ниже — список jobs и их назначение.

### GitHub Actions / GitLab CI — jobs

| Job | Стадия | Инструмент | Блокирует сборку |
|---|---|---|---|
| `pre-commit` | lint | pre-commit (все хуки разом) | ✅ да |
| `lint-python` | lint | ruff check + ruff format --check + compileall | ✅ да |
| `bandit` | lint | bandit ≥ MEDIUM в `resilient_updates/` + `tools/` | ✅ да |
| `lint-shell` | lint | shellcheck ≥ warning (исключая `scripts/windows/`) | ✅ да |
| `lint-docker` | lint | hadolint по каждому `Dockerfile.*` (матрица 6) | ✅ да |
| `lint-yaml` | lint | yamllint strict | ✅ да |
| `lint-powershell` | lint | PSScriptAnalyzer (Error-severity) для `scripts/windows/` | ✅ да |
| `lint-versions` | lint | версии `versions.env` = `pyproject.toml` = `docker-compose.yml` fallback | ✅ да |
| `compose-config` | build | `docker compose config -q` (base + windows overlay) | ✅ да |
| `docker-build` | build | `docker compose build` (матрица 5 сервисов) | ✅ да (needs lint-docker) |
| `smoke` | test | pytest -m smoke | ✅ да (needs lint-python) |
| `pytest` | test | pytest -m "not integration" + coverage ≥ 88% на py3.12 | ✅ да (needs smoke) |

Матрица `docker-build` охватывает сервисы: `resilient-updater`, `extractor`, `cve-bin-tool`,
`apk-analyzer`, `win-analyzer` (без `db-data` — нестандартный build context).

Матрица `pytest` охватывает Python 3.10 (без coverage gate) и 3.12 (gate 88%).

Покрытие загружается как артефакт (`coverage.xml`); в GitLab CI настроен `coverage_report`
с форматом Cobertura.

---

## Хранение данных

### Docker named volumes (не в репозитории)

| Volume | Содержимое |
|---|---|
| `trivy-cache` | Trivy vulnerability DB и Java DB |
| `grype-db` | Скачанный и активированный Grype DB archive |
| `grype-cache` | Runtime cache для grype-scanner |
| `cve-bin-tool-cache` | SQLite DB cve-bin-tool |
| `internal-mirror-data` | Mirror/export артефакты |

### Директория `artifacts/` (в репозитории, исключена .gitignore)

```
artifacts/
├── sbom/                    # SBOM-файлы (syft.json, cyclonedx.json, spdx.json)
├── reports/
│   ├── grype/               # raw JSON Grype
│   ├── trivy/               # raw JSON Trivy
│   ├── cve-bin-tool/        # raw JSON cve-bin-tool
│   └── final/               # итоговые Markdown-отчёты
├── provenance/              # provenance JSON по каждому инструменту
└── extracted/
    └── current/             # результат распаковки + extraction_manifest.json
```

---

## Provenance

Каждое обновление DB и healthcheck записывает `artifacts/provenance/<tool>.json`:

```json
{
  "tool": "grype",
  "artifact_type": "grype-db",
  "selected_source": { "name": "internal-grype-mirror", "url": "..." },
  "attempted_sources": [...],
  "failures": [{ "source": "upstream-1", "reason": "timeout", ... }],
  "activation_status": "activated",
  "used_last_known_good": false,
  "timestamp_utc": "2026-05-14T12:00:00+00:00"
}
```

Provenance включается в финальный Markdown-отчёт. Это позволяет ответить на вопрос «откуда взялись данные о CVE» — важно для аудита и инцидент-ресёрча.

---

## Отказоустойчивость

### Fallback между источниками

Реализован в `fallback.attempt_sources()`:

1. Попытка скачать с источника 1 (наивысший приоритет).
2. При ошибке — retry с backoff (configurable).
3. При невосстановимой ошибке (OCI `invalid_schema`, auth failure, HTTP 4xx) — сразу к следующему источнику без повторов.
4. Если все источники недоступны — last-known-good snapshot.
5. Если нет ни одного — fail closed (exit code 2).

### cve-bin-tool scan timeout

cve-bin-tool запускает 365 regex-паттернов побайтово по каждому файлу. Для крупных Go-бинарей (~100 МБ) это может занять часы. Поэтому scan обёрнут в `timeout $CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS` (дефолт 600 с). При таймауте пишется пустой `[]` отчёт и пайплайн продолжается.

### Подробнее о режимах отказа

См. [docs/failure-modes.md](failure-modes.md).

---

## Прокси

Подробное руководство: [docs/proxy.md](proxy.md).

Краткая схема:
- Python-слой: `build_session()` читает `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` из env; явный конфиг в `feed_sources.yaml` секции `proxy:` имеет приоритет.
- Docker-контейнеры: YAML-якорь `x-proxy-env` прокидывает все proxy-переменные (upper + lower case) через `<<: *proxy-env`; `extra_hosts: [host.docker.internal:host-gateway]` позволяет использовать `host.docker.internal:PORT` вместо `127.0.0.1`.

---

## Конфигурация

Главный файл: `configs/feed_sources.yaml`.

Структура:
```yaml
proxy:          # прокси для Python-слоя (опционально)
trivy:          # источники DB, политики retry, статус DB
grype:          # источники DB, validation, atomic activation, last-known-good
cve_bin_tool:   # источники, NVD API keys, audit политики, зеркала
syft:           # разрешённые типы источников
custom_sources: # пользовательские источники (oci-registry, http, file, git, s3)
```

Валидация при каждом старте: `python -m resilient_updates.cli validate-config`.

---

## Расширение: добавить новый источник

1. Добавить запись в нужный раздел `feed_sources.yaml` (или в `custom_sources.entries`).
2. Задать `priority` (меньше = важнее), `url`, `enabled: true`.
3. Для аутентификации: `auth_env: ENV_VAR_NAME` — значение берётся из env, не хранится в YAML.
4. Запустить `validate-config` — конфиг будет проверен на дубли приоритетов, недопустимые типы и небезопасные значения.
