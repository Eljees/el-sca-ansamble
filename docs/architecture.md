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
| `cli.py` | Точка входа, все команды CLI |
| `fallback.py` | HTTP-запросы с fallback по источникам, retry, классификация ошибок, прокси |
| `config.py` | Загрузка и валидация `feed_sources.yaml` |
| `source_policy.py` | Построение приоритетного списка источников для каждого инструмента |
| `reporting.py` | Сборка финального Markdown-отчёта из raw JSON |
| `healthcheck.py` | Проверка доступности источников |
| `provenance.py` | Запись provenance JSON |
| `atomic_publish.py` | Атомарная активация новой DB (rename, не copy) |
| `artifact_store.py` | Управление last-known-good снапшотами |
| `cve_db_audit.py` | Аудит качества cve-bin-tool DB |
| `extractor.py` | Python-обёртка над artifact-extractor контейнером |

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

| Профиль | Для чего | Сервисы |
|---|---|---|
| `update` | Обновление баз | trivy-updater, grype-updater, grype-db-importer, cve-bin-tool-updater |
| `scan` | Сканирование | syft-sbom, trivy-scanner, grype-scanner, grype-static, cve-bin-tool-scanner |
| `extract` | Распаковка архива | artifact-extractor |
| `report` | Сборка отчёта | report-collector |
| `offline` | Все сервисы без интернета | все scan + offline варианты |
| `test-failover` | Тестирование сценариев отказа | mock-feed-server, grype-updater |

Сервисы `grype-static` и `grype-scanner` связаны напрямую внутри Docker-сети `scanner-net` и не нуждаются в прокси.

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
