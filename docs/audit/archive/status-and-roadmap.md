# Текущее состояние и план развития

> ⚠️ **УСТАРЕЛО (по состоянию на 2026-06-01).** Документ отражает срез на 2026-05-14.
> Часть перечисленных ниже «поломок» уже исправлена позднее — в частности §2b
> (healthcheck без прокси) закрыт коммитом `55fa4fe`. Актуальное состояние и
> приоритизированную очередь см. в
> [`docs/audit/110-fixups-2026-06-01.md`](audit/110-fixups-2026-06-01.md) и в
> хронологии `docs/audit/`. Раздел «План развития» ниже ещё годится как ориентир;
> раздел «Что сейчас сломано» читать только сверяясь с последним аудитом.

> Документ актуален на 2026-05-14. Отражает состояние после двух рабочих сессий исправлений.

---

## 1. Что было исправлено (Фаза 1)

### Критические баги (пайплайн давал неверные результаты)

| Проблема | Файл | Суть |
|---|---|---|
| Syft получал 0 компонентов | `docs/operations.md`, `scan_archive.sh` | Архивы (.tar.gz, .rpm) нужно распаковывать до сканирования; создан `scan_archive.sh` как Linux-эквивалент `run-scan.ps1 -Extract` |
| `reporting.py` не находил provenance | `resilient_updates/reporting.py` | Путь был хардкоден как `artifacts/provenance`, не работал при запуске из другой CWD; исправлено через `Path.resolve()` и `rglob` |
| OCI-источники Trivy вызывали бесконечные ретраи | `resilient_updates/fallback.py` | `InvalidSchema` (протокол `oci://`) не ретраится; добавлен в `_NON_RETRYABLE_REASONS` |
| Дубли в `attempted_sources` в provenance | `resilient_updates/cli.py` | Каждый retry создавал дубль; добавлена дедупликация `_dedup_attempted_sources()` |
| Нет плейсхолдеров для отсутствующих отчётов | `scripts/collect_reports.sh` | Если cve-bin-tool не запустился, пайплайн падал; добавлена функция `_ensure_report` |
| `comands.txt` с NVD API ключами в git | `.gitignore` | Добавлен в `.gitignore`; создан `commit-fixes.ps1` для корректного снятия с трекинга |

### Новые возможности

| Фича | Где |
|---|---|
| Поддержка прокси (SOCKS5, HTTP/HTTPS) | `fallback.py`, `config.py`, `cli.py`, `docker-compose.yml`, `.env.example` |
| Таймаут cve-bin-tool scan (дефолт 10 мин) | `update_cve_bin_tool.sh`, `docker-compose.yml` |
| `scan_archive.sh` — Linux полный цикл | `scripts/scan_archive.sh` |
| `commit-fixes.ps1` — одна команда для коммита | `scripts/windows/commit-fixes.ps1` |
| Секция `proxy:` в `feed_sources.yaml` | `configs/feed_sources.yaml` |
| `x-proxy-env` YAML-якорь + `host.docker.internal` | `docker-compose.yml` |

### Документация

| Документ | Статус |
|---|---|
| `docs/operations.md` | Добавлены: extract→scan, proxy, диагностика нулевых находок |
| `docs/failure-modes.md` | Добавлены: 6 новых режимов отказа |
| `docs/architecture.md` | Переписан с 11 до 235 строк |
| `docs/proxy.md` | Создан с нуля: полное руководство для людей |
| `README.md` | Обновлены: ограничения MVP, troubleshooting, proxy, commit-fixes |

---

## 2. Что сейчас сломано или не идеально

### 2a. Тесты — нет покрытия новой функциональности

**Критично.** Все добавленные модули не покрыты тестами:

| Что не покрыто | Почему важно |
|---|---|
| `build_session()` с `ALL_PROXY` env | Легко сломать при рефакторинге |
| `parse_proxy_config()` / `validate_proxy_config()` | Валидация схем прокси |
| Дедупликация `attempted_sources` | Уже исправляли один раз — могут сломаться снова |
| cve-bin-tool scan timeout (exit 124) | Критический путь; плейсхолдер должен создаваться |
| Syft 0-компонент warning в `reporting.py` | Было добавлено без теста |

Тест `test_fallback_order.py` содержит **всего 1 тест** и не проверяет:
- `InvalidSchema` → немедленный skip без retry
- `AUTH_FAILURE` → немедленный skip
- корректную передачу `session` в downloader

### 2b. `healthcheck.py` не использует прокси

```python
# healthcheck.py сейчас:
source, _payload, attempts = attempt_sources(
    build_sources(config, "trivy", layer),
    timeout=..., retry_count=..., ...
    # ← нет session= !
)
```

`healthcheck` вызывается из `run_healthcheck()`, которая не создаёт сессию. Прокси туда не доходит. Это значит что команда `healthcheck` будет работать без прокси даже если прокси настроен в конфиге.

### 2c. Отчёт не сигнализирует о неполных данных cve-bin-tool

Когда cve-bin-tool завершается по таймауту, пишется пустой `[]`. В итоговом Markdown-отчёте это выглядит как «cve-bin-tool: 0 findings» — не отличить от «scan прошёл, ничего не нашёл». Нужен явный `Consistency warning: cve-bin-tool scan terminated by timeout`.

### 2d. Опасный дефолт `SCAN_TARGET_HOST=.`

В `docker-compose.yml`:
```yaml
source: ${SCAN_TARGET_HOST:-.}
```

Если переменная не задана, контейнер монтирует **весь репозиторий** как scan-target. Syft тогда будет индексировать сам стек, а не цель анализа. Ошибка не очевидна — результаты просто будут неверными.

### 2e. Нет проверки git commit

Все исправления находятся в рабочей директории, но **коммит ещё не сделан** (`.git/index.lock` мешал из Linux). Есть `commit-fixes.ps1`, но факт коммита не верифицирован.

### 2f. Документы, ранее бывшие заглушками — закрыто

Аудит 2026-05-25 подтвердил, что эти файлы давно перестали быть
заглушками; данные ниже сохранены для исторической справки.

| Файл | Было | Стало (на 2026-05-25) |
|---|---|---|
| `docs/security-notes.md` | 9 строк (заглушка) | 107 строк, полноценный документ |
| `docs/windows-powershell.md` | 17 строк (заглушка) | 177 строк, полноценный документ |
| `docs/custom-sources.md` | 24 строки | 174 строки, обновлён с примерами proxy `auth_env` |

См. `docs/audit/40-tooling-docs.md` section 4 для деталей.

### 2g. В репозитории лишние файлы

- `deep-research-report(4).md` — в корне репозитория, не относится к проекту
- `-prompts/` — директория с промптами разработки, не для пользователей
- Оба уже в `.gitignore` (`-prompts/` добавлена), но файлы продолжают лежать в рабочей директории

---

## 3. Архитектурные недостатки

### 3a. Нет CI/CD пайплайна

Нет ни одного автоматического запуска тестов. Правки вносятся вручную без проверки регрессий. Без доступа к PyPI в sandbox pytest вообще не запускается.

**Следствие:** тесты существуют (732 строки в 10 файлах, 27 тест-функций), но их никто не запускает системно.

### 3b. Зависимости не заморожены

`requirements.txt`:
```
PyYAML>=6.0
requests>=2.31.0
PySocks>=1.7.1
pytest>=8.0.0
```

`>=` без верхней границы. При следующем `pip install` может прийти breaking change. Нет `requirements.lock` или `pip-tools` генерации.

### 3c. Нет Makefile / task runner

Пользователи должны помнить длинные `docker compose --profile ... run --rm ...` команды. Есть `run-scan.ps1`, но нет единого entry point для частых задач: update-only, scan-only, report-only, full-cycle.

### 3d. Docker healthcheck не настроен

Сервисы не имеют `healthcheck:` директив. `grype-static` может завершиться с ошибкой, а `grype-scanner` запустится и упадёт с непонятной ошибкой вместо внятного «сервис не готов».

### 3e. Версии инструментов заданы дважды

В `docker-compose.yml` прибиты версии образов (`anchore/syft:v1.20.0`, `aquasec/trivy:0.64.1`). Если обновить образ — нужно обновлять и `.env.example` и возможно скрипты. Нет единого места с «текущими версиями».

---

## 4. Поэтапный план улучшений

### Фаза 2 — Надёжность (приоритет: высокий)

**2.1. Исправить `healthcheck.py` — прокинуть session**
- `run_healthcheck()` должна принимать `config` и создавать сессию через `build_session(parse_proxy_config(config))`
- Изменение: 5 строк в `healthcheck.py`

**2.2. Написать тесты для всего нового из Фазы 1**
- `tests/test_proxy.py` — `build_session()`, `ALL_PROXY`, explicit override, `validate_proxy_config()`
- `tests/test_fallback_order.py` — расширить: `InvalidSchema` no-retry, `AUTH_FAILURE` no-retry, session передаётся в downloader
- `tests/test_reporting.py` — syft 0-компонент warning, cve-bin-tool timeout warning

**2.3. Добавить cve-bin-tool timeout в Consistency warnings отчёта**
- В `reporting.py`: если `cve_count == 0` и отчёт существует — добавить warning что данные могут быть неполными из-за таймаута
- Или: писать маркер в `report.json` при таймауте и проверять его в `reporting.py`

**2.4. Исправить дефолт `SCAN_TARGET_HOST=.`**
- Либо убрать fallback `.` и требовать явного задания переменной
- Либо добавить проверку в скрипты: если `SCAN_TARGET_HOST` не задан — предупреждение

### Фаза 3 — Качество кода (приоритет: средний)

**3.1. Заморозить зависимости**
- Добавить `pip-tools`, создать `requirements.lock`
- В `Dockerfile.resilient-updater`: `pip install -r requirements.lock`

**3.2. CI пайплайн**
- GitHub Actions или GitLab CI: `pytest`, `python -m py_compile` для всех модулей, `docker compose config` (lint compose файла)
- Запускать при каждом push в master

**3.3. Makefile или taskfile**
```makefile
update:    # docker compose --profile update ...
scan:      # docker compose --profile scan ...
report:    # docker compose --profile report ...
full:      # update + scan + report
validate:  # python -m resilient_updates.cli validate-config
```

**3.4. Docker healthcheck для grype-static**
```yaml
healthcheck:
  test: ["CMD", "wget", "-qO-", "http://localhost:8080/v6/latest.json"]
  interval: 5s
  retries: 3
```

### Фаза 4 — Функциональность (приоритет: низкий)

**4.1. Явный маркер таймаута cve-bin-tool в отчёте**
- При `exit 124` записывать `{"_timeout": true, "timeout_seconds": N}` в `report.json`
- `reporting.py` проверяет маркер и добавляет предупреждение в отчёт

**4.2. Batch scan для нескольких артефактов**
- Скрипт принимает список путей / директорию с архивами
- Для каждого: extract → scan → individual report
- Aggregated summary по всем кейсам

**4.3. SBOM diffing**
- Сравнение двух SBOM (новая версия ПО vs старая)
- Показывает: новые компоненты, удалённые, компоненты с изменившимися CVE

**4.4. Автоматическое обновление версий образов**
- Скрипт проверяет последние версии Syft/Grype/Trivy на GitHub Releases
- Предлагает обновить `docker-compose.yml`

---

## 5. Документация — что дописать

| Документ | Статус | Что нужно |
|---|---|---|
| `docs/security-notes.md` | Заглушка 9 строк | Secrets management, proxy credentials, registry auth, image signing |
| `docs/windows-powershell.md` | Заглушка 17 строк | Полные примеры всех PS-команд, работа с `-Extract`, troubleshooting Windows-специфики |
| `docs/custom-sources.md` | Краткий | Добавить: proxy `auth_env`, примеры для OCI/HTTP/file источников |
| `CHANGELOG.md` | Отсутствует | История изменений по версиям |
| `docs/testing.md` | Отсутствует | Как запускать тесты, что тестируется, как добавить тест |

---

## 6. Итоговые числа

| Метрика | До Фазы 1 | После Фазы 1 |
|---|---|---|
| Syft компоненты (Prometheus) | 0 (не работало) | 427 ✅ |
| Grype findings | 0 (не работало) | 49 (2 critical, 28 high) ✅ |
| Тест-функций | 27 | 27 (новые не добавлены) |
| Покрытие прокси тестами | — | 0% |
| Docs: строк | ~350 | ~900 (+docs/proxy.md, arch переписан) |
| Незакоммиченных изменений | 0 | ~15 файлов (нужен `commit-fixes.ps1`) |
