> [!WARNING]
> Snapshot of 2026-05-25 and is OUTDATED as a defect register: D1-D18 are closed (except D13),
> the suite has grown to ~673 tests. For current state see the latest NNN-analysis/NNN-fixups
> in docs/audit/ (now: 270-analysis-2026-06-11.md).

# Audit 2026-05-25 — Тесты и покрытие

## 1. Инвентаризация

| Файл | LOC | Test-функций | Тестируемый модуль |
|---|---:|---:|---|
| `test_analyzers.py` | 278 | 25 (классы) | `scripts/analyze_apk.py`, `scripts/analyze_win_installer.py` |
| `test_proxy.py` | 160 | 16 | `resilient_updates/config.py` proxy parsing |
| `test_proxy_chain.py` | 165 | 12 | `resilient_updates/proxy_chain.py` |
| `test_run_summary.py` | 208 | 9 | `resilient_updates/run_summary.py` |
| `test_mock_failures.py` | 239 | 8 | failover паттерны |
| `test_enrichment.py` | 118 | 7 | `resilient_updates/enrichment.py` |
| `test_fallback_order.py` | 162 | 6 | `resilient_updates/fallback.py` |
| `test_cve_db_audit.py` | 149 | 6 | `resilient_updates/cve_db_audit.py` |
| `test_shell_contracts.py` | 46 | 5 | поведение shell-скриптов |
| `test_scanner_diff.py` | 172 | 5 | `resilient_updates/scanner_diff.py` |
| `test_cli.py` | 138 | 5 | `resilient_updates/cli.py` |
| `test_extractor.py` | 53 | 3 | `resilient_updates/extractor.py` |
| `test_report_html.py` | 178 | 2 | `scripts/report_html.py` |
| `test_atomic_publish.py` | 45 | 2 | `resilient_updates/atomic_publish.py` |
| `test_source_policy.py` | 21 | 1 | `resilient_updates/source_policy.py` |
| `test_reporting.py` | 69 | 1 | `resilient_updates/reporting.py` |
| `test_provenance.py` | 17 | 1 | `resilient_updates/provenance.py` |
| `test_config_validation.py` | 30 | 1 | `resilient_updates/config.py` validation |
| **Итого** | **2438** | **115** | — |

В CI: `pytest -q --maxfail=1 --disable-warnings --cov=resilient_updates --cov-report=term-missing`.

## 2. Распределение покрытия

Карта «строк продакшен-кода / тестов»:

| Модуль | LOC | Тест-функций | Соотношение |
|---|---:|---:|---:|
| `cli.py` | 947 | 5 | **189 LOC/test** |
| `report_html.py` | 947 | 2 | **474 LOC/test** ← скрипт, не модуль, но используется |
| `extractor.py` | 530 | 3 | **177 LOC/test** |
| `reporting.py` | 537 | 1 | **537 LOC/test** ← хуже всех |
| `proxy_chain.py` | 453 | 12 | 38 LOC/test |
| `run_summary.py` | 449 | 9 | 50 LOC/test |
| `cve_db_audit.py` | 411 | 6 | 68 LOC/test |
| `scanner_diff.py` | 345 | 5 | 69 LOC/test |
| `fallback.py` | 150 | 6 | 25 LOC/test |
| `config.py` | 230 | 17 | 14 LOC/test |
| `enrichment.py` | 191 | 7 | 27 LOC/test |
| `healthcheck.py` | 120 | — | **∞** ← не покрыт |
| `atomic_publish.py` | 25 | 2 | 13 LOC/test |
| `provenance.py` | 26 | 1 | 26 LOC/test |
| `source_policy.py` | 107 | 1 | 107 LOC/test |

**Топ-5 дыр**:

1. `cli.py` — 947 строк, 5 тестов. Не покрыты subcommands `db-status`, `activate`, `seed`, `extract`, `render-flags`, `scanner-diff`, `manifest`. Не покрыт `update grype/trivy/cve_bin_tool` цикл с реальной фикстурой.
2. `reporting.py` — 537 строк, 1 тест. Не покрыты ветки timeout, нестандартные status.json/summary.json, fallback in-memory derivation.
3. `extractor.py` — 530 строк, 3 теста. Не покрыты `_extract_external` (7z/rar/zst), pre-filter `max-member-size`, `--skip-ext` логика, escape-имена на Windows.
4. `cve_db_audit.py` — 411 строк, 6 тестов. Не покрыты `_db_policy` branches (после фазы A когда параметр заработает).
5. `healthcheck.py` — 120 строк, 0 тестов. Запускается в живом виде только в `cli.py healthcheck`, нет unit-coverage.

## 3. Отсутствующая интеграция

В CI не запускается ни один сценарий «реальный compose». Есть
`mock-feed-server` (`tests/mock_feed_server/`) — фейковый
HTTP-сервер для failover-сценариев, но он только в профиле
`test-failover` и в CI его никто не дёргает.

**Предложение** (фаза D):

- Job `smoke-integration` в CI с матрицей `os: [ubuntu-latest]`:
  ```yaml
  - run: docker compose --profile scan config -q
  - run: docker compose build resilient-updater extractor
  - run: docker compose --profile test-failover up -d mock-feed-server
  - run: pytest -m smoke -q
  ```
- В `pytest.ini`: маркер `smoke` для тестов, требующих docker.
- Хотя бы один тест: «extractor распаковывает реальный `.tar.gz` →
  manifest валиден → SBOM пишется».

## 4. Coverage gate

В CI:

```
pytest -q --maxfail=1 --disable-warnings --cov=resilient_updates --cov-report=term-missing
```

Нет `--cov-fail-under=N`. Pytest сообщает «X % covered», но не падает,
если покрытие проседает. Регресс в coverage не ловится.

**Предложение** (фаза D/F):

1. Зафиксировать сегодняшнее покрытие на CI (после фазы B–C —
   надо замерить).
2. Добавить `--cov-fail-under=75` (можно начать с 70, и поднимать).
3. Загружать `.coverage` artefact с `actions/upload-artifact` (уже есть)
   + `actions/setup-python` с pip cache (уже есть).

## 5. Фрагильные тесты

Беглый обзор показывает несколько фрагильных мест:

- `test_analyzers.py:25-31` — `_load_script` через `exec(compile(...))` без
  настоящего import. Это работает, но любой тест с этой функцией будет
  пересоздавать модуль на каждый вызов. Замедление + сюрпризы с
  module-level state.
- `test_mock_failures.py` зависит от поднятия `mock_feed_server` —
  если порт занят локально, тест упадёт с непонятной ошибкой.
- `test_report_html.py:178` — 2 теста на ~947 строк скрипта.
  Регрессии в HTML-генерации поймаются только глазами.
- `tests/test_atomic_publish.py:45` — 2 теста, оба happy-path. Race-condition Windows-fallback не покрыт.

## 6. Что добавить (фаза D)

| Файл | Что покрыть |
|---|---|
| `tests/test_extractor_advanced.py` | `--max-member-size-mb`, `--skip-ext`, tar.zst через `_extract_external`, escape-имена |
| `tests/test_cli_subcommands.py` | `db-status`, `activate`, `seed`, `render-flags`, `scanner-diff`, `manifest` |
| `tests/test_cve_db_audit_policy.py` | strict / degraded-ok / lkg-ok behaviour matrix (фаза A добавит логику) |
| `tests/test_healthcheck.py` | unit-mocks для `requests`, проверка JSON-схемы выхода |
| `tests/test_atomic_publish_race.py` | Windows-fallback с моком `os.replace` |
| `tests/test_io.py` | новый `_io.sha256_file/sha512_file/read_json` после фазы B |
| `tests/test_logging.py` | `_logging.setup_logging` JSON-режим (фаза C) |
| `tests/test_manifest.py` | `MANIFEST.json` контракт (фаза C) |
| `tests/test_smoke_compose.py` | интеграционный, маркер `smoke` |

## 7. Запуск в этом аудите

В sandbox-окружении установить `pytest` не получилось (нет доступа к PyPI). Все Python-модули прошли `python -m compileall -q resilient_updates tests scripts/*.py` без ошибок. Полноценный прогон тестов нужно сделать на хост-машине:

```sh
make test
# либо
pytest -q --cov=resilient_updates --cov-report=term-missing
```

Если на хосте `make test` падает — это первое, что чиним до фазы B.

---

**См. также:** [00-overview.md](00-overview.md) · [10-defects.md](10-defects.md) · [20-architecture.md](20-architecture.md) · [40-tooling-docs.md](40-tooling-docs.md)
