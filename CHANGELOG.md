# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
loosely adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `pipeline_state.begin_run`: проверка `schema_version` при resume — несовместимый
  формат сбрасывает состояние вместо тихого mismatch. (`13ebe00`)
- `cli.py`: создание `temp_dir` перед записью grype-архива (grype мог падать с
  FileNotFoundError при отсутствии каталога). (`8810d61`)
- `cve_db_audit`: NVD-детекция через `nvdcve*.json.gz`-файлы; `cve_severity`-таблица
  для NVD заполняется через `cve_metrics` — ранее count всегда возвращал 0. (`cb12af3`)
- `atomic_publish`: фолбэк на уникальный staging-путь при сбое `rmtree` на
  Docker overlayfs (Python 3.12 `_rmtree_safe_fd` не мог удалить 47K-файловое
  дерево на overlayfs). (`106d74e`)
- Windows `run-scan.ps1`: загрузка `route-plan.env` (прокси) перед `-UpdateDb` —
  без этого прокси не применялся при обновлении БД. (`91c19cd`)
- Windows `run_scan_async` (MCP): делегирование на `powershell.exe run-scan.ps1`
  вместо `bash run-scan.sh`; stdout/stderr перенаправляются в
  `artifacts/run-scan.log`. (`b306b42`)
- `tools/docker-mcp/server.py`: `mcp.run()` вместо голого `mcp` в `__main__` —
  без этого сервер завершался немедленно при запуске через `python server.py`.
  Исправлен также `# noqa: WPS515,SIM115` (ruff SIM115 не подавлялся старым
  `# noqa: WPS515`). (`4e81b95`)
- `deploy_light.sh`: автодетект `BUNDLE_DIR` распознаёт бандл, разбитый на части
  (`bundle/el-sca-images-light.tar.part*`), а не только собранный `.tar` — иначе
  «голый» `./scripts/deploy_light.sh` падал с `no such file` на чистом клоне
  (бандл шиппится частями через Git LFS).
- `update_grype` + `feed_sources.yaml`: multi-source failover при сетевых ошибках —
  таймаут / `ReadTimeout` / `ConnectionError` на одном источнике больше НЕ роняет
  обновление, а переходит к следующему источнику (раньше ловился только
  `ValueError`, поэтому троттлинг CDN `grype.anchore.io` ронял весь прогон).
  Добавлен запасной источник `anchore-toolbox-data` (другой хост Anchore);
  `update_download_timeout` поднят 30s→300s (архив grype v6 ~200 МБ).

### Changed

- `configs/feed_sources.yaml`: `min_entries.NVD` снижен с 1000 → 20 (NVD хранит
  метаданные в `cve_metrics`, а не в `cve_severity`; прежний порог всегда давал
  «пустую» базу). (`cb12af3`)

## [0.1.3] - 2026-06-13

### Added

- **Живой таймер этапа в GUI.** Карточка активного этапа в «Процессе анализа»
  показывает прошедшее время (`▶ 42s`) с обновлением каждую секунду и
  пульсирующую подсветку — очевидно, что сканер работает, а не завис.
  Heartbeat-интервал снижен с 30 → 10 с по умолчанию (`EL_SCA_HEARTBEAT_SECONDS`).
- **Имена артефактов рядом с источником (`near-source`).** Дефолтный режим
  сохранения прогонов изменён с `artifacts` на `auto` (оркестратор, `run-scan.sh`
  уже использовал `auto`). В режиме `auto` папка прогона создаётся рядом с
  исходным артефактом: `<dir-артефакта>/<пакет>-<YYYYMMDD-HHMMSS>/` — легко
  найти отчёт рядом с тем, что сканировалось. Управляется через
  `EL_SCA_RUN_OUTPUT_MODE=artifacts|near-source|auto`.
- **Чекпоинты пайплайна + resume (`pipeline_state.py`).** Каждый переход
  этапа (extract → sbom → grype → trivy → cve-bin-tool → report) атомарно
  фиксируется в `artifacts/pipeline_state.json` с ключом прогона
  (target+tool+format). Прерванный/повисший скан продолжается с последнего
  завершённого этапа: `run-scan.sh --resume`, `run-scan.ps1 -Resume`,
  кнопка «⏯ Продолжить с чекпоинта» в дашборде, MCP
  `run_scan(_async)(resume=True)`. CLI-обвязка: `cli run-state
  begin|stage-start|stage-end|stage-skip|finish|show|should-skip`.
- **Heartbeat — живой вывод на долгих этапах.** `run-scan.sh` печатает
  `[stage] … выполняется, прошло Ns` каждые `EL_SCA_HEARTBEAT_SECONDS`
  (по умолч. 30; `--heartbeat N`); оркестратор дашборда шлёт строку статуса
  в SSE-лог, когда контейнер молчит дольше heartbeat-интервала. Каждый этап
  печатает время старта и итоговую длительность (sh и ps1) — больше никакого
  «кажется, повисло».
- **Монитор комплекса.** `python -m resilient_updates.cli monitor
  [--watch N] [--json]` (resilient_updates/monitor.py) — статус
  compose-контейнеров, текущий этап с elapsed, длительности завершённых
  этапов, свежесть баз, хвост лога; `make monitor`. В GUI — панель
  «Монитор · контейнеры и прогресс» (обновление каждые 5 с,
  `GET /api/monitor`); в MCP — тул `monitor`, а `scan_status` дополнен
  структурным блоком `pipeline`.
- **Развёртывание в несколько команд.** `scripts/bootstrap.sh`
  (`make bootstrap` / `make bootstrap-full`) и
  `scripts/windows/bootstrap.ps1`: docker-check → `.env` из шаблона →
  валидация compose → volume-init → сборка образов → (опц.) обновление баз →
  smoke. Идемпотентно; с чистого clone до рабочего комплекса — одна команда.

### Fixed

- `scripts/run-scan.sh`: критическая ошибка — отсутствовал `set -e` в ряде
  путей; hardened robustness stderr/perms на Linux и Windows.
- `scripts/windows/bootstrap.ps1`: заменён PS7-only null-conditional `?.Source`
  на 5.1-safe `Get-Command/.Source`; добавлен `resume:`-hint в «next steps».
- `scripts/run-scan.sh`: `report-collector` запускается с `-u 0` (согласовано
  с run-scan.ps1 и оркестратором) — устранена ошибка прав на uid-owned report-dir.
- `scripts/windows/run-scan.ps1`: добавлен параметр `-Heartbeat` (паритет с
  `--heartbeat` в run-scan.sh); `EL_SCA_HEARTBEAT_SECONDS` экспортируется.
- `scripts/update-db.sh`: persist `db_status/*.json` после обновления баз —
  барели дашборда показывают заполнение без необходимости запускать полный скан.
- `resilient_updates/monitor.py`: UTF-8 stdout на Windows — текстовый вид
  монитора больше не падает на non-ASCII символах.
- `scripts/bootstrap.sh`: установка host-зависимостей Python (fastapi, uvicorn,
  python-multipart) — CLI и дашборд работают out-of-box после bootstrap.
- `scripts/run-scan.sh` + `scripts/windows/run-scan.ps1`: абсолютный путь
  `ARTIFACTS_DIR` в collect-report/report-html — фикс WSL getcwd race.
- `tests/test_orchestrator.py`: fake `_run_scan` принимает новый kwarg
  `resume` (устранён PytestUnhandledThreadExceptionWarning).

## [0.1.2] - 2026-06-12

### Added

- **Route-doctor — обновление БД из любой сети (ADR-0007 P2).** Сервис
  `route-doctor` (профиль `route`) зондирует egress изнутри `scanner-net`
  (сайдкары tinyproxy/proxy-xray, локальный прокси хоста через
  `host.docker.internal`, direct) и пишет `artifacts/route-plan.{json,env}`;
  `resilient_updates/route_plan.py` + CLI `route-plan` (`--write-xray`
  перенацеливает upstream xray-сайдкара на живой хост-прокси:
  `configs/xray/config.gen.json` + override `docker-compose.route-doctor.yml`).
  cve-bin-tool всегда получает HTTP-мост (его клиент не умеет SOCKS).
- **Авто-маршрут везде, по умолчанию (откат на direct):** `run-scan.sh
  --update-db`, веб-кнопки обновления (orchestrator), MCP `update_db` —
  применяют план route-doctor, если `HTTP_PROXY`/`ALL_PROXY` не заданы явно.
  Отключение: `EL_SCA_AUTO_ROUTE=0` / `--no-auto-route` / `auto_route=False`.
- **Обновление баз по отдельности или всех сразу, без скана:**
  `scripts/update-db.sh [all|tool]`, `make update` / `make update TOOL=x`
  (легаси-вариант — `make update-compose`); MCP `update_db(tool="all")`
  обновляет все три базы за один вызов с одним сетевым зондированием (план
  кэшируется 5 минут); новый MCP-тул `route_plan(force)`.
- **Дашборд:** `GET/POST /api/route-plan` + индикатор «🛰 Маршрут» в шапке
  с кнопкой перепроверки сети.

- **Volume-init one-shot** — сервис `volume-init` (профиль `volinit`, alpine,
  root) выставляет владельца uid 1001 на именованных томах перед каждым
  обновлением. Без него `grype-updater` падал с EACCES на
  `/var/lib/resilient-db/grype/tmp`, а `report-collector` не мог перезаписать
  root-owned `artifacts/summary.json`. Запускается через отдельный
  `compose run --rm` (не в составе `up --abort-on-container-exit`).
- **Последовательные шаги обновления** — `start_update` и `update-db.sh`
  запускают каждый апдейтер отдельным `compose run --rm` вместо общего
  `up --abort-on-container-exit`. Это устраняет каскадное убийство
  долгоиграющего cve-bin-tool mid-download при быстром выходе любого другого
  контейнера (exit 137).
- **NVD feed network fallback** — если `modes=feed` + локальная директория
  фидов пуста, `nvd_feed_import.py` автоматически переключается на
  `nvd.nist.gov` при наличии egress (curl / `ALL_PROXY` / `HTTP_PROXY`);
  без egress — предупреждение вместо тихого аборта с 0 CVE.

### Fixed

- Профиль `proxy` не поднимался: `tinyproxy` ждал `service_healthy` от
  `proxy-xray`, у которого healthcheck отключён → `service_started`.
- `make update` (`up --abort-on-container-exit`) мог обрываться быстро
  выходящими one-shot сервисами: `route-doctor` оставлен только в профиле
  `route`.
- run-scan.sh/update-db.sh применяют только свежий (≤10 мин) route-plan.env —
  устаревший план от упавшего доктора не уводит апдейтеры на мёртвый прокси;
  частичный план (exit 2) применяется для маршрутизируемых инструментов.

### Maintenance

- `build_update_command()` помечена устаревшей (`.. deprecated::`) — реальный
  путь обновления использует последовательные `run --rm` шаги.
- `nvd_feed_import._format_data_api2_safe` — добавлена заметка о необходимости
  синхронизации с upstream при апгрейде cve-bin-tool > 3.4.
- `pytest.ini` — обновлена ссылка на актуальный аудит-документ.
- `ruff format` — ликвидирован drift в 3 файлах после сессий с FUSE-mount.
- `docker-compose.yml` `volume-init` — добавлен `mkdir -p` для 7 поддиректорий
  `artifacts/` перед `chmod -R 0777`, чтобы root-owned родительские директории не
  блокировали запись uid-1001 контейнерами (grype-updater, report-collector, cve-bin-tool).
- `pyproject.toml` — версия синхронизирована с `versions.env` и CHANGELOG: `0.1.0 → 0.1.1`.
- `docs/architecture.md` — добавлены 8 пропущенных модулей (`orchestrator.py`, `dashboard.py`,
  `route_plan.py`, `update_doctor.py`, `nvd_feed_import.py`, `scan.py`, `vex.py`,
  `run_layout.py`) и 5 пропущенных CLI-команд (`scan`, `dashboard`, `update-doctor`,
  `route-plan`, `archive-run`); дата таблицы обновлена на 2026-06-12.
- `CONTRIBUTING.md` — исправлены: значение coverage gate (75→88), примеры команд для
  `smoke`/`integration` маркеров, описание назначения маркеров (были перепутаны).
- `scripts/README.md` — добавлены 9 пропущенных скриптов: `update-db.sh`, `scan.sh`,
  `export_images.sh`, `import_images.sh`, `pack_light.sh`, `deploy_light.sh`,
  `export_db_image.sh`, `import_db_image.sh`, `reproduce-cybersec-11531.sh`.
- `tests/test_orchestrator.py` — зафиксированы 10 ранее не закоммиченных тестов.
- Audit-баннеры в `docs/audit/00–30-*.md` — счётчик тестов обновлён до 722.
- `tests/test_orchestrator.py` — ещё 10 целевых тестов для непокрытых ветвей
  (`start_update` single-step, `current_stage_key`, `maybe_periodic_checkpoint`,
  `feed_line` progress в auto-detect режиме, `_resolve_stage` / `begin_stage` /
  `end_stage` no-op пути); покрытие `orchestrator.py` 86 % → 91 %.
- `tests/test_dashboard.py` — 18 новых целевых тестов для вспомогательных функций
  (`_provenance_status`, `_deep_find`, `_read_env_versions`) и endpoint-ветвей
  (403 при `EL_SCA_DASHBOARD_ACTIVE=0`, `/api/route-plan` GET/POST, 500 на ошибку
  записи); покрытие `dashboard.py` 86 % → 99 %.
- `tests/test_nvd_feed_import.py` — исправлен нестабильный тест
  `test_main_continues_after_feed_download_failure`: добавлены `monkeypatch.delenv`
  для всех proxy-переменных окружения и mock `shutil.which`, блокирующий
  Windows-специфичный egress через `curl.exe`.
- Coverage gate: поднят с 85 % до 88 % в `.github/workflows/ci.yml`,
  `.gitlab-ci.yml` и `Makefile`; суммарное покрытие: **93 %** (740 тестов).
- `requirements.txt` — полностью закреплён через `pip-compile --generate-hashes`
  (pip-tools 7.5.3, Python 3.12): все 26 прямых и транзитивных зависимостей
  несут `--hash=sha256:...` для воспроизводимых и tamper-evident Docker-сборок.
- `pytest.ini` — добавлено подавление `ResourceWarning` (httpx/starlette оставляют
  незакрытые сокеты в Python 3.12+), `DeprecationWarning` от starlette/fastapi,
  маркер `integration` (Docker/compose/сеть; по умолчанию исключается в CI).
- `docs/adr/0003-vex-feed.md`, `docs/adr/0005-unified-cli-scan.md` — статус
  изменён с `proposed` на `accepted`; `docs/adr/README.md` обновлён.
- `.gitignore` — добавлены паттерны для `route-doctor.out` и `Dockerfile.*.fc`
  (editor backup), артефакты отладочной сессии (`*.done`, `_local_*.txt` и др.).

## [0.1.1] - 2026-06-11

### Added

- **Proxy-chain toggle in the dashboard** — `GET/POST /api/proxy-chain` + UI
  button cycling `direct | corp | via-vpn`. Runtime selection is persisted to
  gitignored `configs/feed_sources.runtime.yaml`; `load_config()` overlays it
  over the static `configs/feed_sources.yaml` (which stays clean in git).
- **Linux volume-init overlay** (`docker-compose.linux.override.yml`) — fixes
  named-volume UID ownership on Linux hosts.
- **Run history, policy gate, diff** — runs archived to `artifacts/runs/`
  (retention 20), `configs/policy.json` severity gate, "Diff с предыдущим
  прогоном" section in reports; async MCP scan (`run_scan_async`/`scan_status`).
- **Docs:** Ubuntu-from-GitHub deploy guide, remote SCA runbook + wrapper,
  minimal system requirements and per-OS install paths in README/START_HERE.

### Changed

- Extractor: incremental limits; default extraction depth is now unlimited
  (`EXTRACT_MAX_DEPTH=0`); `PYTHONPATH` fixed in the extractor container.
- Syft: update self-check disabled (`SYFT_CHECK_FOR_APP_UPDATE=false`).
- tinyproxy: PID file moved to `/tmp`, image pinned to `latest`.

### Fixed

- **cve-bin-tool source isolation** — `--disable-data-source` flags collapsed
  into a single CSV argument (cve-bin-tool kept only the last flag, so
  "EPSS-only" runs silently pulled all sources for 3+ hours).
- proxy-xray healthcheck disabled (used `sh`, absent in the distroless image;
  FailingStreak grew unbounded).
- Python 3.10 compatibility: `datetime.UTC` shims in `nvd_feed_import`/`vex`
  (bare import broke test collection on the 3.10 CI matrix).
- `artifacts/nvd-feeds/*.gz` (~190 MB) untracked from git; README chat-noise
  tail removed; compose override files gitignored.

### Tests

- 426 → 673 tests; coverage expansion for cli, extractor, nvd_feed_import,
  cve_db_audit, proxy_chain, manifest, scanner_diff, run_summary, enrichment,
  orchestrator, dashboard (proxy-chain + runtime-override suites).

## [0.1.0] - 2026-06-06

First versioned cut. Consolidates the resilient SCA stack (Trivy/Grype/Syft/
cve-bin-tool), the drag-drop dashboard, the cve-bin-tool NVD feed channel, and
all prior automated audit fixups into one tagged baseline.

### Added — 2026-06-06 (cve-bin-tool feed channel + GUI barrels)

- **`resilient_updates/nvd_feed_import.py`** — `feed` update channel for
  cve-bin-tool: builds the NVD half of `cve.db` directly from the static NVD
  **2.0** JSON data feeds (reusing cve-bin-tool's own `format_data_api2`),
  bypassing the rate-limited REST API (403 in restricted contours) and the
  retired 1.1 feeds. Downloads via curl (SOCKS-aware) or local files.
- **`scripts/fetch_nvd_feeds.ps1`** — host-side NVD 2.0 feed downloader for
  air-gapped/SOCKS contours; the importer reads them with `file://`.
- **GUI DB panel ("☢ бочки")** — per-tool + per-source update buttons, live
  download progress, and a red ✕ for bases that can't be loaded in the current
  contour (`CVE_BIN_TOOL_ENRICH_DISABLE`).
- **Non-NVD source enrichment** (OSV/CURL/EPSS/PURL2CPE) routed through the
  xray HTTP sidecar (HTTP→SOCKS bridge): `CVE_BIN_TOOL_ENRICH_PROXY`,
  `CVE_BIN_TOOL_ENRICH_DISABLE`; runs before the NVD feed import so the fetch
  isn't skipped on a fresh DB.
- **`docs/cve-bin-tool-feed.md`** — documents the feed channel, proxy bridge,
  and shipping `cve.db` + image to GitLab.
- Project version (`EL_SCA_VERSION` in `versions.env`) + `docs/RELEASING.md`
  pre-push checklist.

### Changed — 2026-06-06

- `pack-light` `-WithCveBinTool` now also builds and ships the cve-bin-tool
  **image** (not just `cve.db`), so the bundle is air-gap complete.
- DB-update compose commands use `--force-recreate` to avoid reusing a stale
  updater container with a dead network-endpoint ("network <id> not found").
- Barrel fill reflects activation **health**: `degraded` (NVD-only) = 80%.
- `configs/xray/config.json` upstream → `host.docker.internal:10808`.

### Fixed — 2026-06-06

- **Extractor hardening** — per-member isolation in zip/tar (one corrupt/
  encrypted/unsafe member is skipped, not fatal to the archive), timeout on
  external tools (7z/rar/zst can't hang forever), guarded sha/type-detection.
  No single archive can kill the extraction run.
- `trivy-updater` now writes `provenance/trivy.json`, so the Trivy barrel
  reflects the refreshed DB.
- `dashboard.py` missing `import os` (broke `/api/tools`).

### Added — 2026-06-01 automated fixup pass (docs/audit/110–120)

- **`resilient_updates/vex.py`** — VEX document acquisition module (ADR-0003).
  Fetches VEX docs through the same resilient fallback pipeline as DB layers,
  publishes them atomically into `<trivy cache_dir>/vex/`, and records
  provenance.  `cli update vex` delegates to it; `cli render-flags trivy`
  emits `--vex` flags when the cache is populated.  No-op when
  `trivy.vex_repositories` is empty.
- **`docs/adr/0003-vex-feed.md`** — design record for VEX acquisition.
- **`docs/adr/0004-epss-kev-freshness.md`** — design record for planned
  EPSS/KEV enrichment cache (not yet implemented).
- **`tests/test_vex.py`** — 18 unit tests covering all `vex.py` functions
  (`_vex_dir`, `_format_for`, `_ext_for`, `_atomic_write_bytes`, `_fresh_lkg`,
  `fetch_vex` — happy path, LKG fallback, no-sources).
- **`docs/audit/100-fixups-2026-05-31.md`** through
  **`docs/audit/120-fixups-2026-06-01b.md`** — four additional automated audit
  passes documenting findings, fixes applied, and carry-forward items.

### Changed — 2026-06-01 automated fixup pass

- **`cli.py` `update trivy` / `update cve_bin_tool` paths** now use
  `RetryPolicy.from_tool_config(config, tool)` instead of reading
  `retry_backoff_policy` dict keys inline.  One source of truth for retry
  parameters across all update paths.
- **`healthcheck.run_healthcheck`** now probes `trivy-vex` layer in addition
  to `trivy-db`, `trivy-java-db`, `trivy-checks`.
- **`scanner_diff.py`** — removed duplicate local `_first_json` helper; now
  imports `first_json` from `_io` (completing the §1 DRY consolidation).
- **`Makefile` `test` target** — removed `--maxfail=1`; `make test` now
  reports all failing tests instead of stopping at the first.
- **`.pre-commit-config.yaml`** — ruff hook bumped from `v0.5.7` to
  `v0.15.15`, aligning pre-commit with local and CI ruff version.

### Added — 2026-05-25 audit + DRY refactor (docs/audit/)

- **`docs/audit/` (5 files)** — independent audit of architecture, defects,
  tests, tooling, documentation.  Entry point: `docs/audit/00-overview.md`.
- **`resilient_updates/_io.py`** — shared `sha1_file` / `sha256_file` /
  `sha512_file` / `sha256_dir` / `read_json` / `first_json` /
  `collect_json` / `short_hash` / `hash_pair`.  Replaces three
  duplicated copies across `reporting.py` / `run_summary.py` /
  `extractor.py` / `scanner_diff.py`.
- **`resilient_updates/_retry.py`** — `RetryPolicy` dataclass plus
  `from_yaml_node` / `from_tool_config` factories.  Eliminates the
  hardcoded `retry_count=1, backoff_seconds=1` in `cli.update_grype`.
- **`resilient_updates/_logging.py`** — `setup_logging()` with optional
  `LOG_FORMAT=json` for structured logs in CI.  Wired into `cli.main`.
- **`resilient_updates/manifest.py`** — `derive_manifest` + `write_manifest`
  produce a single root `artifacts/MANIFEST.json` linking the eight-or-so
  per-run provenance files.
- **`python -m resilient_updates.cli manifest`** — new CLI subcommand.
- **`configs/wireguard/wg0.conf.example`** — VPN profile no longer fails
  on missing bind-mount source.
- **`docs/INDEX.md`** — sitemap of all documentation organised by audience.
- **`docs/adr/README.md`** — ADR index.
- **`CONTRIBUTING.md`**, **`SECURITY.md`** — root-level dev / disclosure docs.
- **`versions.env`** — single source of truth for upstream scanner /
  sidecar image tags.
- **`pytest.ini`** — markers (`smoke`, `slow`) and strict-marker mode.
- **`requirements.lock`** — placeholder, populated by `make lock`.
- **Tests:** `test_io.py`, `test_retry_policy.py`, `test_logging_setup.py`,
  `test_manifest.py`, `test_fallback_windows_file_url.py`.

### Fixed — 2026-05-25 audit hot-fixes

- **`fallback.fetch_bytes` `file://` URLs on Windows.**  `urlparse` leaves
  `/C:/x/y` as the path; `Path()` fails.  Now routed through
  `urllib.request.url2pathname`.  See `docs/audit/10-defects.md` section 4.
- **`proxy_chain._do_probe`: 4xx no longer counted as `ok`.**  Changed
  `< 500` to `< 400`; corp proxies that return 401/403/404 on
  `generate_204` now correctly trip failover.  See section 3.
- **`Dockerfile.cve-bin-tool` deduplicated pip install.**  Two separate
  `pip install` lines could let the second silently upgrade pins from
  the first; merged into one resolver pass.  Section 6.
- **`scripts/update_trivy.sh` FLAGS array.**  `$FLAGS` is now spread into
  POSIX positional parameters via `set -- $FLAGS`; subsequent trivy
  invocations use the correctly-quoted `"$@"` instead of a single
  unquoted variable.  Section 8.
- **`extractor` uses `shlex.quote` from stdlib** instead of an inline
  custom implementation that missed edge cases.  Section 11.

### Changed — 2026-05-25 DRY refactor

- `reporting.py` / `run_summary.py` / `extractor.py` / `scanner_diff.py`
  now import from `resilient_updates._io`; the inlined hash/JSON
  helpers were removed.  See `docs/audit/20-architecture.md` section 1.
- `configs/feed_sources.yaml` gained a `grype.retry_backoff_policy`
  section.  Previously the listing-fetch retry was hardcoded as
  `retry_count=1, backoff_seconds=1` in `cli.update_grype`.
- `DEPLOYMENT_GUIDE_FINAL.md` renamed to `DEPLOYMENT_GUIDE_EXAMPLE.md`
  with a header disclaimer pointing to the canonical
  `docs/operations.md` / `docs/windows-powershell.md`.
- `docs/architecture.md` profile and CLI tables now match the actual
  `docker-compose.yml` (19 services, 12 profiles) and `cli.py --help`
  (15 subcommands incl. the new `manifest`).
- `docs/status-and-roadmap.md` section 2f no longer claims that
  `security-notes.md` / `windows-powershell.md` / `custom-sources.md`
  are stubs — they have been full documents since Phase 4.

### CI — 2026-05-25

- New job `pre-commit` runs `pre-commit run --all-files` so hooks and
  per-tool CI cannot drift apart.
- New matrix job `docker-build` exercises `docker compose build` for
  every Dockerfile (catches breakages hadolint can't see).
- `pytest` job adds `--cov-fail-under=75` and uploads `coverage.xml`.

### Security — 2026-05-25 audit

- **NVD API keys moved out of `.env`.**  `.env` lived under a synced
  cloud-drive folder (`D:\!ya_drive_sync\YandexDisk\...`) so the
  plaintext keys it contained were being uploaded to Yandex Disk.
  `.env` now contains only non-secret defaults; the actual key values
  live in `.env.local` (also gitignored).  Rotate both keys in NVD
  to be safe.  See `docs/audit/10-defects.md` section 1.

### Pending user-action

- `git rm --cached deep-research-report(4).md "Исследование контейнеризации*.docx"`
  (these are tracked but listed in `.gitignore`).
- Rotate `NVD_API_KEY` and `NVD_API_KEY_FALLBACK` in the NVD console;
  install new values in `.env.local`.

### Audit delta v2 — 2026-05-26 (docs/audit/50-delta-2026-05-25-v2.md)

Повторный независимый аудит после переноса в `D:\dev\el-sca-ansamble`.
Подтвердил применение фаз A–F; нашёл несколько недотянутых хвостов и
парy false-positive'ов (Linux-mount stale-кэш ввёл в заблуждение по двум
пунктам).  Полный отчёт — `docs/audit/50-delta-2026-05-25-v2.md`.

**Added / Changed**

- **`docker-compose.yml` — 4 sidecar image-тега через `${…_VERSION:-…}`.**
  Раньше `versions.env` объявлял `OSV_SCANNER_VERSION`/`XRAY_VERSION`/
  `TINYPROXY_VERSION`/`WIREGUARD_VERSION`, но в compose они не
  использовались.  Теперь `osv-scanner` / `proxy-xray` / `tinyproxy` /
  `wireguard` берут версию из `versions.env`.  Five основных
  scanner-images уже были параметризованы фазой F.  See NEW-2.
- **`Dockerfile.cve-bin-tool` — `ARG CVE_BIN_TOOL_VERSION=3.4`.**
  `pip install … "cve-bin-tool==${CVE_BIN_TOOL_VERSION}"`; чтобы compose
  мог прокинуть build-arg, в `docker-compose.yml` для cve-bin-tool
  сервисов нужно дописать `build: { args: { CVE_BIN_TOOL_VERSION:
  ${CVE_BIN_TOOL_VERSION:-3.4} } }` — оставлено как follow-up, чтобы не
  трогать build-блоки до подтверждения `make lock`.

**False-positives, выловленные перепроверкой через прямой read**

- ~~`docs/operations.md:44` всё ещё `grype:v0.82.0`~~ — на самом деле
  уже `v0.112.0` (фаза E закрыла).
- ~~Все 5 `Dockerfile.*` запускаются от root~~ — на самом деле все
  имеют `USER appuser` + `useradd …` (фаза B/F закрыла).
- ~~`enrichment.date_value` пишется как float~~ — на самом деле уже
  `datetime.fromtimestamp(...).isoformat()`.
- ~~`windows.override.yml` без комментариев к 4G tmpfs~~ — в файле уже
  развёрнутый комментарий-объяснение.

**Pending user-action (новое)**

- `git restore --staged artifacts/db_snapshot.json artifacts/run_manifest.json artifacts/status.json artifacts/summary.json`
  — runtime-артефакты случайно попали в индекс (`.gitignore` уже верный,
  им просто нужно успеть вступить).
- `make lock` — `requirements.lock` пока placeholder (написано в самом
  файле); сгенерировать настоящий с `--generate-hashes`.
- `make test` (или `pytest -q --cov=resilient_updates --cov-report=term-missing`)
  — измерить baseline покрытия, подстроить `--cov-fail-under` в CI.

**Carry-over открытые после v2**

- `cli._dedup_attempted_sources` last-wins (10-defects §15).
- `Dockerfile.apk-analyzer` `JAVA_TOOL_OPTIONS=-Xmx512m` без override (10-defects §18).
- `cve_db_audit._activate` Windows race-window сокращено, но не нулевое (10-defects §13).

---

### Added — 2026-05-20 batch-time digest

- **#5.32 `scripts/windows/make-high-critical-report.ps1`** — standalone
  PowerShell helper that parses an existing run-scan markdown report
  (`*_report_<DATE>.md`) and writes a sibling digest
  `*_high_critical_<DATE>_ru.md` in the CYBERSEC-11531 reference format:
  archive SHA-256, scanner counts, severity totals, Critical findings
  (with originating tool), High findings grouped by scanner.  Accepts a
  single `-Target`/`-ReportPath` or a batch `-Jobs @(...)` array; emits
  a small SUMMARY at the end.
- **#5.33 `scripts/windows/batch-scan.ps1`** — after each successful
  scan, invokes the new helper automatically.  New
  `-SkipHighCriticalDigest` switch turns this off.  When the job
  triggered a `-UpdateDb`, the digest header is annotated «с
  принудительным online-обновлением перед прогоном» so triagers don't
  read it as a stale-DB result.
- **#5.34 `scripts/make-high-critical-report.sh`** — POSIX mirror of
  the PowerShell helper.  Uses `sha256sum` for the archive hash and an
  inline Python heredoc for the markdown walk (regex + table reader is
  hard to keep tidy in pure bash).  Accepts `--target`, `--report`,
  `--jobs-json`, or `--jobs-csv`.  `scripts/batch-scan.sh` calls it
  after each successful job unless `--skip-high-critical-digest` is
  passed.

### Added — Delta from 2026-05-17 (PLAN_2026-05-17.md)

- **#22 Run-summary derivation.** New module
  `resilient_updates/run_summary.py` (`derive`, `write_to_disk`) computes
  the four sidecar JSONs (`summary.json`, `status.json`,
  `run_manifest.json`, `db_snapshot.json`) from existing scanner
  artefacts.  New CLI subcommand `python -m resilient_updates.cli
  write-run-summary --reports-dir <dir>` writes them to disk;
  `scripts/collect_reports.sh` calls it before assembling the final
  Markdown so the header stops showing `UNKNOWN` for DB snapshot, DB
  drift, tool failures, update policy, and input archive SHA-256.
  `reporting.build_report` also does the same derivation in-memory as a
  fallback when the files don't exist, so external invocations stay
  honest too.
- **#5.12 SBOM sanitiser.** `scripts/update_cve_bin_tool.sh` now always
  patches the SBOM before `--sbom-file`: it filters components whose
  `version` is empty / `null` / `unknown` (case-insensitive) so
  cve-bin-tool 3.4 no longer aborts mid-scan with
  `UnknownVersion('version string = UNKNOWN')`.  The same patcher
  injects Go runtime versions when found.
- **#5.14 -UpdateDb warning.** `scripts/windows/run-scan.ps1` prints a
  loud yellow banner when `-UpdateDb` is passed (5–15 min wait expected,
  link to `.env.local` NVD keys, instruction to drop the flag if not
  intentional).  Pairs with the existing DB freshness banner.
- **#5.13 Tests for new modules.**
  - `tests/test_scanner_diff.py` — components added/removed/version-change
    /severity-delta / Markdown headers.
  - `tests/test_enrichment.py` — EPSS CSV parser (incl. malformed rows),
    CISA KEV in both JSON shapes, `enrich_findings`.
  - `tests/test_proxy_chain.py` — Hop / ProxyChain / Policies dataclasses,
    `validate_chains` happy + 2 failure cases, ProxyRouter per-source pin,
    failover, session.proxies, `write_provenance`.
  - `tests/test_run_summary.py` — counts, single + multi-input sha,
    db_snapshot_id, empty root (no exception), timeout flag detection,
    `write_to_disk` creates 4 files, `overwrite=False` respected.
- **#5.15 `scripts/windows/batch-scan.ps1`** — reusable batch runner
  (inline `-Jobs`, `-JobsCsv`, `-JobsJson`).  Wraps each
  `run-scan.ps1` call in try/catch so a single failure doesn't abort the
  rest; prints a colour-coded SUMMARY (`syft / grype / cbt / sev`) per
  case; exit 2 if any case failed (CI-friendly).  `-UpdateDbOnce`
  refreshes DBs only for the first job; `-UpdateDbEvery` is opt-in for
  the truly paranoid.
- **#5.18 `scripts/batch-scan.sh`** — Linux/macOS mirror of `batch-scan.ps1`.
  Accepts `--case/--target` pairs (repeatable), `--jobs-json`, or
  `--jobs-csv`.  Same try-style continue-on-error semantics, same
  SUMMARY table, same exit code contract.
- **#5.20 `make batch`** — Makefile target.  `JOBS_JSON=…` or
  `JOBS_CSV=…`, optional `UPDATE_DB_ONCE=1`.  Delegates to
  `scripts/batch-scan.sh`.
- **#5.21 `--case-id` thread-through.** `scripts/run-scan.sh` already
  accepted `--case-id`; `scripts/batch-scan.sh` now passes it explicitly
  so the Markdown header is correct on the first try (the in-script
  regex rewrite is preserved as a safety net for older runs).
- **#5.22 `batches/` directory.** `example.csv`, `example.json`, and a
  `README.md` so users have a ready-to-edit shape for the runners.
  `.gitignore` keeps committed examples while preventing accidental
  upload of `daily.*` job lists.
- **#5.23 README "Что нового".** Top-level README now opens with a
  short pointer to the day's headline changes: batch-scan, sidecar
  JSON-derivation, DB freshness banner, no-update-by-default,
  `-UpdateDb` warning.
- **#5.26 CLI smoke for `write-run-summary`.** `tests/test_cli.py` got
  two new tests covering happy-path (4 sidecars created) and
  `--no-overwrite` (existing summary survives).
- **#5.28 `scripts/benchmark.sh`** — Linux/macOS mirror of
  `scripts/windows/benchmark.ps1`.  N back-to-back runs with `time`
  capture, JSON summary, host snapshot.

### Changed — Delta from 2026-05-17

- **#24 No-update-by-default profile policy.** `docker-compose.yml`:
  `trivy-updater` now sits in `["update"]`, `grype-updater` in
  `["update", "test-failover"]`, `cve-bin-tool-updater` in `["update"]`.
  All three have been removed from `default` and `offline` profiles.
  Plain `docker compose up` (without `--profile`) no longer attempts to
  reach out to upstream DB sources, and `offline` now genuinely means
  "scan only with local DB" — same semantics `airgap` already had.
- **`scripts/windows/run-scan.ps1` Clean step rewritten** to run via a
  one-shot `alpine sh -c 'find /cleanme -type f ! -name .gitkeep
  -delete'` container.  PowerShell's `Remove-Item` chokes on NTFS-illegal
  names like `app.\AvandocClient.cmd` that innoextract leaves when
  unpacking NSIS installers.  Docker sees the same paths through the 9P
  bind mount as plain ext4 and deletes them happily.  Fallback to
  in-process PowerShell + cmd.exe is preserved when Docker isn't
  reachable.

- **#5.24 `grype-static` healthcheck timing.** `start_period` 3s → 10s,
  `retries` 5 → 10.  Grace window for `grype-scanner` while DB-server
  warms up is now ≈ 60 s (matches `docs/runbook.md` §3.4 observation of
  5–20 s cold-start stabilisation on Docker Desktop).

### Fixed — Delta from 2026-05-17

- **cve-bin-tool binary scan crashed with `invalid choice: '8'`.** Phase
  3.4 mistakenly wired the worker count to cve-bin-tool's `-n` flag, but
  in v3.4 `-n` is reserved for `--nvd <mode>`.  Removed the
  `PARALLEL_FLAGS` from the binary-scan call site; binary scan still
  runs in parallel via cve-bin-tool's internal `multiprocessing.Pool`,
  sized to the host CPU count.  `CVE_BIN_TOOL_PARALLEL` is preserved as
  an env knob with a no-op note for the day upstream ships a real
  `--workers N` flag.

### Added — Phase 0–4 of PLAN_2026-05-16.md

- **Network / proxy / VPN layer.**
  - New optional sidecars in `docker-compose.yml`: `proxy-xray` (SOCKS5:1080
    + HTTP:8118), `tinyproxy` (HTTP front:8888, SOCKS5 upstream), `wireguard`
    (profile `vpn`).
  - Configurations under `configs/xray/` and `configs/tinyproxy/`.
  - YAML chains in `configs/feed_sources.yaml`:
    `proxy.chains`, `proxy.policies` (failover_order, healthcheck TTL,
    retry budget), `proxy.per_source` mapping.
  - New module `resilient_updates/proxy_chain.py` (`ProxyRouter`,
    `ProxyChain`, `Hop`, `Policies`, `validate_chains`).
  - New CLI command `python -m resilient_updates.cli proxy-status`
    writing `artifacts/provenance/proxy.json`.
  - `validate_proxy_config` now validates both flat and chained styles.
  - Documentation: `docs/network-design.md`, `docs/adr/0001-wrapper-first.md`,
    `docs/adr/0002-proxy-sidecar.md`.
  - `.env.example` block for the sidecar chain.

- **Windows acceleration (Phase 3).**
  - `scripts/windows/setup-defender-exclusions.ps1` — idempotent Defender
    exclusions for project + Docker VHDX + WSL helpers; writes provenance.
  - `scripts/windows/benchmark.ps1` — wall-clock benchmark harness writing
    `artifacts/provenance/benchmark.json`.
  - `docker-compose.windows.override.yml` — tmpfs `/tmp` (4 GB for
    cve-bin-tool-scanner, 2 GB elsewhere) plus named volume
    `extracted-staging` so extractor scratch stays on ext4.
  - BuildKit cache mounts (`--mount=type=cache`) in every Dockerfile;
    `# syntax=docker/dockerfile:1.7` header on each.
  - cve-bin-tool parallelism: `CVE_BIN_TOOL_PARALLEL` env knob, auto-default
    to `nproc/2` (capped at 8).
  - Extractor pre-filter: `EXTRACT_MAX_MEMBER_SIZE_MB` and the existing
    `--skip-ext`/`--max-member-size-mb` CLI flags.

- **Quality / tooling (Phase 4).**
  - GitHub Actions workflow `.github/workflows/ci.yml`: lint (ruff,
    shellcheck, hadolint, yamllint, PSScriptAnalyzer), compose schema
    check, pytest with coverage.
  - Linter configs: `.ruff.toml`, `.hadolint.yaml`, `.yamllint`,
    `PSScriptAnalyzerSettings.psd1`.
  - `.pre-commit-config.yaml` with ruff, shellcheck, yamllint, hadolint,
    generic hygiene hooks.
  - `Makefile` with targets `validate`, `update`, `scan`, `report`, `full`,
    `test`, `lint`, `lint-py`, `lint-sh`, `lint-docker`, `lint-yaml`,
    `lock`, `hooks`, `clean`, `clean-deep`.
  - `requirements.in` (pip-tools source of truth) + workflow documentation
    inside `requirements.txt`.

### Changed

- **cve-bin-tool Go runtime injection now multi-version** (Phase 5.7).
  `scripts/update_cve_bin_tool.sh` previously took the first `go1.X.Y`
  string it saw in any binary and injected it as the single
  `golang:go` SBOM component, then `break`ed out of the binary walk.
  When a target ships several binaries built with different Go
  toolchains (e.g. Prometheus 3.11 had go1.23.0 and go1.26.1), only the
  first match made it into the SBOM and only one Go-runtime CVE
  matched per scan — silently undercounting.  The injection now:
  detects ELF files by magic bytes 0x7F-E-L-F (works on Windows
  NTFS bind-mounts where the executable bit is not preserved),
  collects every unique `go1.X.Y` across all ELFs, and adds each
  version as a separate `golang:go` CycloneDX component.  Result:
  a clean `run-scan.ps1 -Clean` against the reference Prometheus
  tarball now produces one finding per unique Go runtime, matching
  the binary-scan baseline.

- `docker-compose.yml`:
  - `grype-static` now has a `healthcheck` (Python urllib probe on `:8080`);
    `grype-scanner` gains a `depends_on: grype-static (service_healthy)`.
  - `cve-bin-tool-scanner` `SCAN_TARGET_HOST` default changed from `.`
    (a silent footgun mounting the whole repo) to fail-fast `:?`.
- `resilient_updates/healthcheck.py` extended to probe grype-db and
  cve-bin-tool-mirror layers in addition to the existing three trivy
  layers; the response now carries a `proxy` block with the active session
  settings.
- `scripts/run-scan.sh` / `scripts/run_scan.sh` got header banners to make
  the dash-vs-underscore naming collision obvious; `scripts/README.md`
  spells out who is who.
- `configs/feed_sources.yaml` proxy section reorganised to support both
  legacy flat form and the new chain form.

### Fixed

- `.env.example` no longer defines `HTTP_PROXY=` twice (the second blank
  declaration silently shadowed the corporate-proxy example).
- `.env.example` ordering: cve-bin-tool timeout block no longer embeds
  itself inside the proxy comment block.

### Documentation

- `PLAN_2026-05-16.md` — full audit + phased plan (root of repo).
- `docs/network-design.md` — sidecar topology, YAML chain schema,
  diagnostics, security notes.
- `docs/adr/0001-wrapper-first.md` — retroactive ADR capturing the
  wrapper-first decision.
- `docs/adr/0002-proxy-sidecar.md` — rationale and alternatives for the
  proxy chain.
- `scripts/README.md` — index of every shell/PS script with purpose,
  Docker dependency, and Windows mirror.

## [3.0.0] — 2026-05-15

Highlights:

- cve-bin-tool exit-code handling in `scripts/windows/run-scan.ps1` fixed
  (exit 1 = "CVEs found", not failure); all scan calls routed through
  `Invoke-CveBinToolChecked`.
- Example deployment guide `DEPLOYMENT_GUIDE_EXAMPLE.md` covering
  X-Ray SOCKS5 setup, SSH reverse tunnel, Docker proxy configuration.
- Migration from v2.0: backward compatible — no changes required.

## [2.0.0] — 2026-04-14

Internal release (see `docs/status-and-roadmap.md` Phase 1):

- Provenance handling rewritten (path resolved via `Path.resolve()` + `rglob`).
- `InvalidSchema` no longer retried for OCI sources.
- Deduplication of `attempted_sources` in provenance.
- Initial proxy support (flat env / yaml form).
- cve-bin-tool scan timeout wrapper.

[Unreleased]: https://github.com/Eljees/el-sca-ansamble/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/Eljees/el-sca-ansamble/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Eljees/el-sca-ansamble/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Eljees/el-sca-ansamble/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Eljees/el-sca-ansamble/releases/tag/v0.1.0
[3.0.0]: https://github.com/Eljees/el-sca-ansamble/releases/tag/v3.0.0
[2.0.0]: https://github.com/Eljees/el-sca-ansamble/releases/tag/v2.0.0
