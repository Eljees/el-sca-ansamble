> [!WARNING]
> Snapshot of 2026-05-25 and is OUTDATED as a defect register: D1-D18 are closed (except D13),
> the suite has grown to ~673 tests. For current state see the latest NNN-analysis/NNN-fixups
> in docs/audit/ (now: 270-analysis-2026-06-11.md).

# Audit 2026-05-25 — Executive Summary

> Этот файл — точка входа в результаты независимого аудита репозитория
> `el-sca-ansamble` на коммите `7a04438` (ahead 1 от `origin/master`).
> Детали по категориям — в соседних файлах `10-defects.md`,
> `20-architecture.md`, `30-tests.md`, `40-tooling-docs.md`.

## 1. Контекст

Проект существенно зрелее снимка из `PLAN_2026-05-16.md`. Большая часть
блокирующих P0 закрыта (`reporting.build_report` корректен и доходит до
`output.write_text`, `Dockerfile.apk-analyzer` достроен, `docker-compose.yml`
имеет 19 сервисов и верхнеуровневые `volumes:`/`networks:`, `SCAN_TARGET_HOST`
fail-fast, `grype-static` имеет `healthcheck` и `depends_on`). CLI и все 15
модулей `resilient_updates` импортируются без ошибок; 19 shell-скриптов
проходят `bash -n`. CI workflow с lint + pytest и pre-commit конфиг
присутствуют. Это аудит зрелого проекта, а не спасательная итерация.

## 2. Сводная таблица находок

| Категория | Кол-во | Самое серьёзное |
|---|---|---|
| Реальные дефекты кода | 9 | NVD ключи в `.env` plaintext; `db_policy` параметр игнорируется; `proxy_chain` 4xx считается «ok» |
| Архитектурные пробелы | 7 | дубль `_sha256_file/_sha512_file` в трёх модулях; logging несистематический; нет корневого `MANIFEST.json` |
| Дыры в тестах | 6 | `extractor.py` (530 строк / 3 теста), `cli.py` (947 строк / 5 тестов), нет coverage gate, нет smoke-integration |
| Расхождения документации с кодом | 8 | `architecture.md` § 11 — 15 сервисов из 19; CLI команды `db-status/activate/seed/extract/render-flags/scanner-diff` не описаны |
| Tooling / workflow | 6 | нет `pre-commit run --all-files` job; нет `--cov-fail-under`; в CI не строится ни один Dockerfile; версии сканеров не централизованы |

## 3. Что НЕ является проблемой (закрыто между 16 и 25 мая)

- `reporting.build_report` собирается полностью (`reporting.py:328…536`).
- `Dockerfile.apk-analyzer` валиден (`pip install androguard`, `COPY analyze_apk.py`, `ENTRYPOINT`).
- `apk-analyzer` и `win-analyzer` присутствуют как compose-сервисы (профили `apk` и `win`).
- `docker-compose.yml` имеет верхнеуровневые `volumes:` (`trivy-cache`, `grype-db`, `grype-cache`, `cve-bin-tool-cache`, `internal-mirror-data`) и `networks: scanner-net`.
- `.env.example` больше не содержит дубль `HTTP_PROXY=`.
- `grype-static` healthcheck + `grype-scanner` `depends_on: { condition: service_healthy }`.
- `cve-bin-tool-scanner` SCAN_TARGET_HOST без silent default — fail-fast.
- `no-update-by-default` policy: updater-сервисы только в профиле `update`.
- Sidecar proxy chain (xray + tinyproxy) реализован, `proxy_chain.py` + CLI `proxy-status` + ADR-0002 написаны.
- ADR-каталог `docs/adr/0001-wrapper-first.md`, `0002-proxy-sidecar.md`.
- Линтеры подключены: `.ruff.toml`, `.hadolint.yaml`, `.yamllint`, `.pre-commit-config.yaml`, `PSScriptAnalyzerSettings.psd1`.
- `Makefile` и `requirements.in` присутствуют.

## 4. Топ-10 приоритетов на устранение

1. **NVD API-ключи в `.env`** в plaintext в Yandex Disk-папке. Файл синхронизируется в облако. Ротировать оба ключа и оставить значения только в `.env.local` ([10-defects.md §1](10-defects.md#1-секреты-в-env)).
2. ~~`db_policy` игнорируется~~ — **false positive**, перепроверка подтвердила, что `cli.py:384-395 → activate_best_cve_bin_tool_db → _policy_allows_status` работают корректно. Подробнее: [10-defects.md §2](10-defects.md#2-db_policy-игнорируется--false-positive-исключено-из-плана).
3. **`proxy_chain._probe_chain` 4xx как «ok»** — `response.status_code < 500` пропускает 404/403/401 как «здоровый» проксь ([10-defects.md §3](10-defects.md#3-proxychainprobechain-классифицирует-4xx-как-ok)).
4. **`fallback.py` `file://` на Windows** ломается: `urlparse("file:///C:/x").path` → `/C:/x`, `Path()` не принимает ([10-defects.md §4](10-defects.md#4-fallback-file-url-на-windows)).
5. **`configs/wireguard/` отсутствует** — `--profile vpn` падает на bind-mount ([10-defects.md §5](10-defects.md#5-нет-configswireguard)).
6. **Дубль `pip install cve-bin-tool==3.4`** поверх `requirements.txt` в `Dockerfile.cve-bin-tool` — конфликт версий ([10-defects.md §6](10-defects.md#6-дубль-cve-bin-tool-pinning)).
7. **`docs/architecture.md` § 11 и § 115** перечисляют 15 сервисов из 19 и 6 профилей из 12 ([40-tooling-docs.md §3](40-tooling-docs.md#3-расхождения-документации-и-compose)).
8. **`docs/status-and-roadmap.md` § 2f** утверждает, что `security-notes.md/windows-powershell.md/custom-sources.md` — заглушки. Они уже полноценные (107/177/174 строк) ([40-tooling-docs.md §4](40-tooling-docs.md#4-устаревшие-утверждения)).
9. **Нет `pytest --cov-fail-under`** в CI и нет покрытия для `extractor.py` (530 строк / 3 теста) ([30-tests.md §2](30-tests.md#2-распределение-покрытия)).
10. **Hash-утилиты дублируются** между `reporting.py`, `run_summary.py`, `extractor.py` ([20-architecture.md §1](20-architecture.md#1-дублирующиеся-утилиты)).

## 5. Поэтапный план фиксов

| Фаза | Что делается | Acceptance |
|---|---|---|
| **A** Hot-fix bundle | NVD-keys → `.env.local`; `git rm --cached` мусора; `db_policy` подключить; `< 500 → < 400` в proxy_chain; `file://` на Windows; убрать дубль pip cve-bin-tool; `configs/wireguard/.gitkeep` | `validate-config` ok; `proxy-status` ok; `compose --profile vpn config -q` ok |
| **B** DRY + поведенческие | `_io.py` (sha/json), `RetryPolicy` dataclass, `update_trivy.sh` массив FLAGS, `run_scan.sh` → exec wrapper, унификация env-vars | `pytest -q` зелёный |
| **C** Logging + manifest | `_logging.py` с JSON-режимом; `run_manifest.json` с `run_id` и ссылками; CLI `manifest` | `LOG_FORMAT=json` структурированно; `manifest` пишет всё в одном файле |
| **D** Тесты | покрытие `extractor`, `cli` subcommands, `atomic_publish` racing; `--cov-fail-under=75`; smoke-integration | CI зелёный с gate 75 % |
| **E** Документация | `architecture.md` таблицы по факту compose; описать недокументированные CLI; убрать ложь про заглушки; `docs/INDEX.md`; переименовать `DEPLOYMENT_GUIDE_FINAL.md` → `_EXAMPLE.md`; `CONTRIBUTING.md` + `SECURITY.md` | вся документация соответствует коду |
| **F** CI / tooling | `pre-commit run --all-files` job; `--cov-fail-under`; `docker-build` job; `requirements.lock`; `versions.env` | один источник правды для версий, билд в CI |

## 6. Дорожная карта улучшений (после фаз)

- **Качество данных**: VEX-фид (`configs/vex.yaml` → Trivy `--ignorefile`); EPSS/KEV cache+TTL; CycloneDX-совместимый `provenance.cdx.json`.
- **UX**: единый CLI `cli.py scan --target ...`; lightweight FastAPI-дашборд; baseline-каталог `artifacts/baselines/<case-id>/`; нотификации Slack/email по `policy_decision != pass`.
- **Архитектура**: профиль `offline-only` с golden-bundle DB; push-mode для cve-bin-tool internal mirror; target=`docker://registry/image:tag`; опциональный ClamAV pre-scan.
- **Сеть**: per-source proxy fallback (corp → via-vpn) на ошибке цепочки; `proxy-status --watch` для долгих runs; `wg0.conf.example`.
- **Windows**: вынести `artifacts/extracted/current` в named volume; калибровочная таблица `CVE_BIN_TOOL_PARALLEL` cores ↔ wall-clock; идемпотентный установщик Defender exclusions.
- **Релиз**: tag `v3.1.0` после фаз A–B; cosign-подпись и checksums в release-workflow.

## 7. Что важно знать на старте

- **Аудит сделан на стороне Linux-sandbox.** Файл `.git/index.lock`, упомянутый в `PLAN_2026-05-16.md` как блокер на Windows, в Linux-копии отсутствует. Если на Windows-хосте `git status` всё ещё падает с `fatal: unable to read…` — удалите `.git/index.lock` вручную.
- **Pytest в этом аудите не прогонялся** (нет доступа к PyPI из sandbox). Все Python-модули проходят `python -m compileall`, и CLI-команды `validate-config`/`healthcheck`/`proxy-status` работают.
- **Все `bash -n`** прошли для 19 shell-скриптов.
- **Полный список цитат с file:line** — в соответствующих файлах рядом.

---

**См. также:**
- [10-defects.md](10-defects.md) — конкретные баги с цитатами
- [20-architecture.md](20-architecture.md) — связность, абстракции, дубли
- [30-tests.md](30-tests.md) — карта покрытия и дыры
- [40-tooling-docs.md](40-tooling-docs.md) — CI, pre-commit, doc-гэпы, релиз
