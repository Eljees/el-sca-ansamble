# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
loosely adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **SBOM-поставки анализируются по содержимому** (`736939a`, CYBERSEC-13860):
  заказчик прислал два CycloneDX-документа вместо самих приложений. Syft мог
  сделать только то, что умеет, — каталогизировать zip с двумя `.json`, —
  Grype сматчил этот SBOM, и отчёт честно сообщил «ничего не найдено».
  В документах было 713 Maven-компонентов и 231 известная уязвимость,
  9 из них Critical (`tomcat-embed-core 9.0.83`, netty, spring-webflux, camel).
  Новый `resilient_updates/sbom_ingest.py` определяет CycloneDX / SPDX /
  Syft-документы **по содержимому** (по имени их не поймать), нормализует к
  CycloneDX и сливает с SBOM от Syft в `artifacts/sbom/scan-input.cdx.json`.
  Слияние, а не замена: поставка может содержать и SBOM, и бинарники. Дедуп
  по `purl`, иначе по `name@version`, поэтому повторный прогон стабилен и наш
  же вывод обратно не подмешивается. Сервис `sbom-ingest` объявлен
  `depends_on: service_completed_successfully` у `grype-scanner` — файл
  гарантированно существует при **любом** способе запуска, без правки шести
  рецептов; `cve-bin-tool` предпочитает его в auto-SBOM. Когда SBOM в
  поставке нет, файл равен обычному выводу Syft и поведение не меняется.
  Проверено через GUI: 2 SBOM → 701 компонент → 231 находка.

### Changed

- **Движки обновлены** (2026-08-10): Syft `v1.20.0`→`v1.50.0`, Grype
  `v0.112.0`→`v0.116.1`, Trivy `0.64.1`→`0.73.0`. Grype и Syft переехали с
  `ghcr.io` на Docker Hub: блобы ghcr редиректят на
  `pkg-containers.githubusercontent.com`, который корп-прокси пересобирает
  своим CA → `docker pull` падает с x509. Проверено на деплое: оба ghcr-тега
  **не тянутся**, идентичные образы с Docker Hub — тянутся. Пины по digest
  зафиксированы в коммите. ⚠️ Экосистему Trivy дважды компрометировали в
  марте 2026 (CVE-2026-33634): вредоносные `v0.69.4`, DockerHub-образы
  `v0.69.5`/`v0.69.6`, 76 из 77 тегов `trivy-action` и все теги `setup-trivy`.
  Наш прежний пин `0.64.1` старше инцидента — деплой не был затронут; `0.73.0`
  заведомо после ремедиации. Никогда не резолвить Trivy через
  `trivy-action`/`setup-trivy` и не переводить эти пины на `latest`. (`d438f7c`)

### Fixed

- **Апдейтер cve-bin-tool был мёртв с 1 августа, и это никто не видел.**
  Пересобранный `0.1.1` образ приехал без каталога `/opt/app/scripts`, а
  запечённый ENTRYPOINT на него ссылался → `cannot open
  /opt/app/scripts/update_cve_bin_tool.sh`, стадия падала за ~4 с с rc=2,
  а бочка продолжала показывать дату последнего удачного импорта. Апдейтер
  переведён на обёртку из примонтированного `/workspace` (сканер уже был
  так переведён) — фиксы обёртки теперь едут `git pull`, без пересборки.
  (`3222e59`)
- **Trivy 0.73.0 жёстко падал на Maven Central.** Без `--offline-scan` он
  резолвит родительские POM с `repo.maven.apache.org`; егресс проксирован,
  прокси отвечает `429`, Trivy эскалирует это в FATAL — стадия умирает,
  отчёт остаётся пустым. Флаг стоял только в режиме `offline`, а пайплайн
  ходит через `scan`. Поймано контрольным сканом сразу после апгрейда:
  находки по тому же артефакту ушли с 6 в **0**. (`d0f9ed1`)
- **Таймаут cve-bin-tool был рассчитан на другую эпоху.** 600 с в деплойном
  `.env` (и 1800 с дефолт) закладывались под побайтовое сканирование крупных
  Go-бинарей. С тех пор как вложенные архивы распаковываются полностью, одна
  поставка даёт SBOM на 25 637 компонентов (14 ГБ дерево, 27 МБ CycloneDX), и
  полукап по каждому компоненту вылетал за бюджет: стадия писала `timeout.flag`
  и **0** находок там, где раньше «находилось» 48. Дефолт поднят до 3600 с,
  документация, обещавшая 600 с, поправлена. (`cf62dbd`)
- **Провал стадии больше нельзя замаскировать нулём.**
  `run_summary._tool_failures` теперь ловит две новые ситуации: стадия с
  `status=error` в `pipeline_state.json` и отчёт инструмента **старше**
  extraction-манифеста прогона (протухший остаток). Именно эта комбинация
  (стадия упала + уцелел старый `[]`) месяц рисовала «0 находок, ошибок нет».
  (`df03ad1`)
- **volume-init никогда не работал.** Проверка «есть ли чужие владельцы»
  использовала GNU-синтаксис `find ! -uid 1001`, которого нет в busybox, а
  ошибка глушилась `2>/dev/null` — страж вечно рапортовал «ok», и root-овый
  `cve.db` после активации под root убивал appuser-сканер на открытии.
  Заменено на busybox-совместимое `! -user 1001`, stderr больше не глушится,
  и volinit гоняется не только перед обновлениями, но и перед сканами.
  (`df03ad1`)

  **Итог верификации** (CYBERSEC-13529, makarov-i-886188.gz, 3.4 ГБ →
  14 ГБ после распаковки): `status=done`, `tool_failures: none`, 27 мин.
  Syft **13 812** компонентов, Grype **1038**, Trivy **146**, cve-bin-tool
  **796** — итого **1980** находок (133 CRITICAL / 767 HIGH), политика честно
  говорит `fail: CRITICAL=133>0`. Для сравнения: прогон 26.07 по тому же
  файлу давал 76 / 7 / 6 / 48 — то есть до фикса вложенных архивов и до
  починки двух движков объект недосканировался на два порядка.

### Added

- **EPSS наконец работает** (2026-07-31): офлайн-доставка вместо дохлого CDN.
  Через корп-прокси epss.cyentia.com отдаёт ~450 Б/с (скачивание невозможно);
  с рабочей станции тот же CSV скачивается за 14 с. Схема: локально скачать
  `epss_scores-current.csv.gz` → доставить на сервер → положить распакованным
  в `cve-bin-tool-cache:/cve-bin-tool/epss/epss_scores-current.csv` **и** в
  `internal-mirror-data:/candidates/*/.cache/cve-bin-tool/epss/` (preseed-
  активация копирует каталог целиком и иначе стирает файл) → прогон
  `cve-bin-tool -u latest --disable-data-source "CURL,GAD,NVD,OSV,PURL2CPE,REDHAT,RSD"`.
  Свежий файл (<24 ч) парсится локально, сеть не нужна. Итог: **354 176
  EPSS-скоров в cve.db** (строка-в-строку с CSV от 30.07). Попутно два фикса:
  (1) `cve_bin_tool_3.4_fixups.py` — недоставало `_conn.commit()` после
  `update_epss()`: вставки уходили в rollback при `close()`, счётчик оставался
  0 (`822be59`); (2) `update_cve_bin_tool.sh` — сканы теперь с `--metrics`,
  иначе EPSS из базы не попадает в report.json (`d239319`). Проверено сканом:
  15/15 находок с `epss_probability`/`epss_percentile`. OSV/PURL2CPE/RSD
  остаются отключёнными (апстрим-баги 3.4 / sneakernet-источник).

- `scripts/register_local_artifact.sh` (new) + `docs/big-artifacts.md` (new):
  штатный маршрут для гигабайтных артефактов — доставка на сервер (rsync с
  `--partial --append-verify` / WinSCP / scp), регистрация в каталоге без
  HTTP-загрузки (hardlink в `artifacts/uploads/`, метаданные 1-в-1 как у
  `create_upload` → полноценная карточка), опциональный автозапуск скана
  (`-s`). Гайд включает настройку WinSCP (приватный ключ → `.ppk`, туннель
  только для запасного маршрута) и ручной fallback без скрипта. Проверено на
  3.4 ГБ (CYBERSEC-13529): доставка 5:27 @ ~10 МБ/с, скан ~4 мин, sha256
  сошлись на всех трёх точках (источник → сервер → отчёт).

### Fixed

- **Не-ASCII имена файлов больше не стираются целиком** (`61d5a35`,
  CYBERSEC-12318): `_safe_filename` заменял каждый не-ASCII символ на `-`, а
  затем `.strip(".-")` уносил эти дефисы **вместе с точкой** — от кириллического
  имени оставалось одно расширение. Поставка на 1.3 ГБ «Сборки на проверку
  ИБ.zip» сохранилась как файл `zip`, run-директория стала
  `zip-20260810-124849`, и в отчёте объект назывался `zip`. Распаковка при
  этом работала (тип определяется по содержимому), поэтому баг был тихий: он
  стоил не находок, а идентификации — ровно того, ради чего отчёт и нужен.
  Теперь кириллица транслитерируется (`Sborki-na-proverku-IB.zip`),
  расширение санитизируется отдельно и всегда выживает, path traversal
  по-прежнему режется. Оригинальное имя в метаданных карточки сохраняется как
  есть.

- **Сага «cve-bin-tool: 0 находок» (2026-07-26, четыре бага одним копом):**
  стадия cve-bin-tool молча падала с ~20.07, а отчёт показывал «0 findings,
  tool failures: none» с протухшего `[]`-плейсхолдера. Цепочка: (1) активация
  БД под root оставила `cve.db` root-овым — appuser-сканер умирал на открытии;
  (2) страж volume-init не лечил это, т.к. busybox-find не знает GNU `-uid`,
  а ошибка глоталась `2>/dev/null` → чекер вечно рапортовал «ok» — теперь
  `! -user 1001` и stderr не глушится (`df03ad1`); (3) volinit гонялся только
  перед обновлениями — теперь и перед сканами (самолечение, `df03ad1`);
  (4) pre-scan аудит БД убивал скан безмолвно (`set -e` + stdout в /dev/null):
  stale-вердикт (rc=4) при `CVE_BIN_TOOL_DB_POLICY=degraded-ok` теперь
  громкий WARN + скан продолжается, прочие коды — внятный FATAL; попутно
  исправлен POSIX-захват rc (`$?` после `if !` инвертирован) и
  `CVE_BIN_TOOL_VERIFY_DB` добавлен в whitelist compose (`07c4039`,
  `2ed5e8d`). Entrypoint сканера переведён на обёртку из **workspace** —
  фиксы едут git pull'ом без ребилда образа. `run_summary._tool_failures`
  теперь ловит стадию-error из `pipeline_state.json` и отчёты старше
  extraction-манифеста — маскировка «нулём» невозможна (`df03ad1`).
  Верификация: CYBERSEC-13529 (3.4 ГБ) → **cve-bin-tool: 48 находок**
  (ansible 2.10.4 и др.), итог 61 finding, policy fail CRITICAL=1.

- Экстрактор: одиночный не-архивный вход (Windows `.exe`/`.msi` инсталлятор,
  бинарь, обычный файл) больше не помечает стадию Extract как `error`. Раньше
  `_archive_kind()` возвращал None → 0 извлечённых → `cli extract` отдавал
  `EXIT_VALIDATION_FAILED (3)` → оркестратор красил стадию красным, хотя все
  сканеры и отчёт завершались (CYBERSEC-13388: avandoc `.exe`). Теперь такой
  вход — благонадёжный passthrough: `manifest.status="pass"`,
  `input_was_archive=False`, `passthrough_count=1`, exit 0. Распознанный, но
  битый/пустой архив по-прежнему остаётся failure. Тесты:
  `test_extract_artifacts_marks_non_archive_file_as_passthrough`,
  `test_extract_cli_passes_when_file_input_is_non_archive`.
- GUI-оркестратор: сканирование Windows-инсталлятора (`.exe`/`.msi`) больше не
  даёт 0 компонентов. Раньше дашборд гонял общий пайплайн (extract → syft по
  сырому файлу), а NSIS/Inno/MSI generic-экстрактор не вскрывает → syft
  каталогизировал 0 компонентов (CYBERSEC-13388: avandoc `.exe`). Теперь
  `orchestrator.py` повторяет ветку `run-scan.sh FORMAT==win`: детектит
  инсталлятор (`is_windows_installer_target`), выбирает `SCAN_STAGES_WIN`
  (стадия **Win-analyzer · SBOM** вместо **SBOM · Syft**), запускает
  `win-analyzer` (7z/innoextract/msiextract + pefile) → PE-SBOM в
  `artifacts/sbom/syft.json`; grype читает этот SBOM, cve-bin-tool сканит
  `extracted/win-installer`. Тесты: `tests/test_win_installer_pipeline.py`.
- Каталог артефактов: повторные сканы одного файла больше не плодят карточки-клоны
  в GUI. `ArtifactCatalog._legacy_artifacts` группирует прогоны `_SCA_reports/`
  по артефакту (ключ = sha256 входа, fallback — имя+case_id): один артефакт →
  одна карточка с историей прогонов (`runs[]`, новейший = `latest_run_id`).
  Раньше каждый `_SCA_reports/<target>-<ts>/` становился отдельной
  `legacy-<run_id>` записью → N сканов avandoc.exe = N дублей. Тест:
  `test_catalog_dedups_repeated_scans_of_same_artifact`.
- GUI «Карта анализа»: для Windows-инсталлятора узел SBOM показывает
  **Win-analyzer** вместо серого «Syft». `renderMap()` жёстко рисовал
  `mapNode("sbom","Syft")`, а в win-режиме стадия называется `win-analyzer` →
  ключа `sbom` нет → узел висел серым pending, хотя SBOM реально построен
  (3 компонента). Теперь узел выбирается по наличию стадии `win-analyzer`.
- Активация БД на ноде упиралась в `No space left on device`: `activate_best_cve_bin_tool_db`
  делает `shutil.copytree(candidate → tmp)` и затем публикует в active — файловые
  источники OSV/RSD (~760k мелких JSON) существуют в ТРЁХ копиях на пике, что
  переполняет 62 ГБ корень. Обход применён вручную (убрать OSV/RSD из кандидата →
  активировать компактную базу NVD+GAD+REDHAT+EPSS+PURL2CPE = 5/8). TODO в коде:
  заменить copytree файловых источников на `os.replace`/hardlink, чтобы снять
  тройное дублирование (тогда OSV/RSD активируются даже на тесном диске).
- Дашборд-контейнер (`el-sca-resilient-updater` образ) крутит код ИЗ ОБРАЗА, поэтому
  фикс мини-бочек (`source_status`) не подхватывался. Временный обход на ноде:
  bind-mount `./resilient_updates:/opt/app/resilient_updates:ro` + rw-подкаталог
  `./artifacts/logs` (иначе падал `Read-only file system: dashboard.log`) в
  `dashboard`-сервисе. Правильное решение — пересобрать образ; отражено в
  `docs/db-update-manual-ru.md`. Внешний доступ 8088→контейнер:8080 держится
  через `socat` (на ноде порт-маппинг только `127.0.0.1:8080`).
- `scripts/sneakernet_build.sh`: CURL возвращён в сборку (best-effort, не фатально
  при rc=33) — он крошечный (~200 строк про curl) и на проксируемом egress ноды
  работает. Точечно доадить CURL к готовой базе нельзя: `cve-bin-tool --update`
  не аддитивен (пересоздаёт БД, одиночный CURL → `CVEDataMissing` → откат).
- GUI мини-бочки cve-bin-tool: OSV/EPSS/PURL2CPE/RSD красились по строкам
  `cve_range_by_source`, но это файловые источники (строк в cve.db не пишут) →
  вечно 0%/красные даже при наличии данных. Теперь `tool_status` берёт их
  заполненность из `source_status` аудита (файлы в db_root), fallback на строки
  для NVD/GAD/REDHAT/CURL. Аудит PURL2CPE считает и standalone-файл
  `purl2cpe/purl2cpe.db`, а не только встроенную таблицу. Тесты:
  `tests/test_dashboard_source_barrels.py`.
- EPSS-сид: хост `epss.cyentia.com` мёртв (Cyentia → Empirical Security),
  сидер качает с `epss.empiricalsecurity.com`, cyentia остался фоллбеком
  (`cve_db_audit.seed_cve_bin_tool_aux_sources`). (`d3d7829`)
- Sneakernet-обновление баз cve-bin-tool через Windows-хост: нода 10.2.108.47
  не достаёт OSV/EPSS/PURL2CPE/RSD (egress-контур режет googleapis, first.org
  и github.com — проверено пробами). Новые `scripts/sneakernet_build.sh`
  (посточниковая сборка в изолированных HOME + sqlite-мерж — обход зависания
  мультиисточникового `--update now` cve-bin-tool 3.4 на быстрой сети),
  `scripts/sneakernet_export.ps1` (scp + импорт), `scripts/sneakernet_node_import.sh`
  (распаковка в candidate root + штатные audit/activate). Runbook уровня
  «промпт для ассистента»: `docs/db-sneakernet-ru.md`.

### Added

- `resilient_updates/artifact_catalog.py`: новый модуль — каталог run-артефактов
  с индексацией по дате, инструменту и case_id; Dashboard GET `/api/artifacts` и
  GET `/api/artifacts/{run_id}/report` отдают список и HTML-отчёт. (`27d002b`)
- `resilient_updates/s3_publish.py`: публикация snapshot run-директории на
  stack-local SeaweedFS/S3 через `s3-client` compose-сервис; `make s3-push` /
  `make s3-list`; `docs/s3-storage.md` описывает layout и bucket-политику. (`f157b6c`)
- `docs/operator-quickstart-ru.md`: пошаговый русскоязычный гайд оператора —
  GitHub/GitLab clone → GUI → DB update → scan → S3 publish → log review. (`a5e19ae`)
- `configs/seaweedfs/s3.json`: Filer config для SeaweedFS S3-gateway. (`f157b6c`)
- `AGENTS.md`: зафиксированы команды проверки, cleanup policy для runtime
  артефактов и правило держать GitHub/GitLab sync отдельным проходом.

### Changed

- `dashboard.py` (`tool_status`) + GUI: карточки БД отдают `db_updated_kind`
  (`built` | `imported` | `null`). Grype/Trivy показывают дату сборки базы
  апстримом, cve-bin-tool — время нашего импорта (у NVD JSON-фидов нет даты
  сборки). Бочка подписывает это как `· сборка` / `· импорт` + тултип, чтобы
  разные по смыслу даты не выглядели одинаково. (аудит-fixup 2026-07-09)
- `monitor.py` / dashboard GUI: `GET /api/monitor` теперь включает
  `latest_run`, а панель «Монитор · контейнеры и прогресс» показывает
  последний сохранённый snapshot/checkpoint текущего контура.
- `orchestrator.py`: периодический checkpoint dashboard/host scan больше не
  ограничивается записью `checkpoint.json`; теперь он сохраняет реальный
  per-run snapshot evidence через `snapshot_artifacts()`.
- `reporting.py` / `run_summary.py`: итоговый отчёт сохраняет сырые счётчики
  severity по каждому сканеру (`severity_totals_raw`) и top-level `input_hash` —
  diff-сессии больше не теряют контекст при агрегации. (`1e57b22`)
- `orchestrator.py` / `run_layout.py` / `cli.py` / `dashboard.py`: scan-run
  публикует snapshot (SBOM + отчёты + провенанс) в `artifacts/runs/<RUN_ID>/`
  после завершения; `snapshot_artifacts()` вызывается как из checkpoint, так и
  при штатном завершении. (`a5e19ae`)
- `resilient_updates/dashboard.py`: UI обогащён вкладкой Artifact Catalog —
  список run-ов с фильтром по сканеру и case_id, просмотр HTML-отчётов. (`27d002b`)
- `scripts/run-scan.sh` / `scripts/windows/run-scan.ps1`: интеграция с
  `s3_publish.py` — при `EL_SCA_S3_PUSH=1` snapshot публикуется в S3 после скана.
  (`a5e19ae`)
- `docs/INDEX.md`, `docs/audit/00-overview.md`, `docs/audit/30-tests.md`,
  `docs/architecture.md`, `docs/operations.md`: актуализированы текущие
  указатели, test-count и описания snapshot/monitor/CI overlay behaviour.

### Changed (perf)

- `orchestrator.py` (`_copy_input_to_run`): входной артефакт ≥ 512 МиБ больше
  не копируется в `_SCA_reports/<run>/input/`, а **хардлинкуется** (та же ФС →
  0 лишних байт; inode переживает purge каталожной копии, evidence целы).
  Мелкие файлы — копия как раньше; cross-device — автоматический фолбэк на
  копию; resume не перекопирует уже лежащий снапшот. Мотивация: артефакты по
  3.5 ГБ удваивали место на каждый прогон. (`ccc9a87`)

### Fixed

- `orchestrator.py` / `extractor.py` / `run_summary.py` / `reporting.py` /
  `_io.py` / `scripts/report_html.py` / `dashboard.py`: итоговый отчёт (веб-обзор
  и `.md`) теперь называет **сканируемый объект** и все его хэши. Раньше шапка
  показывала заглушку `Target: /absolute/path/to/artifact-or-directory` и
  `UNKNOWN` в хэшах — dashboard-скан не выставлял `SCAN_TARGET_DISPLAY` (оставался
  дефолт из `.env`), а хэш финальной цели считался от несуществующего пути;
  `Input SHA-1` терялся, т.к. `run_summary` перехэшировал контейнерный путь,
  которого нет на хосте. Теперь: orchestrator проставляет `SCAN_TARGET_DISPLAY`
  = имя загруженного архива и `CASE_ID` = CYBERSEC-id (перекрывая плейсхолдер);
  extractor пишет `md5+sha1+sha256` архива в манифест одним проходом;
  `run_summary.derive` добавляет `target_hashes` (хэш дерева `extracted/current`)
  в `summary.json` / `run_manifest.json`; HTML и Markdown рендерят **MD5 + SHA-1
  + SHA-256** и для входного архива, и для финальной цели; кнопка Reports
  открывает **самый свежий** ран артефакта. Проверено живым сканом на
  развёртке (`SCAgent_Linux_12_5_1.zip` → имя + 6 хэшей, без `UNKNOWN`).
  (`c2a92c6`)
- `scripts/patches/cve_bin_tool_3.4_fixups.py` (new) + `Dockerfile.cve-bin-tool`:
  патч **двух** апстрим-багов EPSS в cve-bin-tool 3.4 (3.4 — последняя версия на
  PyPI, бампнуть не на что). (1) `Epss_Source.get_cve_data()` звал
  `update_epss()` без обязательного `cursor` → `TypeError`. (2) Порядок:
  `cvedb.get_data` собирает источники раньше, чем `populate_metrics` вставляет
  строку `(1,"EPSS")`, поэтому `EPSS_id_finder` читает пустую `metrics` и падает
  `IndexError`. Оба глушились в «Unable to fetch EPSS». Патч даёт курсор к cve.db
  и гарантирует строку `(1,'EPSS')` **той же константой апстрима**, дальше
  работает родной `store_epss_data`. Идемпотентен и самопроверяется (сборка
  падает, если код сместился); применение проверено: `patched` → import OK →
  повтор `already-patched`.
  ⚠️ На развёртке EPSS **пока не наполняется** и остаётся в
  `CVE_BIN_TOOL_ENRICH_DISABLE`: сам CDN EPSS (`epss.cyentia.com` →
  `empiricalsecurity.com`) в контуре зверски throttled — прямой `curl` через
  корп-прокси даёт ~450 Б/с (15 981 байт за 35 c, затем таймаут), и загрузка не
  завершается. Патч чинит *ингест*; чтобы источник заработал, CSV нужно
  доставить офлайн (та же схема, что и S3-доставка баз). OSV (память) и PURL2CPE
  (баг в core-store `cvedb.py`) тоже остаются отключёнными. (аудит-fixup 2026-07-16)
- `.dockerignore`: добавлен (его не было вовсе). Без него build-контекст на
  реальной развёртке — около 7 ГБ (`bundle/` ~4.3 ГБ, `artifacts/` ~1.9 ГБ,
  `_SCA_reports/` ~0.6 ГБ) и в демон уезжал локальный `.env`. Dockerfile'ы
  копируют только `requirements.txt`, `resilient_updates/`, `scripts/` и
  корневые `*.tar.gz`. После правки контекст — **880 КБ**, сборка проверена.
  (аудит-fixup 2026-07-09)
- `versions.env` / `docker-compose.yml` / `.env.example`: `SEAWEEDFS_VERSION` и
  `MINIO_MC_VERSION` запиннены (`4.38`, `RELEASE.2025-08-13T08-35-41Z`) — раньше
  их не было в `versions.env` вовсе, и оба уходили в `latest`, из-за чего
  storage-слой молча дрейфовал (уехал на SeaweedFS 4.x с новой STS-подсистемой).
  Проверено: статические identities из `configs/seaweedfs/s3.json` работают,
  анонимный доступ отбивается `403`; лог `Failed to load IAM configuration:
  no signing key found for STS service` безобиден. (аудит-fixup 2026-07-09)
- `dashboard.py` (`tool_status`): счётчики cve-bin-tool по источникам теперь
  сопоставляются регистронезависимо. `cve_bin_tool/data_sources/curl_source.py`
  пишет в `cve.db` источник как `Curl`, а дашборд искал ключ `CURL` — бочка
  Curl показывала 0% даже при импортированных строках (проверено на
  развёртке: `cve_range` = `Curl 206`, `GAD 73324`, `REDHAT 296836`).
  Добавлен регрессионный тест. (аудит-fixup 2026-07-09)
- `.env.example` / `scripts/update_cve_bin_tool.sh`:
  `CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS` приведён к `1800` — согласован с
  рантайм-дефолтом в `scripts/run-scan.sh`, `scripts/windows/run-scan.ps1` и
  fallback в `docker-compose.yml` (раньше документированный дефолт был `600`,
  что расходилось с реальным поведением). (аудит-fixup 2026-07-09)
- `cve_db_audit.py`: извлечён `_is_windows() -> bool` хелпер; тест
  `test_activate_best_windows_permission_error_uses_fallback` патчит его вместо
  `os.name` глобально. Исправляет `INTERNALERROR` в pytest на Linux
  (CI ubuntu-latest), присутствовавший с `2d801a0` (2026-06-20). (`38c04dd`)
- `extractor.py`: `extract_artifacts` падал с непойманным `ValueError` при
  входе-директории, содержащей архив с вложенными архивами — rel-путь
  вложенного архива (он находится в ВЫХОДНОМ дереве) вычислялся относительно
  input-директории; extract-стадия обрывалась целиком, манифест не писался
  (воспроизводилось на `_SCA/CYBERSEC-12172`). rel теперь считается
  относительно фактического корня (input или output). Регрессионный тест:
  `test_extract_artifacts_directory_input_with_nested_archives`. (этот коммит)

### Documentation

- `00_PROJECT_CONTEXT.md`: переведён из untracked-черновика в отслеживаемый
  onboarding-док для агентов — версии, карта модулей, поведение
  provenance/дашборда, живая развёртка `10.2.108.47` (доступ, egress,
  `.env`-дельты), carry-forward. `AGENTS.md` теперь ссылается на него как на
  точку входа. (аудит-fixup 2026-07-09)
- `PROJECT_OVERVIEW.md`: новый обзор проекта (версии, фичи, известные баги,
  roadmap) для публикации на GitHub и GitLab. (аудит-fixup 2026-07-09)
- `CONTRIBUTING.md`: добавлена секция "Known dev-environment gotchas" —
  описание FUSE/stale-mount проблемы (mtime не обновляется через FUSE,
  Python грузит stale `.pyc`) и три варианта обхода. (FUSE-DOCS)
- `docs/INDEX.md`: удалены 4 битые ссылки на архивные файлы
  (`audit/350/310/270/240-analysis-*.md` были в `archive/`, INDEX указывал
  на несуществующие пути); нумерация скорректирована.
- `docs/audit/`: 10 файлов серии 400–490 (2026-06-20 – 2026-06-26) перемещены
  в `docs/audit/archive/` (AUDIT-ARCHIVE).
- `docker-compose.yml` `dashboard`: смонтирован `./configs:/workspace/configs:ro` —
  контейнер падал с `FileNotFoundError: configs/feed_sources.yaml`, потому что
  `cli.py` грузит конфиг безусловно, а в `/workspace` монтировался только
  `artifacts/`. (этот коммит)
- `docker-compose.yml` `dashboard`: host-порт параметризован —
  `127.0.0.1:${DASHBOARD_PORT:-8080}:8080` (на хостах, где 8080 занят, задаётся
  `DASHBOARD_PORT` в `.env`). (этот коммит)

### Removed

- SCRIPTS-CLEANUP (аудит 520 §5, подтверждено 2026-07-02): удалены one-off
  скрипты `scripts/reproduce-cybersec-11531.sh`,
  `scripts/windows/reproduce-cybersec-11531.ps1`, `scripts/windows/commit-fixes.ps1`,
  `scripts/windows/extract-projects.ps1`, `scripts/update_grype.sh` (thin shim,
  не используется compose). `docs/reproducibility.md` переведён на штатный
  `run-scan.{sh,ps1}`; `scripts/README.md` обновлён. (этот коммит)

### Refactored

- `cli.py` `_health_summary`: принимает `retry: RetryPolicy` вместо четырёх отдельных
  параметров (`retry_count`, `backoff_seconds`, `retry_codes`, `non_retryable_reasons`).
  Аналогично закрытому A_OBS-1 (`_probe_layer`). (`6202c1f`)

### Tests

- `tests/test_io.py`: `normalize_severity` теперь импортирована и покрыта тестами — 5 новых
  параметрических кейсов (uppercase passthrough, `None`/`""`/`0`/truthy-int → `"UNKNOWN"`). (`85743ff`)

### Changed

- `versions.env`: обновлён комментарий к CI — lint-versions уже реализован в CI начиная
  с `12395c9`. (`6202c1f`)
- `.gitlab-ci.yml`: добавлен job `lint-versions` (паритет с GitHub Actions). (`6202c1f`)
- `docs/architecture.md`: добавлен раздел CI/CD (12 jobs, 3 stages: lint/build/test);
  обновлена таблица модулей — `cli.py` (`_probe_layer`, A_OBS-1) и `healthcheck.py`
  (`_health_summary`, A_OBS-2) принимают `RetryPolicy` напрямую. (`8358aa1`)

## [0.1.5] - 2026-06-24

### Fixed

- `RetryPolicy`: добавлено поле `non_retryable_reasons: frozenset[str]` и константа
  `DEFAULT_NON_RETRYABLE_REASONS`; `as_attempt_kwargs()` теперь включает это поле —
  `attempt_sources(**policy.as_attempt_kwargs())` передаёт единую политику без дублирования.
  `_NON_RETRYABLE_REASONS` в `fallback.py` сохранён как backward-compatible fallback.
  (`bd27371`)
- `attempt_sources`: добавлен параметр `non_retryable_reasons: frozenset[str] | None = None`,
  позволяющий переопределить список неповторяемых причин без правки модуля fallback. (`bd27371`)
- `vex.py`: `fetch_vex` использует `**retry.as_attempt_kwargs()` вместо ручного
  перечисления полей — `non_retryable_reasons` передаётся автоматически. (этот коммит)
- `cli.py` / `healthcheck.py`: `_health_summary` и `_probe_layer` получили параметр
  `non_retryable_reasons` и передают его в `attempt_sources`; все вызовы обновлены. (этот коммит)
- `cli.py` `update_grype`: передаёт `non_retryable_reasons=grype_retry.non_retryable_reasons`
  в `attempt_sources`. (этот коммит)
- `healthcheck._probe_layer`: принимает `retry: RetryPolicy` вместо четырёх
  отдельных параметров (`retry_count`, `backoff_seconds`, `retry_status_codes`,
  `non_retryable_reasons`). Callers в `run_healthcheck` упрощены: trivy и grype
  теперь передают единый объект; cve-bin-tool строит `RetryPolicy` с переопределённым
  `retry_count` из `source_health_policy`. (этот коммит, A_OBS-1)

### Tests

- `test_retry_policy.py`: +3 теста (`default_matches_fallback_constant`,
  `custom_survives_round_trip`, `yaml_does_not_read_non_retryable_reasons`). (`bd27371`)
- `test_fallback_core.py`: +3 теста (`custom_stops_retry`, `empty_allows_retry`,
  `none_falls_back_to_module_default`). (`bd27371`)
- `test_docker_mcp_server.py`: +3 теста платформенных путей `run_scan_async`
  (win32 PS1 args, win32 all optional flags, linux bash args). (`f3dc338`)
- `test_cve_db_audit.py`: +5 тестов Windows atomic rename — happy path (`os.replace`
  вызван, `copytree` нет), EXDEV → copytree fallback, rollback active при сбое promotion,
  нет active → staging промотируется чисто, PermissionError → _win_activate_fallback. (`2d801a0`)
- `tests/pester/Import-RoutePlan.Tests.ps1`: +10 Pester-тестов для PowerShell-функции
  `Import-RoutePlan` — no-op при уже установленном прокси, отсутствие `route-plan.env`
  без ошибки, загрузка HTTP_PROXY/ALL_PROXY/multi-var/comments/`=` в значении,
  `-RunDoctor` (missing/fresh/stale/без флага). (`2d801a0`)

### Fixed (continued)

- `cve_db_audit._win_activate_fallback`: атомарное переключение активной DB на Windows
  через `os.replace` (`MoveFileExW`) — устраняет окно отсутствия `active/` при ротации
  базы. Fallback на `shutil.copytree`+`rmtree` только при `OSError`/`EXDEV`
  (cross-device). (`2d801a0`)

### Changed

- `docker-compose.yml`: все 12 образов `elariaphd/el-sca-*` переведены с захардкоженного
  `:0.1.1` на `${EL_SCA_VERSION:-0.1.4}` — `docker compose --env-file versions.env` теперь
  автоматически подхватывает актуальную версию; деплой устаревшего образа невозможен. (`816fb45`)

## [0.1.4] - 2026-06-17

### Fixed

- `route_plan.render_env`: не выставляет `HTTP_PROXY`/`HTTPS_PROXY` когда trivy/grype
  работают через SOCKS-only маршрут. Ранее HTTP-маршрут cve-bin-tool проникал в глобальные
  `HTTP_PROXY`/`HTTPS_PROXY`, а Go's `net/http` отдаёт предпочтение `HTTPS_PROXY` над
  `ALL_PROXY` — grype/trivy пытались HTTP CONNECT на SOCKS5-порт и завершались с ошибкой
  даже при корректном `ALL_PROXY`. (`d4065cd`)
- `orchestrator._run_scan` / `orchestrator.start_update`: добавлен `_load_dotenv` — читает
  `.env` файл в окружение оркестратора. Без этого прокси, заданный только в `.env`, не
  попадал в auto-route логику и игнорировался при запуске из GUI / MCP. (`d4065cd`)
- `orchestrator._extract_produced_output`: удалён лишний `import json` внутри метода
  (F811 — `json` уже импортирован на уровне модуля в строке 23). (этот коммит)
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
- `run-scan.sh`: cve-bin-tool стадия больше НЕ роняет весь скан — добавлен
  `run_stage_soft` (при провале offline-скана / нераспознанной feed-собранной
  cve.db пишется предупреждение и пайплайн продолжается к отчёту grype/trivy).
  Жёсткий режим возвращается через `EL_SCA_CVEBT_REQUIRED=1`. Раньше
  `cve_bin_tool - Database does not exist` (exit 40) блокировал весь отчёт.
- `docker-compose.yml` (cve-bin-tool-scanner): закреплён `HOME=/home/appuser` +
  `XDG_CACHE_HOME`. Контейнер шёл как root (HOME=/root), а cve-bin-tool ищет БД в
  `$HOME/.cache/cve-bin-tool/cve.db`, тогда как том с базой смонтирован в
  `/home/appuser/.cache` → сканер падал `Database does not exist` (exit 40) при
  ЖИВОЙ, наполненной cve.db. Теперь offline-скан находит базу. (Корневой фикс к
  предыдущему пункту про run_stage_soft.)

### Added

- Тесты для колонки «Fixed in» в `reporting.py`: `test_grype_findings_extracts_fix_versions`,
  `test_trivy_findings_extracts_fixed_version`, `test_cve_bin_tool_findings_fixed`,
  `test_markdown_table_renders_fixed_in_column` и сопутствующие (N6-2). (этот коммит)

### Changed

- Отчёт (`reporting.py`): в таблицу High/Critical-находок добавлена колонка
  **«Fixed in»** (исправленная версия пакета) — из grype `fix.versions` и trivy
  `FixedVersion`. Теперь видно не только уязвимую версию, но и в какой версии
  уязвимость устранена (по аналогии с таблицами в задачах CYBERSEC). (`2bf9fea`)

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

[Unreleased]: https://github.com/Eljees/el-sca-ansamble/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/Eljees/el-sca-ansamble/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/Eljees/el-sca-ansamble/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Eljees/el-sca-ansamble/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Eljees/el-sca-ansamble/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Eljees/el-sca-ansamble/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Eljees/el-sca-ansamble/releases/tag/v0.1.0
[3.0.0]: https://github.com/Eljees/el-sca-ansamble/releases/tag/v3.0.0
[2.0.0]: https://github.com/Eljees/el-sca-ansamble/releases/tag/v2.0.0
