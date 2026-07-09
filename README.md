# Resilient Scanner Stack

Этот репозиторий содержит контейнерный SCA-комплекс для `Trivy`, `Grype`, `Syft` и `cve-bin-tool`.

`SCA` означает `Software Composition Analysis`, то есть анализ состава ПО и поиск известных уязвимостей в бинарях, пакетах и зависимостях.  
`Wrapper-first` означает, что логика отказоустойчивости и orchestration вынесена во внешние скрипты и Python-модули, а не реализована форком upstream-инструментов.  
`Provenance` означает машинно-читаемую фиксацию происхождения результата: какие источники обновления были опрошены, какой источник выбран, какие ошибки были до fallback.

**Версия проекта:** см. `EL_SCA_VERSION` в [`versions.env`](versions.env). Полный список изменений — в [`CHANGELOG.md`](CHANGELOG.md); порядок выпуска и чек-лист перед пушем — в [`docs/RELEASING.md`](docs/RELEASING.md).

## Документация

Точки входа, по возрастанию глубины:

| Документ | Зачем |
|---|---|
| [`START_HERE.md`](START_HERE.md) | Развернуть с нуля на чистой машине (Windows/Linux) |
| [`QUICK_START.md`](QUICK_START.md) | Первый скан за 5 минут |
| [`PROJECT_OVERVIEW.md`](PROJECT_OVERVIEW.md) | Версии, фичи, известные баги, roadmap |
| [`00_PROJECT_CONTEXT.md`](00_PROJECT_CONTEXT.md) | **Onboarding для агентов и инженеров**: карта модулей, поведение provenance, живая развёртка, egress-контур |
| [`AGENTS.md`](AGENTS.md) | Правила для coding-агентов в этом репозитории |
| [`docs/INDEX.md`](docs/INDEX.md) | Полный сайтмап документации |

Эксплуатация и устройство:

- [`docs/architecture.md`](docs/architecture.md) — сервисы и модули · [`docs/adr/`](docs/adr/) — архитектурные решения
- [`docs/operations.md`](docs/operations.md) — справочник команд · [`docs/operations-guide.md`](docs/operations-guide.md) — разбор по шагам
- [`docs/operator-quickstart-ru.md`](docs/operator-quickstart-ru.md) — путь оператора: GUI → обновление баз → скан → отчёт
- [`docs/runbook.md`](docs/runbook.md) — траблшутинг · [`docs/failure-modes.md`](docs/failure-modes.md) — классификация отказов
- [`docs/proxy.md`](docs/proxy.md) и [`docs/network-design.md`](docs/network-design.md) — прокси, VPN, авто-маршрут
- [`docs/s3-storage.md`](docs/s3-storage.md) — внутренний S3 (SeaweedFS) · [`docs/airgap.md`](docs/airgap.md) — работа без сети
- [`docs/distribution.md`](docs/distribution.md) и [`docs/SHIP_AND_DEPLOY.md`](docs/SHIP_AND_DEPLOY.md) — сборка и передача бандла
- [`docs/reproducibility.md`](docs/reproducibility.md) — контракт воспроизводимости
- [`SECURITY.md`](SECURITY.md) и [`docs/security-notes.md`](docs/security-notes.md) — модель угроз и заметки
- [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`docs/RELEASING.md`](docs/RELEASING.md) · [`CHANGELOG.md`](CHANGELOG.md)
- [`docs/audit/660-analysis-2026-07-09.md`](docs/audit/660-analysis-2026-07-09.md) — последний аудит

## Что нового (2026-07-09)

- **Trivy снова обновляется.** База тянется с `mirror.gcr.io` (собственный дефолт
  upstream), потому что блобы `ghcr.io` уходят на `pkg-containers.githubusercontent.com`,
  который корпоративные TLS-инспектирующие прокси пересобирают своим CA —
  и Trivy падал с `x509: certificate signed by unknown authority`.
  `ghcr.io` и `public.ecr.aws` остались запасными.
- **Даты баз больше не врут.** Каждая карточка отдаёт `db_updated_kind`:
  Grype и Trivy показывают дату **сборки базы апстримом**, cve-bin-tool —
  время **нашего импорта** (у NVD JSON-фидов даты сборки нет). В GUI это
  подписано как `· сборка` / `· импорт`.
- **Отчёт в один клик.** `/runs` группирует прогоны по датам, у каждого — ссылка
  `report.md`; новый эндпоинт `GET /api/runs/{run_id}/report.md` отдаёт итоговый
  Markdown инлайном (`text/markdown`) для копирования и передачи.
- **Удаление артефакта из хранилища.** Кнопка «🗑 Удалить навсегда» с тремя
  подтверждениями; сервер дополнительно требует `?confirm=<artifact_id>`.
  `legacy-*` артефакты (представления сохранённых прогонов) удалять запрещено —
  это evidence.
- **Тема Phosphor CRT.** Зелёный фосфорный монохром, моношрифт, сканлайны.
  Бочки с мутагеном остались кислотно-зелёными.
- **Пины и контекст сборки.** `SEAWEEDFS_VERSION` / `MINIO_MC_VERSION` переехали
  в [`versions.env`](versions.env) (были незапиннеными `latest`), появился
  [`.dockerignore`](.dockerignore) — build-контекст ужался с ~7 ГБ до 880 КБ.
- **cve-bin-tool: источники.** NVD + GAD + REDHAT + Curl наполняются;
  OSV, EPSS и PURL2CPE помечены недоступными в этом контуре
  (`CVE_BIN_TOOL_ENRICH_DISABLE`) из-за апстрим-багов 3.4 — подробности в
  [`00_PROJECT_CONTEXT.md`](00_PROJECT_CONTEXT.md).

## Что нового (2026-06-11)

- **Обновление баз из любой сети (route-doctor, ADR-0007).** Контейнер
  `route-doctor` зондирует изнутри docker-сети, какой egress жив прямо сейчас
  (сайдкары tinyproxy/xray, локальный прокси хоста через
  `host.docker.internal:<порт>`, прямой выход), и пишет план
  `artifacts/route-plan.{json,env}`. Апдейтеры применяют его автоматически —
  корп-прокси, v2rayN, VPN или прямой выход больше не требуют ручной настройки
  `HTTP_PROXY`/`ALL_PROXY`. cve-bin-tool всегда получает HTTP-мост (его клиент
  не умеет SOCKS). Отключение: `EL_SCA_AUTO_ROUTE=0` или `--no-auto-route`.
  Подробности — [docs/proxy.md](docs/proxy.md), раздел «Автовыбор маршрута».
- **Базы обновляются по отдельности или все сразу, без скана.**
  `./scripts/update-db.sh [all|trivy|grype|cve-bin-tool]`, `make update`
  (всё) / `make update TOOL=grype` (один инструмент); через MCP —
  `update_db(tool="all")` с одним сетевым зондированием на весь прогон;
  в GUI — кнопки «Обновить ВСЁ» / per-tool / per-source, теперь тоже с
  авто-маршрутом, плюс индикатор «🛰 Маршрут» в шапке.
- **Фиксы compose:** профиль `proxy` снова поднимается (`tinyproxy` ждал
  healthy от `proxy-xray`, у которого healthcheck отключён); `route-doctor`
  не входит в профили `update`/`scan` и не обрывает долгие апдейтеры.

## Что нового (2026-06-06)

- **GUI с drag-and-drop.** Перетащите артефакт в веб-интерфейс — анализ
  стартует автоматически, стадии конвейера и лог идут в реальном времени,
  карточки показывают версии и время обновления баз, есть кнопка разового
  обновления баз. Запуск: `python -m resilient_updates.cli dashboard
  --repo-root . --port 8080` (см. секцию 5.1).
- **Операторская инструкция GitHub/GitLab → GUI → update DB → scan → S3/logs:**
  [`docs/operator-quickstart-ru.md`](docs/operator-quickstart-ru.md).
- **Выгрузка проекта с базами на GitLab/Docker.** Текущие базы пакуются в
  data-образ и едут в Container Registry; на целевой машине разворачиваются
  одной командой. Скрипты `scripts/export_db_image.sh` /
  `import_db_image.sh` (+ Make-цели `db-export-image` / `db-import-image`) и
  руководство `docs/SHIP_AND_DEPLOY.md`.

## Что нового (2026-05-17)

- **Batch-runner для нескольких артефактов.** Готовый запуск пачки тикетов одной командой — см. `scripts/windows/batch-scan.ps1` / `scripts/batch-scan.sh` и шаблоны в `batches/`. Подробности — `docs/operations.md` секция «Batch».
- **Шапка отчёта больше не `UNKNOWN`.** Поля `DB snapshot`, `DB drift`, `Tool failures`, `Update policy`, `Input archive SHA-256` теперь вычисляются автоматически из существующих провенансов и манифестов через `python -m resilient_updates.cli write-run-summary` (вызывается из `collect_reports.sh`); если файлы отсутствуют, `reporting.py` делает то же in-memory.
- **DB freshness banner.** `scripts/windows/run-scan.ps1` показывает большой цветной баннер с возрастом каждой DB перед сканом и после — `OK` (зелёный) / `STALE — older than 24h` (жёлтый) / `MISSING` (красный). Если что-то stale — рядом инструкция, как обновить.
- **No-update-by-default.** Updater-сервисы (`trivy-updater`, `grype-updater`, `cve-bin-tool-updater`) теперь только в профиле `update` / `test-failover`. Чистый `docker compose up` больше не пытается обновлять БД, профили `offline` и `airgap` действительно означают «без сети».
- **`-UpdateDb` теперь громко предупреждает** про 5–15 минут ожидания и `.env.local` NVD ключи.

## 1. Что входит в комплекс

### Сканеры и вспомогательные компоненты

- `Trivy`
  - контейнерный сканер уязвимостей;
  - рабочая DB хранится в Docker `named volume`, то есть в именованном Docker-хранилище, а не в каталоге репозитория;
  - использует штатные multi-repository flags для DB и Java DB;
  - пишет raw JSON в `artifacts/reports/trivy/`.

- `Grype`
  - сканер уязвимостей по `SBOM`;
  - получает DB через wrapper, который сначала подготавливает archive DB, а затем импортирует её в runtime cache;
  - scan-stage работает с отключённым auto-update, то есть не подтягивает новую DB сам по себе;
  - пишет raw JSON в `artifacts/reports/grype/`.

- `Syft`
  - генератор `SBOM`;
  - не имеет собственной vulnerability DB;
  - пишет `SBOM` в `artifacts/sbom/`.

- `artifact-extractor`
  - контейнер подготовки входных артефактов;
  - рекурсивно распаковывает архивы до заданной глубины;
  - пишет `extraction_manifest.json`, то есть машинно-читаемый журнал того, что было распаковано и где лежит результат.

- `cve-bin-tool`
  - бинарный сканер CVE с собственным локальным cache DB;
  - DB и auxiliary data хранятся в Docker `named volumes`;
  - вынесен в отдельные update/scan стадии;
  - пишет raw JSON в `artifacts/reports/cve-bin-tool/`.

- `resilient_updates`
  - Python orchestration layer;
  - валидирует конфигурацию;
  - ведёт provenance;
  - обновляет Grype DB;
  - выполняет audit для `cve-bin-tool` DB;
  - собирает итоговый Markdown-отчёт.

- `report-collector`
  - отдельный контейнер сборки финального отчёта;
  - агрегирует evidence из `artifacts/`;
  - формирует единый Markdown-отчёт.

- `mock-feed-server`
  - тестовый контейнер для сценариев отказа источников;
  - нужен для failover-тестов, а не для обычного сканирования.

- `apk-analyzer` *(специализированный pipeline)*
  - анализ Android APK через androguard: разбор `AndroidManifest.xml` и DEX, генерация synthetic SBOM;
  - запускается только при `-Format apk` (auto-detect для `.apk` и `.zip` с `.apk` внутри);
  - пишет `artifacts/reports/apk/apk_analysis.txt` и `artifacts/sbom/syft.json`.

- `win-analyzer` *(специализированный pipeline)*
  - анализ Windows-installer'ов (NSIS `.exe`, MSI, обёртки в `.zip`): распаковка через innoextract/msitools, PE-метаданные через pefile;
  - запускается только при `-Format win`;
  - пишет `artifacts/reports/win/win_analysis.txt` и `artifacts/sbom/syft.json`.

- `osv-scanner` *(опционально, profile `osv`)*
  - дополнительный матчинг по google/osv.dev — комплементарен Grype/Trivy для ecosystem-advisories (Go/npm/pypi/Maven);
  - пишет `artifacts/reports/osv-scanner/report.json`.

- `proxy-xray` + `tinyproxy` *(опционально, profile `proxy`)*
  - sidecar-стек для сложной сети: единая точка `tinyproxy:8888` (HTTP front) → `proxy-xray:1080` (SOCKS5 + routing) → upstream chain;
  - конфигурация в `configs/xray/config.json` и `configs/tinyproxy/tinyproxy.conf`;
  - подробности — `docs/network-design.md` и `docs/adr/0002-proxy-sidecar.md`.

- `wireguard` *(опционально, profile `vpn`)*
  - VPN-туннель для случаев, когда конечные зеркала доступны только из VPN;
  - конфиг в `configs/wireguard/wg0.conf` (gitignored).

### Контейнерные сервисы

Состав сервисов описан в [docker-compose.yml](D:/dev/el-sca-ansamble/docker-compose.yml):

- `stack-info` — минимальная проверка стека и конфигурации;
- `trivy-updater` — прогрев Trivy DB cache *(profile `update`)*;
- `trivy-scanner` — запуск Trivy scan-stage;
- `grype-updater` — загрузка и активация Grype DB archive *(profile `update` + `test-failover`)*;
- `grype-db-importer` — импорт активного Grype DB archive в runtime cache для scan-stage;
- `grype-static` — статическая HTTP-раздача активной Grype DB (с healthcheck);
- `grype-scanner` — запуск Grype по SBOM;
- `syft-sbom` — построение SBOM;
- `artifact-extractor` — рекурсивная распаковка входного архива или каталога с артефактами;
- `cve-bin-tool-updater` — обновление и audit DB `cve-bin-tool` *(profile `update`)*;
- `cve-bin-tool-scanner` — запуск `cve-bin-tool` по целевому каталогу;
- `db-admin` — общий runner для `validate-config`, `db-status`, `audit`, `proxy-status`, `write-run-summary`;
- `report-collector` — сборка итогового Markdown-отчёта;
- `mock-feed-server` — имитация отказов источников *(profile `test-failover`)*;
- `apk-analyzer` *(profile `apk`)* — анализ Android APK;
- `win-analyzer` *(profile `win`)* — анализ Windows-installer'ов;
- `osv-scanner` *(profile `osv`)* — google/osv.dev matcher;
- `proxy-xray`, `tinyproxy` *(profile `proxy`)* — sidecar proxy chain;
- `wireguard` *(profile `vpn`)* — VPN-туннель.

**Профильная политика:** updater-сервисы (`*-updater`) присутствуют **только** в профиле `update`, чтобы голый `docker compose up` не пытался обновлять БД. Профили `offline` и `airgap` означают «сканирование без сети». См. `docs/airgap.md`.

### Основные каталоги артефактов

- `artifacts/sbom/` — SBOM-файлы Syft;
- `artifacts/reports/grype/` — raw JSON Grype;
- `artifacts/reports/trivy/` — raw JSON Trivy;
- `artifacts/reports/cve-bin-tool/` — raw JSON `cve-bin-tool`;
- `artifacts/reports/final/` — итоговые Markdown-отчёты;
- `artifacts/provenance/` — provenance JSON;
- `artifacts/extracted/` — результаты автоматической распаковки и `extraction_manifest.json`;
- `artifacts/mirror/` — экспортируемые mirror/export артефакты.

Рабочие vulnerability DB больше не считаются частью каталога репозитория.  
Они хранятся в Docker `named volumes`:

- `trivy-cache`
- `grype-db`
- `grype-cache`
- `cve-bin-tool-cache`
- `internal-mirror-data`

Это убирает разнобой по путям хранения на host-системе и делает схему одинаковой для Windows, WSL и Linux.

## 2. Развёртывание комплекса с нуля

### Требования

#### Минимальные системные требования

| Ресурс | Минимум | Рекомендуется | Зачем |
|---|---|---|---|
| ОС | Windows 10/11 x64 (с WSL2) или Linux x86_64 (Ubuntu 20.04+/аналог) | — | хост Docker |
| CPU | 2 ядра | 4+ ядра | cve-bin-tool гоняет регэкспы по бинарям |
| RAM | 4 ГБ | 8 ГБ+ | Trivy/Grype/cve-bin-tool + распаковка |
| Диск (свободно) | 20 ГБ | 30 ГБ+ | бандл ~3.3 ГБ (LFS) + загруженные образы + тома БД + артефакты сканов |
| Сеть | нужна для online-обновления баз | — | при работе из бандла/зеркал не требуется |

#### Необходимые компоненты

| Компонент | Версия | Для чего | Обязателен |
|---|---|---|---|
| Docker Engine / Docker Desktop | Engine 20.10+ / Desktop 4.x | запуск всего стека сканеров | да |
| Docker Compose v2 | плагин `docker compose` (не `docker-compose`) | оркестрация сервисов | да |
| Git | 2.x | клонирование | да |
| Git LFS | 3.x | образы и базы уязвимостей лежат в `bundle/` через LFS (~3.3 ГБ) | да |
| Python | 3.10+ (в контейнерах — 3.12) | CLI-обёртка (`resilient_updates`), `run-scan.sh`, GUI-дашборд | да для CLI/GUI |
| pip + venv | под вашу версию Python | установка зависимостей дашборда | для GUI |

> Чистый поток «`docker compose --profile ...`» требует только Docker + Git/Git LFS.
> Python на хосте нужен для CLI-обёртки (`run-scan.sh`, `validate-config`) и веб-дашборда.
> На Windows Docker Desktop должен работать на бэкенде **WSL2** (не Hyper-V/Windows-контейнеры).

#### Установка компонентов

**Windows (PowerShell от администратора, через `winget`):**

```powershell
winget install -e --id Docker.DockerDesktop      # после установки: запустить, включить WSL2 backend
winget install -e --id Git.Git
winget install -e --id GitHub.GitLFS
winget install -e --id Python.Python.3.12
git lfs install
```

Проверка:

```powershell
docker --version
docker compose version
git lfs version
python --version
```

**Linux (Ubuntu/Debian):**

```sh
# Docker Engine + Compose v2 (официальный скрипт)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"          # затем перелогиниться, чтобы группа применилась

# Git, Git LFS, Python
sudo apt-get update
sudo apt-get install -y git git-lfs python3 python3-pip python3-venv
git lfs install
```

Проверка:

```sh
docker --version
docker compose version          # должно быть "Docker Compose version v2.x"
git lfs version
python3 --version
```

> Если `docker compose version` сообщает об ошибке, а есть только старый `docker-compose` (v1) —
> поставьте плагин Compose v2: `sudo apt-get install -y docker-compose-plugin`.

### Шаг 1. Клонирование репозитория

```powershell
git clone https://github.com/Eljees/el-sca-ansamble.git
cd el-sca-ansamble
```

Linux:

```sh
git clone https://github.com/Eljees/el-sca-ansamble.git
cd el-sca-ansamble
```

### Шаг 2. Проверка окружения

Windows PowerShell:

```powershell
docker --version
docker compose version
git lfs version
python --version
```

Linux:

```sh
docker --version
docker compose version
git lfs version
python3 --version
```

### Шаг 3. Подготовка каталогов артефактов

Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force -Path `
  artifacts, `
  artifacts\reports, `
  artifacts\reports\final, `
  artifacts\provenance, `
  artifacts\sbom, `
  artifacts\cache, `
  artifacts\mirror | Out-Null
```

Linux:

```sh
mkdir -p artifacts/reports/final artifacts/provenance artifacts/sbom artifacts/cache artifacts/mirror
```

### Шаг 4. Валидация конфигурации и Compose

Windows PowerShell:

```powershell
python -m resilient_updates.cli validate-config
docker compose --profile default --profile update --profile scan --profile test-failover --profile offline --profile report config | Out-Null
```

Linux:

```sh
python3 -m resilient_updates.cli validate-config
docker compose --profile default --profile update --profile scan --profile test-failover --profile offline --profile report config >/dev/null
```

### Шаг 5. Smoke-test комплекса

Windows PowerShell:

```powershell
.\scripts\windows\smoke-test.ps1
```

Linux:

```sh
./scripts/smoke_test.sh
```

### Шаг 6. Сборка локальных образов

`Docker build` нужен для контейнеров с нашим Python wrapper-слоем и `cve-bin-tool`.

Windows PowerShell:

```powershell
docker compose build
```

Linux:

```sh
docker compose build
```

## 3. Центральная конфигурация

Главный policy-файл источников: [configs/feed_sources.yaml](D:/dev/el-sca-ansamble/configs/feed_sources.yaml)

Он управляет:

- Trivy DB repositories;
- Trivy Java DB repositories;
- Trivy checks bundle repositories;
- Grype upstream update URLs и внутренним stable endpoint;
- mirrors и DB-audit политикой для `cve-bin-tool`;
- допустимыми типами источников Syft;
- пользовательскими источниками `custom_sources`.

## 4. Последовательность команд для полного сканирования всеми сканерами

Ниже приведён рекомендуемый сценарий для каталога с артефактами.  
Целевой каталог можно менять через `SCAN_TARGET_HOST`.

Пример целевого каталога:

```text
C:\scans\CYBERSEC-11531\prometheus-3.11.0.linux-amd64.tar.gz_extracted\prometheus-3.11.0.linux-amd64\prometheus-3.11.0.linux-amd64
```

### 4.1. Полный цикл на Windows PowerShell

#### Шаг 1. Задать target

```powershell
$env:SCAN_TARGET_HOST = "C:\scans\CYBERSEC-11531\prometheus-3.11.0.linux-amd64.tar.gz_extracted\prometheus-3.11.0.linux-amd64\prometheus-3.11.0.linux-amd64"
$env:SCAN_TARGET_CONTAINER = "/scan-target"
$env:SCAN_TARGET_DISPLAY = $env:SCAN_TARGET_HOST
$env:SYFT_TARGET = "/scan-target"
$env:SYFT_FROM = "dir"
$env:TRIVY_TARGET = "/scan-target"
$env:CVE_BIN_TOOL_TARGET = "/scan-target"
$env:REPORT_OUTPUT = "/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md"
```

#### Шаг 2. Обновить базы

```powershell
$env:TRIVY_RENDERED_FLAGS = python -m resilient_updates.cli render-flags trivy
docker compose --profile update run --rm -e TRIVY_RENDERED_FLAGS=$env:TRIVY_RENDERED_FLAGS trivy-updater
docker compose --profile update run --rm grype-updater
docker compose --profile update run --rm grype-db-importer
docker compose --profile update run --rm cve-bin-tool-updater
```

#### Шаг 3. Построить SBOM

```powershell
docker compose --profile scan run --rm syft-sbom
```

#### Шаг 4. Запустить все сканеры

```powershell
docker compose --profile scan run --rm -e TRIVY_RENDERED_FLAGS=$env:TRIVY_RENDERED_FLAGS trivy-scanner
docker compose --profile scan run --rm grype-scanner
docker compose --profile scan run --rm cve-bin-tool-scanner
```

#### Шаг 5. Собрать сводный отчёт

```powershell
docker compose --profile report run --rm report-collector
python -m resilient_updates.cli collect-report `
  --reports-dir artifacts `
  --target $env:SCAN_TARGET_HOST `
  --display-target $env:SCAN_TARGET_DISPLAY `
  --output "C:\scans\CYBERSEC-11531\cve_analysis_report_2026-05-14_ru.md"
```

#### Шаг 6. Где лежат результаты

- все сырые находки всех сканеров:
  - `artifacts/reports/grype/report.json`
  - `artifacts/reports/trivy/report.json`
  - `artifacts/reports/cve-bin-tool/report.json`
- SBOM:
  - `artifacts/sbom/syft.json`
  - `artifacts/sbom/cyclonedx.json`
  - `artifacts/sbom/spdx.json`
- provenance:
  - `artifacts/provenance/*.json`
- финальный Markdown:
  - `artifacts/reports/final/cve_analysis_report_generated_ru.md`
  - либо путь, заданный в `--output`

### 4.1.1. Готовый Windows-блок: скопировать, вставить, поменять путь, запустить

Ниже блок команд в формате `copy/paste`.  
Нужно поменять только значение `$env:SCAN_TARGET_HOST`.

```powershell
Set-Location "D:\dev\el-sca-ansamble"

$env:SCAN_TARGET_HOST = "D:\path\to\artifact-folder"
$env:SCAN_TARGET_CONTAINER = "/scan-target"
$env:SCAN_TARGET_DISPLAY = $env:SCAN_TARGET_HOST
$env:SYFT_TARGET = "/scan-target"
$env:SYFT_FROM = "dir"
$env:TRIVY_TARGET = "/scan-target"
$env:CVE_BIN_TOOL_TARGET = "/scan-target"
$env:REPORT_OUTPUT = "/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md"

New-Item -ItemType Directory -Force -Path `
  artifacts, `
  artifacts\reports, `
  artifacts\reports\final, `
  artifacts\provenance, `
  artifacts\sbom, `
  artifacts\cache, `
  artifacts\mirror | Out-Null

python -m resilient_updates.cli validate-config
docker compose --profile default --profile update --profile scan --profile report config | Out-Null

.\scripts\windows\run-scan.ps1 `
  -Target $env:SCAN_TARGET_HOST `
  -Tool all `
  -ReportOutput "artifacts\reports\final\cve_analysis_report_windows_ru.md"

Write-Host ""
Write-Host "Full report: artifacts\reports\final\cve_analysis_report_windows_ru.md"
Write-Host "Raw Grype:   artifacts\reports\grype\report.json"
Write-Host "Raw Trivy:   artifacts\reports\trivy\report.json"
Write-Host "Raw CVE BT:  artifacts\reports\cve-bin-tool\report.json"
Write-Host "SBOM:        artifacts\sbom\syft.json"
```

Если входной путь указывает на архив, добавьте `-Extract`. Тогда сначала будет выполнена контейнерная распаковка в `artifacts\extracted\current`, а сканеры пойдут уже по распакованному каталогу.

По умолчанию `run-scan.ps1` не обновляет базы: scan-stage использует уже подготовленные Docker volumes и только выводит предупреждение, если база старше 24 часов или отсутствует. Для явного обновления перед сканом добавьте `-UpdateDb` или заранее выполните отдельные update-команды из раздела развёртывания.

```powershell
.\scripts\windows\run-scan.ps1 `
  -Target "D:\path\to\artifact.zip" `
  -Tool all `
  -Extract `
  -ReportOutput "artifacts\reports\final\cve_analysis_report_windows_ru.md"
```

Если нужен совсем короткий шаблон только для уже подготовленного каталога:

```powershell
.\scripts\windows\run-scan.ps1 -Target "D:\path\to\artifact-folder" -Tool all -ReportOutput "artifacts\reports\final\cve_analysis_report_windows_ru.md"
```

Для пакетной распаковки каталога с кейсами, например `C:\scans\projects`, используйте:

```powershell
.\scripts\windows\extract-projects.ps1 `
  -Root "C:\scans\projects" `
  -OutputRoot "artifacts\extracted\projects" `
  -MaxDepth 4
```

### 4.2. Полный цикл на Linux

```sh
export SCAN_TARGET_HOST="/absolute/path/to/artifact-folder"
export SCAN_TARGET_CONTAINER="/scan-target"
export SCAN_TARGET_DISPLAY="$SCAN_TARGET_HOST"
export SYFT_TARGET="/scan-target"
export SYFT_FROM="dir"
export TRIVY_TARGET="/scan-target"
export CVE_BIN_TOOL_TARGET="/scan-target"
export REPORT_OUTPUT="/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md"
export TRIVY_RENDERED_FLAGS="$(python3 -m resilient_updates.cli render-flags trivy)"

docker compose --profile update run --rm -e TRIVY_RENDERED_FLAGS="$TRIVY_RENDERED_FLAGS" trivy-updater
docker compose --profile update run --rm grype-updater
docker compose --profile update run --rm grype-db-importer
docker compose --profile update run --rm cve-bin-tool-updater

docker compose --profile scan run --rm syft-sbom
docker compose --profile scan run --rm -e TRIVY_RENDERED_FLAGS="$TRIVY_RENDERED_FLAGS" trivy-scanner
docker compose --profile scan run --rm grype-scanner
docker compose --profile scan run --rm cve-bin-tool-scanner

docker compose --profile report run --rm report-collector
python3 -m resilient_updates.cli collect-report \
  --reports-dir artifacts \
  --target "$SCAN_TARGET_HOST" \
  --display-target "$SCAN_TARGET_DISPLAY" \
  --output "artifacts/reports/final/cve_analysis_report_linux_ru.md"
```

### 4.3. Готовый Linux-блок: скопировать, вставить, поменять путь, запустить

Ниже блок команд в формате `copy/paste`.  
Нужно поменять только значение `SCAN_TARGET_HOST`.

```sh
cd /path/to/el-sca-ansamble || exit 1

export SCAN_TARGET_HOST="/absolute/path/to/artifact-folder"
export SCAN_TARGET_CONTAINER="/scan-target"
export SCAN_TARGET_DISPLAY="$SCAN_TARGET_HOST"
export SYFT_TARGET="/scan-target"
export SYFT_FROM="dir"
export TRIVY_TARGET="/scan-target"
export CVE_BIN_TOOL_TARGET="/scan-target"
export REPORT_OUTPUT="/workspace/artifacts/reports/final/cve_analysis_report_linux_ru.md"
export TRIVY_RENDERED_FLAGS="$(python3 -m resilient_updates.cli render-flags trivy)"

mkdir -p artifacts/reports/final artifacts/provenance artifacts/sbom artifacts/cache artifacts/mirror

python3 -m resilient_updates.cli validate-config
docker compose --profile default --profile update --profile scan --profile report config >/dev/null

docker compose --profile update run --rm -e TRIVY_RENDERED_FLAGS="$TRIVY_RENDERED_FLAGS" trivy-updater
docker compose --profile update run --rm grype-updater
docker compose --profile update run --rm grype-db-importer
docker compose --profile update run --rm cve-bin-tool-updater

docker compose --profile scan run --rm syft-sbom
docker compose --profile scan run --rm -e TRIVY_RENDERED_FLAGS="$TRIVY_RENDERED_FLAGS" trivy-scanner
docker compose --profile scan run --rm grype-scanner
docker compose --profile scan run --rm cve-bin-tool-scanner

docker compose --profile report run --rm report-collector

python3 -m resilient_updates.cli collect-report \
  --reports-dir artifacts \
  --target "$SCAN_TARGET_HOST" \
  --display-target "$SCAN_TARGET_DISPLAY" \
  --output "artifacts/reports/final/cve_analysis_report_linux_ru.md"

echo
echo "Full report: artifacts/reports/final/cve_analysis_report_linux_ru.md"
echo "Raw Grype:   artifacts/reports/grype/report.json"
echo "Raw Trivy:   artifacts/reports/trivy/report.json"
echo "Raw CVE BT:  artifacts/reports/cve-bin-tool/report.json"
echo "SBOM:        artifacts/sbom/syft.json"
```

Для архива можно сначала выполнить контейнерную распаковку и затем сканировать результат:

```sh
export EXTRACT_INPUT_HOST="/absolute/path/to/artifact.zip"
export EXTRACT_OUTPUT="/workspace/artifacts/extracted/current"
docker compose --profile extract run --rm artifact-extractor

export SCAN_TARGET_HOST="$(pwd)/artifacts/extracted/current"
```

Если нужен совсем короткий шаблон только для замены пути:

```sh
SCAN_TARGET_HOST="/absolute/path/to/artifact-folder"; \
export SCAN_TARGET_HOST SCAN_TARGET_CONTAINER="/scan-target" SCAN_TARGET_DISPLAY="$SCAN_TARGET_HOST" SYFT_TARGET="/scan-target" SYFT_FROM="dir" TRIVY_TARGET="/scan-target" CVE_BIN_TOOL_TARGET="/scan-target" REPORT_OUTPUT="/workspace/artifacts/reports/final/cve_analysis_report_linux_ru.md"; \
TRIVY_RENDERED_FLAGS="$(python3 -m resilient_updates.cli render-flags trivy)" && \
docker compose --profile update run --rm -e TRIVY_RENDERED_FLAGS="$TRIVY_RENDERED_FLAGS" trivy-updater && \
docker compose --profile update run --rm grype-updater && \
docker compose --profile update run --rm grype-db-importer && \
docker compose --profile update run --rm cve-bin-tool-updater && \
docker compose --profile scan run --rm syft-sbom && \
docker compose --profile scan run --rm -e TRIVY_RENDERED_FLAGS="$TRIVY_RENDERED_FLAGS" trivy-scanner && \
docker compose --profile scan run --rm grype-scanner && \
docker compose --profile scan run --rm cve-bin-tool-scanner && \
docker compose --profile report run --rm report-collector && \
python3 -m resilient_updates.cli collect-report --reports-dir artifacts --target "$SCAN_TARGET_HOST" --display-target "$SCAN_TARGET_DISPLAY" --output "artifacts/reports/final/cve_analysis_report_linux_ru.md"
```

## 5. Быстрый запуск для Windows

Если нужен быстрый запуск без ручного перечисления контейнеров, можно использовать [scripts/windows/run-scan.ps1](D:/dev/el-sca-ansamble/scripts/windows/run-scan.ps1).

Текущий `run-scan.ps1` теперь умеет полный цикл через `-Tool all` и отдельные прогоны через `syft`, `grype`, `trivy`, `cve-bin-tool`. По умолчанию базы не обновляются; для принудительного обновления перед сканом используйте `-UpdateDb`.

Пример:

```powershell
.\scripts\windows\run-scan.ps1 `
  -Target "C:\scans\CYBERSEC-11531\prometheus-3.11.0.linux-amd64.tar.gz_extracted\prometheus-3.11.0.linux-amd64\prometheus-3.11.0.linux-amd64" `
  -ReportOutput "C:\scans\CYBERSEC-11531\cve_analysis_report_2026-05-14_ru.generated.md"
```

## 5.1. Графический интерфейс (GUI) — drag-and-drop

Активный веб-интерфейс: перетащите артефакт в окно — анализ начнётся
автоматически, стадии конвейера (extract → SBOM → Grype → Trivy →
cve-bin-tool → report) подсвечиваются в реальном времени, ниже идёт живой лог.
Карточки «Базы инструментов» показывают версию каждого сканера и время
последнего обновления его БД. Обновление баз по умолчанию **выключено** —
скан использует уже загруженный снимок; отдельная кнопка «Обновить базы
(разово)» запускает обновление только по требованию.

**Зависимости.** GUI запускается на хосте (ему нужен доступ к `docker
compose`). Ставьте веб-зависимости тем же интерпретатором, которым запускаете
GUI — используйте `python -m pip`, а не голый `pip` (иначе пакеты уедут в
другой Python и появится ошибка `dashboard requires uvicorn`):

```powershell
python -m pip install fastapi "uvicorn[standard]" python-multipart
```

**Запуск:**

```powershell
python -m resilient_updates.cli dashboard --repo-root . --port 8080
# затем откройте http://127.0.0.1:8080
```

`--repo-root .` указывает, из какой папки вызывать `docker compose` для сканов
и обновления баз (по умолчанию — родитель `--artifacts-dir`). Перетащите
артефакт в зону загрузки — он сохранится в `artifacts/uploads/`, и поднимется
`docker compose --profile scan`. Отчёты появятся в `artifacts/reports/` (как и
при запуске из CLI, см. ниже).

> Контейнерный compose-сервис `dashboard` остаётся read-only (только просмотр
> прошлых прогонов). Активный GUI с загрузкой артефактов и обновлением баз
> работает именно при запуске на хосте через `cli dashboard`.

## 6. Что именно даёт итоговый отчёт

Итоговый Markdown, собираемый через `report-collector` и `python -m resilient_updates.cli collect-report`, содержит:

- сведения об объекте анализа;
- перечисление evidence-файлов;
- сводку по всем находкам всех сканеров;
- секцию `High / Critical findings`;
- provenance-файлы.

То есть:

- `все уязвимости` доступны в raw JSON отчётах каждого сканера и в агрегированной сводке;
- `критические и высокие` вынесены отдельно в Markdown-таблицу для быстрого анализа.

## 7. Полезные команды

Зафиксировать все правки одной командой (удаляет stale index.lock, снимает comands.txt с трекинга):

Windows PowerShell:

```powershell
.\scripts\windows\commit-fixes.ps1
```

Настройка прокси — см. [docs/proxy.md](docs/proxy.md).

Обновить базы без скана (авто-маршрут через route-doctor; работает за
корп-прокси, локальным v2rayN/xray, VPN или напрямую):

```sh
./scripts/update-db.sh            # все базы (trivy + grype + cve-bin-tool)
./scripts/update-db.sh cve-bin-tool   # одна база
make update                       # то же, что update-db.sh all
make update TOOL=grype            # один инструмент
```

Посмотреть, какой egress живой прямо сейчас (карта маршрутов per-tool):

```sh
docker compose --profile route run --rm route-doctor
python -m resilient_updates.cli update-doctor    # зондирование с хоста
```



Проверить provenance:

```powershell
python -m resilient_updates.cli provenance
```

Проверить healthcheck источников:

```powershell
python -m resilient_updates.cli healthcheck
```

Упаковать артефакты на Windows:

```powershell
.\scripts\windows\pack-artifacts.ps1
```

Очистить generated артефакты:

Windows:

```powershell
.\scripts\windows\clean-generated.ps1
```

Linux:

```sh
./scripts/clean_generated.sh
```

## 8. Ограничения текущего MVP

- Trivy healthcheck в Python wrapper не является полноценной OCI-aware проверкой: `oci://` URL классифицируются как `invalid_schema` и мгновенно пропускаются без повторных попыток (это правильное поведение — зафиксировано в failure-modes).
- Grype mirror/update flow работает через наш wrapper и внутренний stable endpoint, а не через встроенный multi-source fallback самого Grype.
- `cve-bin-tool` scan на крупных Go-бинарях (>50 МБ) может занимать долгое время. По умолчанию применяется таймаут 600 с (10 мин), настраивается через `CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS`.
- Syft намеренно не имеет никакой vulnerability DB — он отвечает за построение SBOM, а не за matching CVE.
- Прокси-поддержка Python-слоя не распространяется автоматически на бинарные инструменты (Trivy, Grype, Syft) внутри Docker — для них прокси задаётся через переменные окружения в `.env` (см. [docs/proxy.md](docs/proxy.md)).

## 9. Troubleshooting

- `validate-config` упал:
- проверить [configs/feed_sources.yaml](D:/dev/el-sca-ansamble/configs/feed_sources.yaml)
  - убедиться, что нет пустых или конфликтующих источников

- `docker compose ... config` упал:
  - проверить Docker Desktop или Docker Engine
  - проверить корректность путей `SCAN_TARGET_HOST`

- Trivy scan не стартует:
  - убедиться, что Trivy DB уже прогрета через `trivy-updater`
  - проверить доступность container registry

- Grype scan не стартует:
  - убедиться, что `syft.json` уже создан
  - убедиться, что `grype-updater` и `grype-static` отработали корректно

- `cve-bin-tool` scan не стартует или завис:
  - проверить DB audit и содержимое cache
  - проверить offline bundle или cache DB
  - если scan висит часами — это нормально для крупных Go-бинарей (100+ МБ); таймаут задан `CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS=600` в `.env`, при достижении пишется пустой отчёт и пайплайн продолжается

- итоговый отчёт пустой:
  - проверить наличие raw JSON в `artifacts/reports/`
  - проверить наличие `SBOM` в `artifacts/sbom/`
  - проверить `artifacts/provenance/`
