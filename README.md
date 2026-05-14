# Resilient Scanner Stack

Этот репозиторий содержит контейнерный SCA-комплекс для `Trivy`, `Grype`, `Syft` и `cve-bin-tool`.

`SCA` означает `Software Composition Analysis`, то есть анализ состава ПО и поиск известных уязвимостей в бинарях, пакетах и зависимостях.  
`Wrapper-first` означает, что логика отказоустойчивости и orchestration вынесена во внешние скрипты и Python-модули, а не реализована форком upstream-инструментов.  
`Provenance` означает машинно-читаемую фиксацию происхождения результата: какие источники обновления были опрошены, какой источник выбран, какие ошибки были до fallback.

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

### Контейнерные сервисы

Состав сервисов описан в [docker-compose.yml](D:/!ya_drive_sync/YandexDisk/rostel/el-sca-ansamble/docker-compose.yml):

- `stack-info` — минимальная проверка стека и конфигурации;
- `trivy-updater` — прогрев Trivy DB cache;
- `trivy-scanner` — запуск Trivy scan-stage;
- `grype-updater` — загрузка и активация Grype DB archive;
- `grype-db-importer` — импорт активного Grype DB archive в runtime cache для scan-stage;
- `grype-static` — статическая HTTP-раздача активной Grype DB;
- `grype-scanner` — запуск Grype по SBOM;
- `syft-sbom` — построение SBOM;
- `artifact-extractor` — рекурсивная распаковка входного архива или каталога с артефактами;
- `cve-bin-tool-updater` — обновление и audit DB `cve-bin-tool`;
- `cve-bin-tool-scanner` — запуск `cve-bin-tool` по целевому каталогу;
- `report-collector` — сборка итогового Markdown-отчёта;
- `mock-feed-server` — имитация отказов источников.

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

- Docker с поддержкой `docker compose`;
- Python `3.12+`;
- доступ в сеть для online update-stage, если не подготовлены свои внутренние зеркала;
- хост Windows или Linux.

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
python --version
```

Linux:

```sh
docker --version
docker compose version
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

Главный policy-файл источников: [configs/feed_sources.yaml](D:/!ya_drive_sync/YandexDisk/rostel/el-sca-ansamble/configs/feed_sources.yaml)

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
D:\!ya_drive_sync\YandexDisk\rostel\to_analyze\_to_verify_logic_CYBERSEC-11531\test\prometheus-3.11.0.linux-amd64.tar.gz_extracted\prometheus-3.11.0.linux-amd64\prometheus-3.11.0.linux-amd64
```

### 4.1. Полный цикл на Windows PowerShell

#### Шаг 1. Задать target

```powershell
$env:SCAN_TARGET_HOST = "D:\!ya_drive_sync\YandexDisk\rostel\to_analyze\_to_verify_logic_CYBERSEC-11531\test\prometheus-3.11.0.linux-amd64.tar.gz_extracted\prometheus-3.11.0.linux-amd64\prometheus-3.11.0.linux-amd64"
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
  --output "D:\!ya_drive_sync\YandexDisk\rostel\to_analyze\_to_verify_logic_CYBERSEC-11531\test\cve_analysis_report_2026-05-14_ru.md"
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
Set-Location "D:\!ya_drive_sync\YandexDisk\rostel\el-sca-ansamble"

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

Для пакетной распаковки каталога с кейсами, например `D:\!ya_drive_sync\YandexDisk\rostel\to_analyze\__projects`, используйте:

```powershell
.\scripts\windows\extract-projects.ps1 `
  -Root "D:\!ya_drive_sync\YandexDisk\rostel\to_analyze\__projects" `
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

Если нужен быстрый запуск без ручного перечисления контейнеров, можно использовать [scripts/windows/run-scan.ps1](D:/!ya_drive_sync/YandexDisk/rostel/el-sca-ansamble/scripts/windows/run-scan.ps1).

Текущий `run-scan.ps1` теперь умеет полный цикл через `-Tool all` и отдельные прогоны через `syft`, `grype`, `trivy`, `cve-bin-tool`. По умолчанию базы не обновляются; для принудительного обновления перед сканом используйте `-UpdateDb`.

Пример:

```powershell
.\scripts\windows\run-scan.ps1 `
  -Target "D:\!ya_drive_sync\YandexDisk\rostel\to_analyze\_to_verify_logic_CYBERSEC-11531\test\prometheus-3.11.0.linux-amd64.tar.gz_extracted\prometheus-3.11.0.linux-amd64\prometheus-3.11.0.linux-amd64" `
  -ReportOutput "D:\!ya_drive_sync\YandexDisk\rostel\to_analyze\_to_verify_logic_CYBERSEC-11531\test\cve_analysis_report_2026-05-14_ru.generated.md"
```

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

- Trivy healthcheck в Python wrapper пока не является полноценной OCI-aware проверкой, то есть не понимает `oci://` так же нативно, как сам Trivy.
- Grype mirror/update flow работает через наш wrapper и внутренний stable endpoint, а не через встроенный multi-source fallback самого Grype.
- `cve-bin-tool` пока использует wrapper-first pipeline без форка upstream, но безопасная isolated activation для DB ещё требует следующего этапа усиления.
- Syft намеренно не имеет никакой vulnerability DB, потому что он отвечает за построение SBOM, а не за matching CVE.

## 9. Troubleshooting

- `validate-config` упал:
  - проверить [configs/feed_sources.yaml](D:/!ya_drive_sync/YandexDisk/rostel/el-sca-ansamble/configs/feed_sources.yaml)
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

- `cve-bin-tool` scan не стартует:
  - проверить DB audit и содержимое cache
  - проверить offline bundle или cache DB

- итоговый отчёт пустой:
  - проверить наличие raw JSON в `artifacts/reports/`
  - проверить наличие `SBOM` в `artifacts/sbom/`
  - проверить `artifacts/provenance/`
