# Пользовательская инструкция: обновить базы и просканировать артефакт

Цель: с чистой машины выкачать стек из GitHub/GitLab, поднять веб-панель,
обновить базы, просканировать артефакт и понимать, где смотреть результаты и
логи.

## 1. Получить проект

GitHub:

```sh
git clone https://github.com/Eljees/el-sca-ansamble.git el-sca-ansamble
cd el-sca-ansamble
```

GitLab:

```sh
git clone https://gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble.git el-sca-ansamble
cd el-sca-ansamble
```

Подготовить Python-зависимости для GUI:

```sh
python -m pip install fastapi "uvicorn[standard]" python-multipart
```

Проверить compose:

```sh
docker compose config -q
```

## 2. Поднять внутреннее S3-хранилище

```sh
docker compose --profile storage up -d seaweedfs
python -m resilient_updates.cli s3-results-push --help
```

Для баз пока используются команды:

```sh
make s3-db-pull
make s3-db-push
```

Если `make` недоступен, используйте shell-обвязку напрямую:

```sh
./scripts/s3_storage.sh db-pull latest
./scripts/s3_storage.sh db-push
```

## 3. Запустить GUI

Обычный локальный запуск:

```sh
python -m resilient_updates.cli dashboard --repo-root . --port 8080
```

Открыть:

```text
http://127.0.0.1:8080
```

Если надо сразу публиковать результаты сканов в S3:

```sh
EL_SCA_RESULTS_TO_S3=1 python -m resilient_updates.cli dashboard --repo-root . --port 8080
```

На удалённой Ubuntu безопаснее открыть через SSH tunnel:

```sh
python3 -m resilient_updates.cli dashboard --repo-root . --host 127.0.0.1 --port 8088
```

С рабочей машины:

```powershell
ssh -i C:\Users\314he\.ssh\elaria_rostel -L 8088:127.0.0.1:8088 elaria@192.168.1.33
```

Открыть:

```text
http://127.0.0.1:8088
```

## 4. Обновить базы через GUI

В веб-панели нажать обновление баз:

- `all` — Trivy, Grype, cve-bin-tool;
- `trivy` — только Trivy;
- `grype` — Grype + импорт активного snapshot;
- `cve-bin-tool` — все источники cve-bin-tool;
- `cve-bin-tool:NVD`, `OSV`, `GAD`, `REDHAT`, `EPSS`, `PURL2CPE`, `RSD` — точечный источник.

Если прямой интернет не работает, dashboard сначала пробует route-plan через
доступные proxy/VPN/sidecar. Ход обновления пишется в:

```text
artifacts/db_status/updates/20260707-120000_all.log
```

После успешного обновления можно сохранить базы во внутренний S3:

```sh
make s3-db-push
```

## 5. Просканировать артефакт через GUI

Перетащить файл/архив в окно dashboard. GUI покажет стадии:

```text
extract -> SBOM -> Grype -> Trivy -> cve-bin-tool -> report
```

Результаты сохраняются:

```text
_SCA_reports/prometheus-20260707-120000/
artifacts/reports/final/
```

Если был включён `EL_SCA_RESULTS_TO_S3=1`, snapshot также появится:

```text
s3://el-sca/scans/prometheus-20260707-120000/
s3://el-sca/scans/latest/
```

## 6. То же самое без GUI

Обновить базы покомандно через Python/compose:

```sh
docker compose --profile volinit run --rm volume-init
python -m resilient_updates.cli route-plan --json --artifacts-dir artifacts
docker compose --profile update run --rm trivy-updater
docker compose --profile update run --rm grype-updater
docker compose --profile update run --rm grype-db-importer
docker compose --profile update run --rm cve-bin-tool-updater
```

Просканировать через готовый runner:

```sh
EL_SCA_RESULTS_TO_S3=1 ./scripts/run-scan.sh /path/to/artifact
```

Windows:

```powershell
$env:EL_SCA_RESULTS_TO_S3="1"
.\scripts\windows\run-scan.ps1 -Target "C:\path\artifact.zip"
```

Опубликовать уже готовый snapshot в S3 без shell-скриптов:

```sh
python -m resilient_updates.cli s3-results-push
python -m resilient_updates.cli s3-results-push _SCA_reports/prometheus-20260707-120000
```

## 7. Логи и ротация

Главные места:

```text
artifacts/run-scan.log              # command runner
artifacts/run-scan.log.1..5         # rotated command logs
_SCA_reports/prometheus-20260707-120000/job.log  # GUI scan job
artifacts/db_status/updates/*.log   # GUI/command DB update transcripts
artifacts/logs/dashboard.log        # Python dashboard log
```

Настройки:

```sh
LOG_LEVEL=DEBUG
LOG_FORMAT=json
LOG_FILE=artifacts/logs/dashboard.log
LOG_MAX_BYTES=10485760
LOG_BACKUP_COUNT=5
EL_SCA_LOG_BACKUP_COUNT=5
EL_SCA_UPDATE_LOG_KEEP=50
EL_SCA_HEARTBEAT_SECONDS=30
```

Для разбора падения обычно нужны:

```sh
docker compose ps
docker compose logs --no-color > artifacts/logs/compose-debug.log
python -m resilient_updates.cli monitor --json > artifacts/logs/monitor.json
```

Не коммитить `_SCA_reports/`, `artifacts/logs/`, `artifacts/run-scan.log*`,
`artifacts/db_status/` и raw reports: это runtime evidence.
