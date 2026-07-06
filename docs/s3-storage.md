# Внутреннее S3-хранилище баз и результатов

MVP-цель: добавить в стек один внутренний склад, куда можно складывать
валидированные базы сканеров и результаты прогонов. На первом шаге это
SeaweedFS с S3 API и простая обвязка `scripts/s3_storage.sh`.

## Состав

- `seaweedfs` — S3-совместимое хранилище, профиль Compose `storage`.
- `s3-client` — одноразовый контейнер `minio/mc`, профиль `storage-tools`.
- `scripts/s3_storage.sh` — команды публикации/получения.

Запуск:

```sh
make s3-init
```

По умолчанию bucket называется `el-sca`, endpoint внутри Docker:
`http://seaweedfs:8333`. С хоста S3 API опубликован на
`http://127.0.0.1:8333`.

MVP-ключи доступа лежат в `.env.example` и
`configs/seaweedfs/s3.json`: `el-sca` / `el-sca-secret`. Для реального стенда
замените их в обоих местах или вынесите генерацию `s3.json` в отдельный
секретный deploy-шаг.

## Layout bucket

```text
s3://el-sca/
  db/
    trivy/
      latest/
      previous/
    grype/
      latest/
      previous/
    cve-bin-tool/
      latest/
      previous/
      sources/
        nvd/latest/
        osv/latest/
        gad/latest/
        redhat/latest/
        epss/latest/
        purl2cpe/latest/
        rsd/latest/
    all/
      latest/
      previous/

  scans/
    latest/
    previous/
    <run-id>/
```

Retention намеренно простой: перед публикацией новый `latest` сдвигает старый
снимок в `previous`. Исторические immutable-снапшоты можно добавить позже.

## Базы

Опубликовать текущие Docker volume'ы баз:

```sh
make s3-db-push
```

Команда сначала вызывает существующий `db-exporter`, затем кладёт архивы в S3:

- `trivy-cache.tar.gz` → `db/trivy/latest/`
- `grype-db.tar.gz`, `grype-cache.tar.gz` → `db/grype/latest/`
- `cve-bin-tool-cache.tar.gz`, `internal-mirror-data.tar.gz` →
  `db/cve-bin-tool/latest/`
- все архивы вместе → `db/all/latest/`

Восстановить базы из S3:

```sh
make s3-db-pull              # latest
make s3-db-pull SLOT=previous
```

После скачивания архивов в `incoming/` запускается существующий `db-importer`,
а затем `grype-db-importer`.

## Отдельные источники cve-bin-tool

Для проблемных источников можно заливать сырьё отдельно:

```sh
./scripts/s3_storage.sh cve-source-push nvd artifacts/nvd-feeds
./scripts/s3_storage.sh cve-source-push osv /path/to/osv
./scripts/s3_storage.sh cve-source-push redhat /path/to/redhat
```

Поддерживаемые имена: `nvd`, `osv`, `gad`, `redhat`, `epss`, `purl2cpe`, `rsd`.
Готовый собранный `cve.db` всё равно хранится отдельно в
`db/cve-bin-tool/latest/`, потому что это самый быстрый путь для закрытого
контура.

## Результаты сканирования

`run-scan.sh` уже сохраняет per-run snapshot в `artifacts/runs/<run-id>/`.
Опубликовать последний snapshot:

```sh
make s3-results-push
```

Или явно:

```sh
make s3-results-push RUN=artifacts/runs/my-run-id
```

Снимок появляется в двух местах:

- `scans/<run-id>/` — постоянная ссылка на конкретный прогон;
- `scans/latest/` — последний опубликованный прогон.

Завтра на этом месте можно добавить простой HTTP index/дашборд, чтобы открывать
`report.html` и `MANIFEST.json` прямо с сервера.

## Ubuntu smoke без ручного копирования

На локальной машине:

```sh
git push origin master
git push gitlab master
```

На Ubuntu:

```sh
git pull
docker compose --profile storage config -q
make s3-init
```

Если нужно проверить DB round-trip без интернета:

```sh
make s3-db-pull
docker compose --profile airgap run --rm db-admin db-status grype \
  --path /var/lib/resilient-db/grype/active
```
