# Air-gapped эксплуатация

Этот документ описывает, как развернуть el-sca-ansamble в среде без сетевого выхода — например, в закрытом периметре, где базы уязвимостей доставляются на USB-носителе или через отдельный bastion.

Профиль `airgap` в `docker-compose.yml` отличается от `offline` тем, что **полностью исключает** все `*-updater` сервисы. Если стек запущен с `COMPOSE_PROFILES=airgap`, никакая попытка обновления БД физически не возможна — нет ни одного контейнера, который мог бы дёрнуть upstream.

---

## 1. Подготовка bundle (на машине с сетью)

```sh
# Один раз — собрать «golden» снимок баз.
cd /path/to/el-sca-ansamble
SCAN_TARGET_HOST=/tmp/dummy COMPOSE_PROFILES=update docker compose up --abort-on-container-exit

# Получаем активные снимки:
#   /var/lib/resilient-db/trivy/                (Docker volume trivy-cache)
#   /var/lib/resilient-db/grype/active/         (Docker volume grype-db)
#   /var/lib/resilient-db/cve-bin-tool/active/  (Docker volume internal-mirror-data)

# Экспортируем их одним архивом (volumes-export).
docker run --rm \
  -v el-sca-ansamble_trivy-cache:/from/trivy \
  -v el-sca-ansamble_grype-db:/from/grype \
  -v el-sca-ansamble_internal-mirror-data:/from/cbt \
  -v "$PWD/artifacts/airgap":/out alpine \
  sh -c 'tar -C /from -czf /out/db-bundle-$(date -u +%Y%m%d).tar.gz .'
```

Размер bundle'а: 4–8 GB в зависимости от наполнения cve-bin-tool DB.

---

## 2. Доставка в закрытый периметр

Любым организационно допустимым каналом: USB, DVD, выделенный download-gateway. Bundle должен иметь sha256 + GPG-подпись от ответственного лица; целостность проверяйте перед импортом (см. `docs/security-notes.md` раздел 2).

---

## 3. Импорт bundle в air-gapped стенде

```sh
# Создать пустые volume'ы соответствующего имени.
docker compose --profile airgap up --no-start
# (контейнеры не стартуют, volumes создаются.)

# Импортировать содержимое.
docker run --rm \
  -v el-sca-ansamble_trivy-cache:/to/trivy \
  -v el-sca-ansamble_grype-db:/to/grype \
  -v el-sca-ansamble_internal-mirror-data:/to/cbt \
  -v "$PWD/incoming":/in alpine \
  sh -c 'cd / && tar -xzf /in/db-bundle-YYYYMMDD.tar.gz -C /'

# Активировать Grype-снимок в runtime cache.
docker compose --profile airgap run --rm grype-db-importer

# Проверить, что cve-bin-tool DB прошла аудит.
docker compose --profile airgap run --rm db-admin \
  audit cve-bin-tool-db --db-root /var/lib/resilient-db/cve-bin-tool/active
```

Если аудит провалится (`min_entries`, `max_cache_age`) — bundle устарел. На air-gapped стенде не остаётся выбора, кроме повторной доставки свежего bundle: pipeline честно вернёт `EXIT_STALE_REJECTED`.

---

## 4. Сканирование

```sh
SCAN_TARGET_HOST=/path/to/artifact \
  COMPOSE_PROFILES=airgap docker compose up --abort-on-container-exit
```

Что произойдёт:

- `artifact-extractor` распакует архив.
- `syft-sbom` соберёт SBOM (Syft не нуждается в сетевом доступе — он читает только сам артефакт).
- `grype-static` отдаст активный снимок Grype DB по `http://grype-static:8080`.
- `grype-scanner` сматчит SBOM против локального снимка (`GRYPE_DB_AUTO_UPDATE=false`).
- `trivy-scanner` отработает `--offline-scan` (если был выставлен `MODE=offline` при сборке bundle — иначе вызовите вручную `update_trivy.sh offline`).
- `cve-bin-tool-scanner` использует locally-cached DB (`--offline`).
- `report-collector` соберёт итоговый отчёт.

В `artifacts/provenance/*.json` будет видно, что ни один источник не пробовали онлайн — `attempted_sources` пуст для каждого update-стейджа (потому что они вообще не запускались).

---

## 5. Расхождения с обычным режимом

| Что | Online | Airgap |
|---|---|---|
| Обновление trivy/grype/cve-bin-tool DB | через `update`-сервисы | через bundle-доставку |
| `EPSS` и `CISA KEV` enrichment | по тем же файлам, что и cve-bin-tool DB | работает, если bundle содержит `epss/` и `kev/` |
| `proxy-status` healthcheck | внешние URL | бессмыслен; не вызывайте |
| `healthcheck` через CLI | пробует upstream | вернёт `down`/`degraded` для всех сетевых layer'ов — это **нормально** в airgap |
| `last_known_good` policy | страховка | основной режим |

---

## 6. Запреты

В режиме airgap:

- **Не запускайте** профили `update` или `proxy` — кто-то из контейнеров попытается ходить наружу и упадёт по таймауту, что замусорит провенанс. Используйте только `airgap`.
- **Не отключайте** `validate_hash` / `validate_age` ради ускорения — это единственный механизм проверки, что bundle не был подменён.
- **Не оставляйте** `*.example.invalid` URL'ы включёнными в `custom_sources` — они тратят retry-бюджет на DNS-резолв, который в airgap всё равно падает.

---

## 7. Чек-лист стенда

- [ ] `docker compose --profile airgap config -q` отрабатывает.
- [ ] `validate-config` не находит ошибок.
- [ ] `db-admin audit cve-bin-tool-db --db-root /var/lib/resilient-db/cve-bin-tool/active` → `pass`.
- [ ] `db-admin db-status grype --path /var/lib/resilient-db/grype/active` → age в пределах `warning_age`.
- [ ] Один контрольный скан reference-артефакта прошёл и собрал отчёт.
- [ ] В отчёте секция Provenance показывает source `null` или `last-known-good` для всех update-фаз.
