# Runbook — что делать, когда стек упал

Этот документ — операционный справочник по типичным сбоям el-sca-ansamble. Для каждого симптома: как диагностировать, как починить, какой раздел кода/документации трогать дальше.

Группировка по слою: запуск compose, обновление DB, сканирование, отчёт, сеть/прокси, Windows-специфика.

---

## 1. Запуск compose

### 1.1. `service "X" is not running`

**Симптом.** `docker compose run --rm <name>` отвечает `service X is not running` или `service not found`.

**Причина 99% случаев.** Не активирован профиль. Сервисы в `docker-compose.yml` распределены по профилям (`default`, `scan`, `update`, `offline`, `airgap`, `proxy`, `vpn`, `apk`, `win`, `osv`, `report`, `test-failover`). Без выбранного профиля поднимаются только сервисы без `profiles:` — таких в этом репо нет.

**Диагностика:**
```sh
docker compose config --services                 # все сервисы, что есть в схеме
docker compose --profile scan config --services  # только из профиля scan
echo "$COMPOSE_PROFILES"
```

**Фикс:** `export COMPOSE_PROFILES=scan,update` (или `COMPOSE_PROFILES=airgap`, и т. п.). На Windows: `$env:COMPOSE_PROFILES = "scan,update"`.

### 1.2. `Set SCAN_TARGET_HOST in .env to the path …`

**Симптом.** compose валится с этим сообщением до запуска контейнеров.

**Причина.** Bind-mount защищён `${SCAN_TARGET_HOST:?…}` — переменная не задана.

**Фикс.** Либо `export SCAN_TARGET_HOST=/abs/path/to/file`, либо вызов через `scripts/run-scan.sh -t …` / `scripts\windows\run-scan.ps1 -Target …`, которые сами проставляют переменную.

### 1.3. `Volume "trivy-cache" not found`

**Причина.** Docker Compose v1 (`docker-compose` с дефисом) не подхватывает named volumes из схемы v2. Либо обновление Docker Desktop сменило `name` named volume.

**Фикс:**
1. Использовать `docker compose` (без дефиса).
2. `docker compose down -v && docker compose --profile scan up` (создаст volumes заново; **внимание:** это сотрёт кэши БД).

### 1.4. `Workspace still starting`

**Причина.** Это сообщение от Cowork-режима, не от docker. Если действительно от docker — обычно WSL2 backend не успел подняться.

**Фикс.** Подождать 5–10 сек, повторить. Если не помогает: `wsl --shutdown && wsl` (всё закроется и перезапустится).

---

## 2. Обновление DB

### 2.1. `update grype` падает с `EXIT_ALL_SOURCES_FAILED` (exit 2)

**Симптом.** В `artifacts/provenance/grype.json` все `attempted_sources` имеют `failures[].reason`.

**Диагностика.** Прочитайте `failures[].reason`:

| reason | Что делать |
|---|---|
| `dns_or_network_unavailable` | Проверьте `proxy-status` и `host.docker.internal` (см. §5) |
| `http_4xx_non_retryable` | Чаще всего 404 — URL зеркала устарел, обновите `feed_sources.yaml.grype.upstream_update_urls` |
| `auth_failure` | Токен в `auth_env` не установлен или истёк |
| `checksum_mismatch` | Сетевой MITM или повреждённая загрузка — попробуйте другой источник |
| `stale_data` | Источник вернул архив, старше `max_allowed_built_age` — fall-through к следующему |
| `invalid_schema` | Указан `oci://` для Grype, который понимает только HTTP listing — поправьте YAML |

**Фикс.** Включите дополнительный fallback-источник в `grype.upstream_update_urls` или активируйте корпоративное зеркало в `custom_sources.entries`.

### 2.2. `update cve-bin-tool` всегда уходит в `last-known-good`

**Симптом.** В логах `cve-bin-tool updater fell back to last-known-good database`, exit 0.

**Причина.** Либо нет валидного `NVD_API_KEY`, либо upstream NVD недоступен, либо timeouts.

**Фикс.**
1. Заведите `NVD_API_KEY` (бесплатно на nvd.nist.gov) и пропишите в `.env`.
2. Поднимите `CVE_BIN_TOOL_UPDATE_TIMEOUT_SECONDS` (дефолт 420 сек) для медленных каналов.
3. Если стенд air-gapped — это **нормальное** поведение, ничего не чините. См. `docs/airgap.md`.

### 2.3. `cve.db is stale` после `audit`

**Симптом.** `audit cve-bin-tool-db` отвечает `overall_status: fail`, в `failures` строка `cve.db is stale: age_hours=X exceeds max_cache_age=Y`.

**Фикс.**
- Запустить `update cve-bin-tool`.
- В airgap — доставить свежий bundle.
- Или (только осознанно) расширить `max_cache_age` в `feed_sources.yaml.cve_bin_tool.db_audit`.

---

## 3. Сканирование

### 3.1. Syft нашёл 0 components

**Симптом.** В итоговом отчёте `Syft components: 0`, в Consistency warnings — `syft: 0 components — extraction may not have run`.

**Причина.** Цель — архив, не распакованный до сканирования. Syft умеет читать `tar.gz` напрямую только в `--from oci-archive`/`docker-archive` режимах; для произвольного `.zip`/`.tar.gz`/`.rpm`/`.deb` нужна distinct extract-фаза.

**Фикс.** Либо `scripts/run-scan.sh -t archive.tar.gz -e` (флаг `-e` включает extract), либо вызов `scripts/scan_archive.sh archive.tar.gz`. На Windows: `run-scan.ps1 -Extract`.

### 3.2. cve-bin-tool 0 findings + `timeout.flag`

**Симптом.** `artifacts/reports/cve-bin-tool/report.json` это `[]`, в той же папке появился `timeout.flag` с `timed_out_after=N`.

**Причина.** scan превысил `CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS`.

**Фикс. По степени радикальности:**
1. **SBOM fast-path.** Установите `CVE_BIN_TOOL_AUTO_SBOM=1` (по умолчанию уже 1) — cve-bin-tool прочитает `artifacts/sbom/cyclonedx.json` вместо binary scan.
2. **Pre-filter.** Set `CVE_BIN_TOOL_MAX_FILE_MB=128` чтобы пропустить файлы крупнее 128 МБ.
3. **Checkers.** `CVE_BIN_TOOL_CHECKERS=go,rust` — ограничить regex-checker'ы до релевантных языков. Auto-detect это уже делает для pure-Go целей.
4. **Увеличить таймаут.** `CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS=3600`.
5. **Параллелизм.** `CVE_BIN_TOOL_PARALLEL` в cve-bin-tool 3.4 является no-op; не используйте его как рычаг ускорения.

### 3.3. Trivy экспоненциально медленный на bind-mount'ах

**Симптом.** На Windows `trivy fs /scan-target` идёт > 20 мин для целей 1–2 ГБ.

**Причина.** 9P bind-mount NTFS → контейнер. Каждое `stat()`/`open()` — round-trip.

**Фикс.**
- Перенести цель внутрь WSL ext4 (`\\wsl$\Ubuntu\samples\…`) и указать SCAN_TARGET_HOST на путь там.
- Применить Defender exclusions (`scripts/windows/setup-defender-exclusions.ps1`).
- Активировать `docker-compose.windows.override.yml` через `COMPOSE_FILE`.

### 3.4. grype-scanner стартует, но падает с `connection refused`

**Симптом.** Логи `grype-scanner` показывают `dial tcp ... :8080: connection refused`.

**Причина.** `grype-static` не успел подняться или упал. С Phase 1.6 в compose есть `depends_on: grype-static: condition: service_healthy`, но healthcheck сам по себе может стабилизироваться 5–20 сек.

**Фикс.**
- `docker compose --profile scan logs grype-static` — посмотреть, поднялся ли HTTP-сервер.
- Если active-каталог пуст: `docker compose --profile update run --rm grype-updater` сначала.

---

## 4. Отчёт

### 4.1. `report-collector` падает с `missing required scan artifacts`

**Причина.** Один из обязательных JSON отсутствует — обычно сканер сам не отработал.

**Фикс.**
- `ls artifacts/reports/{grype,trivy,cve-bin-tool} artifacts/sbom` — что есть, чего нет.
- Перезапустить недостающий сканер: `docker compose --profile scan run --rm <name>`.

### 4.2. В отчёте «0 findings» при заведомо уязвимом образе

**Диагностика — пошагово.**
1. `wc -c artifacts/sbom/syft.json` — не пуст ли SBOM. Если 0 / `{}` — Syft не нашёл компонентов, см. §3.1.
2. `python -m json.tool artifacts/reports/grype/report.json | head` — есть ли `matches`. Если нет — DB Grype не активна.
3. `python -m resilient_updates.cli db-status grype --path /var/lib/resilient-db/grype/active` — `warning: true`? тогда `update grype`.

### 4.3. В шапке отчёта неправильный номер кейса

**Симптом.** В первой строке Markdown указан `CYBERSEC-UNKNOWN` или не тот тикет.

**Причина.** Runner не получил `-CaseId` / `--case-id` и не смог найти `CYBERSEC-\d+`
в пути к цели.

**Фикс.** Передайте номер явно:

```powershell
.\scripts\windows\run-scan.ps1 -Target "D:\samples\app.zip" -CaseId CYBERSEC-12080 -Clean
```

```sh
./scripts/run-scan.sh -t /path/to/app.zip --case-id CYBERSEC-12080 -c
```

---

## 5. Сеть / прокси

### 5.1. `proxy-status` показывает все цепочки `down`

**Диагностика.**
```sh
docker compose run --rm db-admin proxy-status --force
docker compose logs proxy-xray tinyproxy
docker compose exec proxy-xray sh -c 'echo > /dev/tcp/127.0.0.1/1080 && echo OK'
```

**Возможные причины.**
- Sidecar не поднят — проверьте `COMPOSE_PROFILES=…,proxy`.
- `xray` outbound не настроен (placeholder `host.docker.internal:1080` указывает на отсутствующий v2rayN на хосте).
- WireGuard sidecar не поднят (профиль `vpn`), а цепочка `via-vpn` его требует.

**Фикс.** Поправить `configs/xray/config.json` outbounds или цепочки в `feed_sources.yaml.proxy.chains`. См. `docs/network-design.md`.

### 5.2. `127.0.0.1` не доступен из контейнера

Классическая Docker-ошибка. См. `docs/proxy.md` раздел «Ключевая проблема: 127.0.0.1 внутри Docker ≠ 127.0.0.1 снаружи». Короткий ответ: используйте `host.docker.internal`.

### 5.3. Корпоративный TLS MITM-прокси отвергает соединения

**Симптом.** `SSL: CERTIFICATE_VERIFY_FAILED` при попытках достать upstream'ы.

**Фикс.** Прокинуть корпоративный CA в каждый сервис (`SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`) и собрать кастомный образ с этим CA в `/etc/ssl/certs/`. **Не отключайте** verify — это нарушает security baseline.

---

## 6. Windows-специфика

### 6.1. Defender exclusions «применились», но скан всё равно медленный

**Диагностика.** `Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess` — проверьте, что наши пути там. Если групповая политика домена их перетёрла — `gpresult /r /scope:computer | findstr Defender`.

**Фикс.** Согласовать exclusions с админом домена (нужно для всех файловых путей под `D:\…\el-sca-ansamble\` и `%LOCALAPPDATA%\Docker\wsl\…`).

### 6.2. `wsl: command not found` после установки

**Фикс.** Перезагрузка после `wsl --install`. Если не помогает — Windows Features → проверить «Virtual Machine Platform» и «Windows Subsystem for Linux».

### 6.3. Docker Desktop крутится с CPU 90 %+, но контейнеры пусты

**Причина.** WSL2 indexing / Defender real-time scan на NTFS bind-mount'ах.

**Фикс.** Запустите `setup-defender-exclusions.ps1`, активируйте `docker-compose.windows.override.yml`, перенесите hot paths в ext4 (см. `docs/windows-powershell.md` §6).

---

## 7. CI / тесты

### 7.1. `pytest` падает с `ModuleNotFoundError: resilient_updates`

**Причина.** Запущено не из корня репозитория, либо `PYTHONPATH` не настроен.

**Фикс.** `cd <repo>` и `python -m pytest`. На Windows: `Set-Location <repo>; python -m pytest`.

### 7.2. CI job `lint-docker` валится на DLxxxx

**Фикс.** Если хадолинтовое правило применимо — поправить Dockerfile. Если это false positive в нашем контексте — добавить ID в `.hadolint.yaml -> ignored:` с обоснованием в комментарии.

---

## 8. Эскалация

Если ни один из пунктов не подошёл:

1. Соберите `artifacts/provenance/*.json` за неудачный run + `docker compose logs > debug.log` + `docker compose config > compose-flat.yml`.
2. Зафиксируйте версии: `docker --version`, `docker compose version`, `python -V`, образ-тэги из `docker images | grep -E 'trivy|grype|syft|cve-bin-tool'`.
3. Откройте Issue (или приватный канал для security-incident'ов, см. `docs/security-notes.md` §7).
