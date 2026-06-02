# Безопасность el-sca-ansamble

Этот документ собирает все security-considerations проекта в одном месте: секреты, аутентификация прокси, подпись DB-зеркал, threat-model sidecar-стека. Документ дополняет ADR-0002 (`docs/adr/0002-proxy-sidecar.md`), но фокусируется именно на эксплуатации.

---

## 1. Секреты — где живут и где нет

| Тип | Куда класть | Куда **не** класть |
|---|---|---|
| `NVD_API_KEY`, `NVD_API_KEY_FALLBACK` | `.env`, Docker secrets, CI-secret-manager | `feed_sources.yaml`, любые `*.md` |
| Учётки внутренних registry (`TRIVY_INTERNAL_REGISTRY_PASSWORD`, `SYFT_REGISTRY_PASSWORD`, `CVE_BIN_TOOL_MIRROR_TOKEN`, `GRYPE_CUSTOM_AUTH_TOKEN`) | `.env` через `*_env`-плейсхолдер в `custom_sources` | напрямую в `url:` поле |
| VLESS/Shadowsocks/Trojan UUID-ы из Xray | `configs/xray/config.json` (не коммитится — см. `.gitignore`) или env-переменные | в `feed_sources.yaml`, в логах |
| WireGuard private key | `configs/wireguard/wg0.conf` (gitignored) | где угодно ещё |
| Учётки корпоративного прокси | `HTTP_PROXY=http://user:pass@host:port` в `.env` (плюс URL-кодирование спец-символов) | в YAML, в shell history без `set +o history` |

**`.gitignore` гарантирует**: `.env`, `configs/wireguard/`, `configs/xray/*.local.json`, `docker-auth.json`, `comands.txt`. Перед коммитом — `git status` и контроль глазами. Pre-commit hook `check-added-large-files` отлавливает случайно подложенные ключи > 5 MB; для маленьких секретов используется `git-secrets` / `trufflehog` (не зависят от проекта, ставятся отдельно).

`custom_sources.entries[*]` принимает `auth_env: NAME` — Python-слой читает значение из `os.environ`. Никогда не подставляйте секрет прямо в URL внутри YAML.

---

## 2. Подпись и валидация баз уязвимостей

| База | Что валидируется | Что **не** валидируется |
|---|---|---|
| **Grype** | sha256 архива (через `listing.json.checksum`) + cog-cog возраст (`max_allowed_built_age`); запись активируется атомарно через `publish_directory()` | подпись GPG/Sigstore — Anchore не публикует подписи листингов на этом канале |
| **Trivy** | OCI-layer digest (через сам Trivy) — wrapper не делает второй проверки | ничего сверх |
| **cve-bin-tool** | целостность `cve.db` (sqlite read), минимальные счётчики строк по `data_source`, max cache age | подпись upstream'а |
| **Syft** | целостность контейнера | подпись |

Из этого следует: **wrapper защищает от испорченных архивов** (битый zstd, неполный download, протухание), но **не** от компрометации источника. Если злоумышленник подменит `listing.json` + контент с правильной sha256 — wrapper примет содержимое. Меры:

1. Зеркала, помеченные `trust_level: official` или `internal`, должны быть на HTTPS с проверкой TLS (на всех хопах в proxy-цепочке).
2. Для критичных установок включайте только `internal-*` зеркала в `*-repositories[]`/`upstream_update_urls`, остальные `enabled: false`.
3. Подменяемые зеркала (`enabled: false` по умолчанию в `custom_sources.entries`) включайте только при наличии корпоративного контроля.

`insecure_registry`, `disable_validation`, `ignore_signatures`, `allow_stale_forever` — четыре имени, которые **запрещены** в YAML; `validate_config` падает с явной ошибкой если что-то подобное появляется.

---

## 3. Прокси и threat-model sidecar-стека

См. ADR-0002 раздел Consequences. Кратко.

- Компрометация `tinyproxy` ⇒ MITM на HTTP-трафик сканеров (HTTPS-CONNECT прозрачен, но злоумышленник видит SNI/IP).
- Компрометация `proxy-xray` ⇒ MITM на всё, включая способность подменять `outbound`. Это и есть главная единая точка отказа цепочки.
- Компрометация `wireguard` ⇒ возможность подменять трафик "под VPN".

Меры:

1. **Никаких `Allow 0.0.0.0/0`** в `tinyproxy.conf` без явного периметра — текущий конфиг ограничен `172.16.0.0/12` плюс loopback.
2. **Только один путь наружу.** Xray принимает соединения только из `scanner-net` (docker network); внешние клиенты не маршрутизируются по умолчанию.
3. **Аудит**: `proxy-status` пишет полный лист цепочек и их состояние в `artifacts/provenance/proxy.json` каждый run.
4. **Обновление образов**: фиксируйте теги (`kalaksi/tinyproxy:1.11.2`, не `latest`), регулярно делайте `docker compose pull && docker compose build --no-cache`.
5. **TLS до прокси**: `https://`-фронты приветствуются; `socks5h://` использует remote DNS, что закрывает DNS-leak.

Логи `tinyproxy` (`LogLevel Info`) пишутся со схемой URL — Authorization-заголовки не логируются. Если включаете `LogLevel Connect/Debug` — проверьте, чтобы файл логов не попал в провенанс/артефакты.

---

## 4. Аутентификация в registry

`docker login` создаёт `~/.docker/config.json` или `docker-auth.json`. Для контейнеров — монтируйте read-only:

```yaml
volumes:
  - ${HOME}/.docker/config.json:/root/.docker/config.json:ro
```

Никогда не коммитьте `docker-auth.json` (запрещено `.gitignore`). Для CI используйте `docker/login-action` со secret-binding'ом (`secrets.DOCKER_TOKEN`), не plain env.

Syft использует `SYFT_REGISTRY_USERNAME` / `SYFT_REGISTRY_PASSWORD`; они проходят через `x-proxy-env` без логирования.

---

## 5. Last-known-good как страховка, не как индульгенция

Pipeline принципиально fail-closed:

- `grype.last_known_good.max_age` — окно, в течение которого допустим возврат к старой DB. Свыше — exit code 4 (`EXIT_STALE_REJECTED`).
- `cve_bin_tool.db_audit.max_cache_age` — то же для cve-bin-tool, кроме того проверяется `min_entries` по обязательным data sources.
- `validate_age: true` и `validate_hash: true` в `grype.validation` — **обязательны**; конфиг с `false` отвергается `validate-config`.

Если по политике (например, в air-gapped среде) допустим бесконечный stale — это **должно** быть отдельным профилем `offline-only` с честным `fail_closed_if_required_missing: false`. Не выключайте проверки молча.

---

## 6. Чеклист перед прод-деплоем

- [ ] `.env` не в git (проверьте `git check-ignore .env`).
- [ ] `configs/wireguard/wg0.conf`, `configs/xray/config.json` (если содержат UUID) не в git.
- [ ] `docker compose config` проходит без warning'ов.
- [ ] `python -m resilient_updates.cli validate-config` отвечает `{"status":"ok"}`.
- [ ] `python -m resilient_updates.cli proxy-status` показывает все рабочие цепочки `ok`.
- [ ] Defender exclusions применены (`scripts/windows/setup-defender-exclusions.ps1`).
- [ ] Хотя бы один внешний `enabled: true` источник — на HTTPS.
- [ ] Аудит cve-bin-tool DB прошёл (нет `fail_closed_if_required_missing: false`).
- [ ] Версии образов в `docker-compose.yml` зафиксированы тэгом (`v0.112.0`, не `latest`).
- [ ] `requirements.txt` синхронизирован с `requirements.in` (`make lock`).
- [ ] Все изменения проходят `make lint && make test`.

---

## 7. Дашборд (ADR-0006) — сетевой сервис

Дашборд (`cli dashboard` / compose-профиль `dashboard`) — единственный
компонент стека, который **слушает сеть**. Поэтому отдельные правила:

- **Read-only.** Сервис только читает `artifacts/`; в v1 нет мутаций, нет
  запуска сканов из UI. В compose том смонтирован как `:ro`.
- **Loopback по умолчанию.** `cli dashboard` биндится на `127.0.0.1`; compose
  публикует порт как `127.0.0.1:8080:8080`. Не выставляйте на `0.0.0.0` без
  необходимости.
- **Аутентификации нет в v1.** Это внутренний инструмент. Для выставления
  наружу — **только за reverse-proxy с auth** (nginx/Caddy + basic/OIDC); сам
  сервис аутентификацию не выполняет.
- **Секреты.** Дашборд отдаёт provenance/summary/reports — убедитесь, что в
  этих артефактах нет ключей (NVD-ключи живут в `.env.local`, в provenance не
  попадают). Проверяйте перед публикацией.
- **Зависимости.** Добавляет первые веб-зависимости (`fastapi`, `uvicorn`) —
  обязателен lock с хешами (`make lock`) перед сборкой образа.

## 8. Отчётность об уязвимостях самого стека

Если найдёте уязвимость в `resilient_updates` или в обвязке — заведите Issue с пометкой `security:` (либо приватный канал, если есть). Не публикуйте PoC в публичных каналах до фикса.
