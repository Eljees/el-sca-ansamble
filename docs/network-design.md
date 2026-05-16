# Сетевая архитектура — sidecar-стек

Этот документ описывает, как el-sca-ansamble выходит в интернет через цепочки прокси и опциональный VPN-туннель. Старый плоский режим (`HTTP_PROXY=…` или `proxy.http: …` в `feed_sources.yaml`) полностью сохранён — sidecar'ы и YAML-цепочки добавлены как опциональный слой поверх.

См. также:
- `docs/proxy.md` — введение в proxy-переменные, `host.docker.internal`, выбор схем SOCKS5/HTTP.
- `docs/adr/0002-proxy-sidecar.md` — почему именно `tinyproxy + xray`, какие альтернативы рассмотрены.
- `configs/feed_sources.yaml` — текущая схема `proxy.chains / policies / per_source`.
- `configs/xray/config.json`, `configs/tinyproxy/tinyproxy.conf` — реальные конфиги sidecar'ов.

---

## 1. Топология

```
                 ┌────────────────── Docker network "scanner-net" ──────────────────┐
                 │                                                                   │
   scanners ───► │  tinyproxy:8888  ──►  proxy-xray:1080  ──►  upstream chain  ──►  WAN
   (trivy,       │   HTTP/HTTPS front     SOCKS5 + routing      (corp proxy /        │
   grype-        │   (фронт-точка для     (xray-core; чертит    v2rayN /             │
   updater,      │    HTTP_PROXY)         outbound rules)        WireGuard /         │
   syft-sbom,    │                                                direct …)          │
   cve-bin-                                                                          │
   tool-                                                                             │
   updater,                                                                          │
   resilient-                                                                        │
   updater)      │                            (опционально)                           │
                 │                       wg0:wireguard sidecar                         │
                 │                       — для traffic, идущего "под VPN"            │
                 └───────────────────────────────────────────────────────────────────┘
```

**Базовая идея.** Внутри `scanner-net` существует ровно одна стабильная точка выхода — `tinyproxy:8888` (HTTP/HTTPS) и `proxy-xray:1080` (SOCKS5). Чем бы дальше ни ходил трафик (корпоративный прокси, v2rayN на хосте, VPN), эту маршрутизацию знает только sidecar `proxy-xray`. Сканеры всегда обращаются к одному и тому же DNS-имени — `tinyproxy` или `proxy-xray`.

**Почему два sidecar'а, а не один.**

- `Trivy`, `Grype`, `Syft` написаны на Go и читают только `HTTP_PROXY` / `HTTPS_PROXY`. SOCKS5 они не понимают.
- `cve-bin-tool` ходит через Python `requests`. Понимает и SOCKS5 (через PySocks), и HTTP-прокси.
- `curl`/`wget` в bootstrap-скриптах — оба варианта.

`tinyproxy` даёт Go-сканерам ту самую HTTP-точку, `xray` решает, куда уйдёт пакет дальше (SOCKS5-upstream к v2rayN, прямое соединение, цепочка VLESS/Shadowsocks/Trojan).

---

## 2. Когда включать

| Сценарий | Профили compose | Что в `.env` |
|---|---|---|
| Локальный прогон без прокси | `scan`, `update` | `HTTP_PROXY=`, `HTTPS_PROXY=`, `ALL_PROXY=` |
| v2rayN/Xray уже стоит на Windows-хосте | `scan`, `update` | `ALL_PROXY=socks5h://host.docker.internal:1080` |
| Корпоративный HTTP-прокси | `scan`, `update` | `HTTP_PROXY=http://proxy.corp.example:3128` |
| **Sidecar-цепочка** (рекомендуется для сложной сети) | `scan,update,proxy` | `HTTP_PROXY=http://tinyproxy:8888`, `ALL_PROXY=socks5h://proxy-xray:1080` |
| Sidecar + VPN | `scan,update,proxy,vpn` | то же + `configs/wireguard/wg0.conf` |

Стандартная команда запуска с цепочкой:

```sh
COMPOSE_PROFILES=scan,update,proxy docker compose up -d
```

Sidecar'ы стартуют в `restart: unless-stopped`, поэтому переживают перезапуск отдельных сканеров.

---

## 3. YAML-схема цепочек

Файл `configs/feed_sources.yaml`, секция `proxy`:

```yaml
proxy:
  no_proxy: "localhost,127.0.0.1,grype-static,tinyproxy,proxy-xray"
  default_chain: corp

  chains:
    direct:
      description: "No proxy"
      hops: []
    corp:
      hops:
        - role: front
          url:  "http://tinyproxy:8888"
        - role: socks
          url:  "socks5h://proxy-xray:1080"
    via-vpn:
      hops:
        - role: vpn
          interface: wg0
        - role: socks
          url:  "socks5h://proxy-xray:1080"

  policies:
    healthcheck_url: "https://www.google.com/generate_204"
    healthcheck_timeout_seconds: 5
    healthcheck_ttl_seconds: 60
    failover_order: ["corp", "via-vpn", "direct"]
    retry_per_chain: 2

  per_source:
    - source: anchore-public-db
      chain: corp
    - source: primary-mirror
      chain: corp
```

Терминология.

- **Hop** — один шаг цепочки. Поле `url` подключается к `requests.Session.proxies`; поле `interface` (для роли `vpn`) — только метаданные, по нему ProxyRouter не поднимает туннель сам.
- **Entry URL** — `url` ПОСЛЕДНЕЙ hop'ы в списке с непустым `url`. Это адрес, на который сканеры физически коннектятся первым. Цепочка из примера выше: scanner → `http://tinyproxy:8888` → внутри docker → `socks5h://proxy-xray:1080` → xray уходит в свой `outbound`. С точки зрения сканера entry — `tinyproxy:8888`, всё остальное прозрачно.
- **per_source** — точечная привязка. Имя источника — это `name:` из любой `trivy.*_repositories[]` / `grype.upstream_update_urls[]` / `cve_bin_tool.mirrors[]` / `custom_sources.entries[]`.

ProxyRouter сначала смотрит `per_source`, потом `default_chain`. Если выбранная цепочка нездорова, обходит по `failover_order`, далее по `direct`.

Старая плоская форма (`proxy.http: …`, `proxy.https: …`) остаётся валидной — она преобразуется в анонимную цепочку при загрузке.

---

## 4. Диагностика

```sh
# Со стороны хоста (через resilient-updater)
docker compose run --rm db-admin proxy-status
```

Команда возвращает JSON вида:

```json
{
  "status": "ok",
  "chains": {
    "corp":    {"status": "ok",      "latency_ms": 184, "entry_url": "http://tinyproxy:8888"},
    "via-vpn": {"status": "down",    "error": "ConnectTimeoutError(\"...wg0...\")"},
    "direct":  {"status": "ok",      "latency_ms": 4012, "entry_url": null}
  }
}
```

И параллельно пишет `artifacts/provenance/proxy.json` с тем же содержимым плюс блок `policies`, `default_chain`, `per_source`, `no_proxy`. Файл забирает `report-collector` и включает в итоговый отчёт.

Exit code:

- `0` — хотя бы одна цепочка `ok` (даже если остальные `down`).
- `2` (`EXIT_ALL_SOURCES_FAILED`) — ни одна цепочка не отвечает; пайплайн дальше не имеет смысла.

Полезные ручные проверки (по-прежнему работают):

```sh
# Что видит сама сессия Python-слоя
docker compose run --rm db-admin healthcheck

# Прокси изнутри произвольного контейнера
docker run --rm --network el-sca-ansamble_scanner-net curlimages/curl:latest \
  curl -fsSv -x http://tinyproxy:8888 https://www.google.com/generate_204

# Xray (SOCKS5 inbound)
docker run --rm --network el-sca-ansamble_scanner-net curlimages/curl:latest \
  curl -fsSv -x socks5h://proxy-xray:1080 https://www.google.com/generate_204
```

---

## 5. Когда правильнее не использовать sidecar'ы

- **Прокси через явный системный `HTTP_PROXY` на Linux-хосте, без Docker-Desktop.** Тогда родной env-механизм dockerd проще, sidecar только усложняет.
- **Изолированный/offline сценарий.** Если внутри `scanner-net` ничего не должно ходить наружу — оставляем `direct` и `default_chain: direct`.
- **CI-runner на изолированной машине с одним прокси.** Никакой failover-логики не нужно, лучше плоская форма.

Sidecar-стек оправдан, когда хотя бы одно из:

1. Несколько прокси (корпоративный + личный + VPN).
2. Часть источников должна ходить через VPN, остальные — нет.
3. Внутри сети периодически отваливается то корпоративный, то домашний прокси — нужен автоматический failover без редактирования `.env`.

---

## 6. Безопасность

- UUID/credentials VLESS, WG private key, NVD API key — только в `.env` или Docker secrets, **не в `configs/*.yaml`** и не в git.
- `tinyproxy.conf` ограничивает `Allow` блоком `172.16.0.0/12` плюс `127.0.0.1`. Если ваш bridge-сегмент попадает в другой диапазон, отредактируйте `Allow`. **Никогда не оставляйте `Allow 0.0.0.0/0`** при доступности sidecar-сети снаружи Docker.
- `xray` пишет логи на уровне `warning`. Если включаете `debug`, помните, что в логи попадают пути URL — следите, что `Authorization`-заголовки не утекают.
- Threat-model: компрометация `proxy-xray` ⇒ может перехватывать HTTP-трафик сканеров. Компрометация `tinyproxy` ⇒ то же. Защита: образы с фиксированными версиями, регулярные `docker pull`, изоляция compose-проекта от других docker-сетей.

---

## 7. Известные ограничения

- `proxy-xray` healthcheck сейчас простейший (`echo > /dev/tcp/127.0.0.1/1080`). Полноценный health endpoint (`api`) обещан в xray ≥ 1.9 — добавим после обновления образа.
- WG sidecar не route'ит трафик сканеров автоматически — для этого нужно либо переключить scanner-сервис на `network_mode: "service:wireguard"` (через `docker-compose.override.yml`), либо настроить `outbounds` в `configs/xray/config.json` с маршрутом `wg0`. Документ по этой связке появится отдельно.
- Failover между цепочками работает на уровне Python-слоя (`resilient_updates`). Go-сканеры пользуются единственным `HTTP_PROXY`, который им подсунули из `.env`/`x-proxy-env`; failover для них смысла не имеет (одна точка `tinyproxy`, дальше всё решает xray).
