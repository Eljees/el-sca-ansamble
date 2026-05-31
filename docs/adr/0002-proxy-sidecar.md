# ADR-0002: sidecar proxy-стек (tinyproxy + xray) + опциональный WG

- Status: Accepted
- Date: 2026-05-16
- Decision owners: SCA-pipeline team
- Связанные документы: [docs/network-design.md](../network-design.md), [docs/proxy.md](../proxy.md).

## Context

К моменту версии v3.0 проект жил на двух плоских механизмах прокси:

- `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` через `x-proxy-env` в `docker-compose.yml` — для Go-сканеров и curl-обвязок внутри контейнеров.
- Секция `proxy.http` / `proxy.https` / `proxy.no_proxy` в `configs/feed_sources.yaml` — только для Python-слоя (`resilient_updates`).

Этого хватало, пока:

1. Прокси один.
2. Источники доступны через один и тот же прокси.
3. Не требуется failover между несколькими маршрутами или сегментом, доступным только через VPN.

Реальная среда (см. `DEPLOYMENT_GUIDE_EXAMPLE.md`) такого не даёт:

- Доступ к публичным зеркалам идёт через v2rayN на Windows-хосте (SOCKS5 на `host.docker.internal:1080`).
- Часть внутренних зеркал лежит за корпоративным HTTP-прокси.
- Иногда нужно ходить «под VPN» (WireGuard) — например, к закрытому on-prem registry.
- Сложная цепочка `scanner → corp proxy → VPN → endpoint` сегодня не выражается в одном `HTTP_PROXY`.

## Decision

Ввести **sidecar proxy-стек** внутри docker-сети `scanner-net`:

1. **`proxy-xray`** (`ghcr.io/xtls/xray-core:latest`) — единственное место, где живут все outbound-маршруты (SOCKS5 upstream к v2rayN, freedom-direct, VLESS/Shadowsocks/Trojan, …). Внутри сети поднимает:
   - SOCKS5 inbound на `proxy-xray:1080`,
   - HTTP inbound на `proxy-xray:8118` (резерв),
   - dokodemo-door на `127.0.0.1:18080` для healthcheck'а.
2. **`tinyproxy`** (`kalaksi/tinyproxy:1.11.2`) — HTTP/HTTPS front для Go-сканеров (Trivy/Grype/Syft), которые читают только `HTTP_PROXY`. Слушает `tinyproxy:8888`, апстрим — `socks5 proxy-xray:1080`.
3. **`wireguard`** (`linuxserver/wireguard:latest`) — опциональный WG-туннель. Включается профилем `vpn`, конфиг — в `configs/wireguard/wg0.conf`. ProxyRouter не управляет туннелем напрямую — `vpn`-hop в цепочке метаданные; реальный трафик уходит в WG через xray-outbound или `network_mode: "service:wireguard"`.

Поверх sidecar'ов — **YAML-схема цепочек** в `configs/feed_sources.yaml`:

```yaml
proxy:
  default_chain: corp
  chains:
    direct:   {hops: []}
    corp:     {hops: [{role: front, url: "http://tinyproxy:8888"},
                       {role: socks, url: "socks5h://proxy-xray:1080"}]}
    via-vpn:  {hops: [{role: vpn,   interface: wg0},
                       {role: socks, url: "socks5h://proxy-xray:1080"}]}
  policies:
    failover_order: ["corp", "via-vpn", "direct"]
    healthcheck_url: "https://www.google.com/generate_204"
    healthcheck_ttl_seconds: 60
  per_source:
    - {source: anchore-public-db, chain: corp}
```

Логика выбора цепочки реализована в новом модуле `resilient_updates/proxy_chain.py` (класс `ProxyRouter`). CLI-команда `proxy-status` пингует все цепочки и пишет `artifacts/provenance/proxy.json`.

Все три sidecar-сервиса выключены по умолчанию (`profiles: ["proxy"]`, `["vpn"]`). Существующие сетапы не ломаются; sidecar-цепочка включается одним `COMPOSE_PROFILES=…,proxy …`.

## Consequences

### Положительные

- Сканеры обращаются к одной стабильной точке (`tinyproxy:8888` / `proxy-xray:1080`) внутри docker-сети — нет больше путаницы `127.0.0.1` vs `host.docker.internal`.
- Цепочки прокси и failover декларативно описаны в YAML; для смены маршрута достаточно отредактировать `feed_sources.yaml`.
- Sidecar добавляет «единое место для outbound-секретов» (VLESS UUID, WG key) — никаких сканеров с прошитой credentials.
- Healthcheck цепочек кэшируется на TTL — нет хаотичного пинга upstream'а в каждом запросе.
- Новый CLI `proxy-status` встроен в общую provenance-логику, отчёт автоматически фиксирует, какая цепочка использовалась.

### Отрицательные

- +2 контейнера в стандартном «proxy»-режиме (~50 MB RAM каждый). Незаметно на десктопе, но в CI-okтава может потребовать +memory.
- Two-step setup: нужно и поднять профиль, и проставить env-переменные. Документ `docs/network-design.md` это объясняет.
- Зависимость от стабильности upstream-образов `ghcr.io/xtls/xray-core` и `kalaksi/tinyproxy`. Закрепляем тэгом, обновляем по плану (см. Phase 4).

## Alternatives considered

- **HAProxy front вместо tinyproxy.** Мощнее, но не понимает HTTP CONNECT semantics так аккуратно «из коробки» и требует больше конфиг-кода.
- **Privoxy.** Хорош в чёрно-белых списках, но slowly maintained, не имеет встроенного SOCKS-upstream без хака.
- **iptables-маршрутизация в `scanner-net`.** Прозрачно для сканеров, но требует root-привилегий и `--cap-add NET_ADMIN`. Хрупко на Docker Desktop под Windows.
- **`network_mode: "service:vpn"` для всех сканеров.** Жёсткая привязка ко включённому VPN; нет ни failover, ни диагностики «работает прокси или нет».
- **`gluetun`-стиль ИТ-в-одном-контейнере.** Хороший вариант, но менее знаком команде; xray покрывает нужные outbound-протоколы.

## Migration

1. Старая плоская форма `proxy.http: …` сохранена; `validate_proxy_config()` поддерживает оба стиля.
2. Пользователь, который хочет sidecar-цепочку, добавляет `COMPOSE_PROFILES=…,proxy` и одну секцию `proxy.chains` в `feed_sources.yaml`.
3. Если ничего не менять — поведение остаётся ровно прежним.

## Open questions

- Включить `tinyproxy` в `default`-профиль, чтобы поднимался автоматически при `docker compose up`? — Пока нет: усложняет offline-кейс. Решение пересмотреть после первой недели прод-использования.
- Метрики (Prometheus exporter на tinyproxy/xray) — оставлено на Phase 5.
