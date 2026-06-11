# ADR-0007: обновление БД сканеров из любой точки

- Status: Accepted (P1 + автовыбор маршрута реализованы)
- Date: 2026-06-02 (обновлено 2026-06-11)
- Decision owners: SCA-pipeline team
- Связанные документы: [docs/network-design.md](../network-design.md),
  [docs/airgap.md](../airgap.md), [docs/proxy.md](../proxy.md),
  [adr/0002-proxy-sidecar.md](0002-proxy-sidecar.md)

## Context

Главная боль проекта — обновить БД сканеров (Trivy, Grype, cve-bin-tool/NVD)
из **любой** сетевой точки: корп-сеть с единственным прокси, домашний прямой
выход, цензурируемая сеть, рвущийся канал, полный air-gap. Фундамент уже есть:

- **fallback** (`fallback.py`) — мультиисточник, приоритеты, классификация
  ошибок (`classify_http_status`/`classify_exception`), ретраи, LKG;
- **прокси-цепочки** (`proxy_chain.py`) — именованные `chains` (`corp`/`via-vpn`/
  `direct`), `per_source` маппинг, `policies.failover_order`, VPN-сайдкар
  (WireGuard), xray+tinyproxy, healthcheck с TTL-пиннингом;
- **разнообразие источников** — Trivy: несколько OCI-репо; Grype: зеркала;
  cve-bin-tool: `nvd_modes: [json-mirror, api2, json-nvd]`; `custom_sources`;
- **зеркало/bundle** — `cvebt_export_bundle.sh`/`import`, `offline_policy`,
  `diagnose_cvebt_update.sh`.

Чего не хватает для «из любой точки»: (а) **видимости** — какой маршрут жив
прямо сейчас; (б) **закалки транспорта** под враждебные сети; (в) формального
**sneakernet** и (г) **per-source эскалации** прокси.

## Decision

Достроить «update from anywhere» поверх существующего fallback/proxy-слоя
шестью механизмами. Источник правды (`feed_sources.yaml`, ProxyRouter,
`build_sources`) не меняется — добавляем диагностику, транспортные опции и
sneakernet-обёртки.

### 1. `cli update-doctor` — карта достижимости

Зондирует каждую пару **(tool, layer) × chain** и печатает матрицу: какой
источник через какую цепочку отвечает (ok / 4xx / timeout / dns-fail), плюс
**рекомендованный маршрут per-tool**. Это actionable-расширение healthcheck:
оператор в новой точке видит «отсюда обновляйся через `via-vpn`, json-mirror жив,
ghcr недостижим». Сетевые вызовы инъектируемы → тестируется без сети.

### 2. Закалка транспорта (`fallback.fetch_bytes`)

- **Conditional GET** — слать `If-None-Match`/`If-Modified-Since` по
  сохранённому ETag; `304` ⇒ LKG свежий, не качаем зря;
- **Resumable/chunked** — `Range`-докачка при обрыве (переживать флапающий
  канал), потоковая запись во временный файл + atomic publish;
- **OCI registry-rewrite** — таблица `registry_mirrors` (`ghcr.io` → корп-
  зеркало) применяется к `--db-repository`/OCI-URL прозрачно.

### 3. DNS-обход

Опциональный DoH-резолвер / статическая `hosts`-карта в конфиге для доменов,
заблокированных на уровне DNS (частый корп-кейс). Применяется только к
источникам обновлений, не глобально.

### 4. Per-source эскалация прокси

Сейчас `failover_order` переключает цепочку для всего раннера. Добавить
эскалацию **на конкретном источнике**: corp → via-vpn → direct при его ошибке,
с запоминанием рабочей пары (source→chain) на TTL. Реализуется в
`attempt_sources` + ProxyRouter.

### 5. Sneakernet как первый класс — `cli bundle export|import`

Обёртка над `cvebt_export_bundle.sh`/`import` для **всех** инструментов: на
связанном хосте `bundle export` собирает БД (Trivy/Grype/cve-bin-tool) с
provenance + SHA-хешами в один каталог/архив → перенос (USB/файл) →
`bundle import` в air-gap с проверкой целостности и atomic publish. Закрывает
«точку» без сети совсем.

### 6. Censorship-обход

Параметризовать xray-сайдкар (VLESS/Reality/obfs) шаблоном
`configs/xray/config.json.example` + раздел в `docs/network-design.md`: как
поднять обфусцированный egress, когда обычный прокси/VPN режется DPI.

## Phasing

| Фаза | Объём | Риск | Acceptance |
|---|---|---|---|
| P1 ✅ | `cli update-doctor` — зондирование (tool×layer×chain) + матрица + рекомендация; тесты с инъекцией probe | низкий (read-only) | `update-doctor` печатает матрицу и per-tool маршрут на фикстуре без сети |
| P1.5 ✅ | `cli route-plan` + сервис `route-doctor` (зондирует ИЗНУТРИ scanner-net: сайдкары tinyproxy/xray, `host.docker.internal:<порт>`, direct) → пишет `route-plan.{json,env}`; per-tool выбор с HTTP-only для cve-bin-tool; авто-применение в `update_db`/`run_scan.sh` по умолчанию (откат на direct); `--write-xray` перенацеливает upstream xray на живой хост-прокси | низкий-средний (аддитивно, opt-out) | `route-plan` на фикстуре без сети выдаёт корректный per-tool план; cve-bin-tool никогда не получает SOCKS; round-trip json/env |
| P2 | транспорт: conditional GET (ETag), Range-resume, OCI registry-rewrite; тесты на моках | средний | повторный апдейт с актуальным ETag не качает; обрыв докачивается; ghcr→mirror переписывается |
| P3 | DoH/hosts-резолвер + per-source эскалация прокси + `cli bundle export/import` + xray-шаблон/доки | средний | bundle round-trip (export→import) с integrity-проверкой; эскалация запоминает рабочую пару |

## Consequences

**Плюсы:** оператор в любой точке получает карту «как обновиться» и
автоматический выбор живого маршрута; обновления переживают цензуру, DNS-
блок, рвущийся канал и полный air-gap; механизмы аддитивны к существующему
fallback.

**Минусы / риски:** DoH/registry-rewrite/обфускация расширяют конфиг и
поверхность — по умолчанию всё выключено, включается явно per-source;
censorship-обход может нарушать политики конкретной сети — это решение
оператора, документируем, не навязываем.

**Альтернатива (отклонена):** полагаться только на текущий `failover_order`.
Отклонено — он не даёт ни видимости (какой маршрут жив), ни per-source
эскалации, ни conditional/resume, ни формального sneakernet; «из любой точки»
требует именно диагностики + транспортной закалки.
