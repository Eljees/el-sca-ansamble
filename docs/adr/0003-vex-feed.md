# ADR-0003: VEX-фид — подавление findings через Trivy `--vex`

- Status: Proposed
- Date: 2026-05-31
- Decision owners: SCA-pipeline team
- Связанные документы: [docs/custom-sources.md](../custom-sources.md),
  [docs/architecture.md](../architecture.md),
  [adr/0001-wrapper-first.md](0001-wrapper-first.md)

## Context

`configs/feed_sources.yaml` уже объявляет секцию `trivy.vex_repositories`
(пример — `internal-vex-hub`), `source_policy.build_sources` маппит слой
`trivy-vex → vex_repositories`, а `healthcheck.run_healthcheck` с этого пасса
пробит слой `trivy-vex`. Но **нигде в пути сканирования VEX не применяется**:
`grep -RIn -- '--vex'` по `scripts/`, `configs/`, `resilient_updates/` пуст.

Итог: VEX-источник конфигурируется и диагностируется, но на результат скана
не влияет — findings, которые поставщик пометил «not_affected / fixed»,
по-прежнему попадают в отчёт. Это шум и ложные срабатывания для оператора.

Особенность: db/java-db/checks-слои Trivy — это OCI-репозитории, которые
Trivy тянет сам по `--db-repository <url>`. VEX-хаб (`internal-vex-hub`) —
это API-эндпойнт, а `trivy --vex` принимает **локальный файл/каталог**
(OpenVEX / CSAF / CycloneDX-VEX), а не произвольный URL. Значит VEX-документ
надо предварительно **скачать** и положить на диск.

## Decision

Применяем «wrapper-first»-подход (ADR-0001): VEX-документ проходит тот же
устойчивый конвейер, что и БД-слои — fallback-загрузка → atomic publish →
provenance → offline-LKG, после чего `render-flags trivy` отдаёт Trivy путь
к опубликованному файлу через `--vex`.

### Компонент 1 — Acquisition (новый модуль `resilient_updates/vex.py`)

`fetch_vex(config, *, session=None) -> dict` :

- `sources = build_sources(config, "trivy", "trivy-vex")` (уже работает);
- `attempt_sources(...)` качает документ (тот же fallback/retry, что и DB);
- atomic-publish в `<trivy cache_dir>/vex/<source-name>.<ext>`
  (`atomic_publish` / `_io`), `<ext>` по `format`;
- `write_provenance(artifacts/provenance/trivy-vex.json, …)` — какой документ,
  hash, источник, timestamp;
- offline: если сеть недоступна, но опубликованный LKG-файл свежий
  (`require_fresh_hours`) — используем его, иначе `used_last_known_good=true`.

CLI: новый под-парсер `update vex` (или ветка в существующем `update`,
по аналогии с `update trivy`), вызывающий `fetch_vex`.

### Компонент 2 — Application (`cli._render_trivy_flags`, cli.py:141)

Добавить после цикла checks (cli.py:148):

```python
vex_dir = Path(config["trivy"]["cache_dir"]) / "vex"
if config.get("trivy", {}).get("vex_policy", {}).get("enabled") and vex_dir.is_dir():
    for doc in sorted(vex_dir.glob("*")):
        if doc.is_file():
            parts.append(f"--vex {doc}")
```

Если VEX не сконфигурирован / каталог пуст — список флагов не меняется
(полная обратная совместимость, нулевой риск для существующих сканов).

### Компонент 3 — Config (`configs/feed_sources.yaml`, секция `trivy`)

```yaml
  vex_repositories:
    - name: internal-vex-hub
      url: "https://vex.example.invalid/api"
      format: openvex          # openvex | csaf | cyclonedx   (НОВОЕ)
      priority: 10
      enabled: true
  vex_policy:                  # НОВОЕ
    enabled: true
    mode: apply                # apply (подавлять) | annotate (только метить)
    require_fresh_hours: 168   # старше — считать LKG несвежим
```

### Компонент 4 — Provenance / reporting

- `artifacts/provenance/trivy-vex.json` — какой VEX-документ применён, hash,
  источник, свежесть.
- `run_summary` дополнить полем `vex_applied` (имена документов).
- (Опционально, отдельная итерация) `scanner_diff`: дифф скана с VEX и без,
  чтобы показать «N findings подавлено VEX» — измеримая ценность фичи.

### Компонент 5 — Tests

- `test_cli`: `render-flags trivy` отдаёт `--vex <file>` при наличии файла в
  `<cache>/vex/` и `vex_policy.enabled`; **не** отдаёт при пустом каталоге или
  `enabled:false` (контракт обратной совместимости).
- `test_vex` (новый): `fetch_vex` — успех, fallback, offline-LKG, битый формат;
  использовать существующий `tests/mock_feed_server`.
- `test_healthcheck`: `trivy-vex` уже в цикле проб (этот пасс) — добавить
  ассерт на ключ `trivy-vex` в результате.

## Phasing

| Фаза | Объём | Риск | Acceptance |
|---|---|---|---|
| P1 | Config-схема + хук в `_render_trivy_flags` + тесты контракта | нулевой (no-op без VEX) | `render-flags` отдаёт `--vex` только когда файл есть |
| P2 | `vex.py` acquisition + CLI `update vex` + atomic publish + provenance | низкий | `update vex` публикует файл и пишет provenance; offline-LKG работает |
| P3 | `run_summary.vex_applied`, docs (`custom-sources.md`, `operations.md`), опц. `scanner_diff` suppression-count | низкий | отчёт показывает применённый VEX; (опц.) число подавленных findings |

## Consequences

**Плюсы:** меньше ложного шума в отчётах; VEX проходит ту же устойчивую
загрузку и provenance, что и БД (единый механизм, ADR-0001); обратная
совместимость — без VEX поведение не меняется.

**Минусы / риски:** формат VEX-документа поставщика должен соответствовать
`format`; рассинхрон VEX и БД может подавить актуальную уязвимость — поэтому
`require_fresh_hours` и режим `annotate` для аудита перед `apply`.

**Альтернатива (отклонена):** нативные «VEX Repositories» Trivy (`--vex repo`
+ `repository.yaml`) — требует, чтобы хаб реализовывал repo-протокол Trivy;
у `internal-vex-hub` это просто API, поэтому fetch-then-file универсальнее.
