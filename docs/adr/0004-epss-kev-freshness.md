# ADR-0004: EPSS/KEV freshness (TTL) для enrichment

- Status: Proposed
- Date: 2026-06-01
- Decision owners: SCA-pipeline team
- Связанные документы: [docs/architecture.md](../architecture.md),
  [adr/0003-vex-feed.md](0003-vex-feed.md)

## Context

EPSS- и KEV-обогащение **уже реализовано и подключено**:

- `enrichment.load_epss_scores` / `load_kev_set` читают кэш на диске
  (`<DB_ROOT>/epss/epss_scores-current.csv`,
  `<DB_ROOT>/kev/known_exploited_vulnerabilities.json`);
- `enrichment.enrich_findings` (enrichment.py:169) вызывается из
  `reporting.build_report` (reporting.py:355-357);
- отчёт добавляет колонки `EPSS` / `KEV`, тесты в `tests/test_enrichment.py`.

Чего **нет**: проверки свежести. EPSS-скоры FIRST.org обновляются ежедневно,
KEV CISA — несколько раз в неделю. Если сид давно не запускался (air-gap,
сбой обновления), `enrich_findings` молча подставит **протухшие** значения, и
триажер отсортирует findings по устаревшей вероятности эксплуатации, не зная
об этом. `mtime` файла уже считывается (enrichment.py:88-89), но нигде не
сравнивается с порогом и не сигнализируется.

## Decision

Добавить TTL-осведомлённость как **additive** слой: читать `mtime` EPSS/KEV-
файлов, сравнивать с настраиваемым порогом и проводить вердикт о свежести в
отчёт и provenance. При отсутствии файлов или политики — поведение прежнее
(graceful degradation, как и сейчас).

### Компонент 1 — Freshness-хелпер (`enrichment.py`)

```python
def source_freshness(roots=None, *, max_age_hours: float = 24.0) -> dict[str, Any]:
    """Вернуть {'epss': {...}, 'kev': {...}} с age_hours/stale/path для
    каждого фида.  Файл отсутствует -> {'present': False}."""
```

Считает `age_hours = (now - mtime)/3600`, `stale = age_hours > max_age_hours`.
Дефолт 24 ч для EPSS, отдельный порог для KEV (например 168 ч) через config.

### Компонент 2 — Config (`configs/feed_sources.yaml`)

```yaml
  enrichment_policy:           # НОВОЕ (под cve_bin_tool или верхний уровень)
    epss_max_age_hours: 24
    kev_max_age_hours: 168
    on_stale: warn             # warn (баннер в отчёт) | ignore | fail (exit!=0)
```

### Компонент 3 — Reporting

`build_report` перед таблицей вставляет однострочный баннер, когда любой фид
`stale`:

```
> ⚠️ EPSS data is 73h old (threshold 24h) — exploit scores may be outdated.
```

Колонки EPSS/KEV не меняются; меняется только наличие предупреждения.

### Компонент 4 — Provenance / exit

Поле `enrichment_freshness` в run-provenance (age/stale по каждому фиду). При
`on_stale: fail` — ненулевой exit, чтобы CI/оператор заметили протухший кэш.

### Компонент 5 — Tests

- `source_freshness`: свежий / протухший / отсутствующий файл (по `mtime`
  через `os.utime`, как в `tests/test_cli.py::test_db_status_payload_*`).
- `build_report`: баннер появляется при stale, отсутствует при свежих/нет данных.
- backward-compat: без `enrichment_policy` — отчёт идентичен текущему.

## Phasing

| Фаза | Объём | Риск | Acceptance |
|---|---|---|---|
| P1 | `source_freshness` + config-схема + тесты хелпера | нулевой | хелпер корректно классифицирует свежесть |
| P2 | баннер в `build_report` + тесты отчёта | низкий | предупреждение появляется только при stale |
| P3 | provenance-поле + `on_stale: fail` режим | низкий | exit!=0 при протухшем кэше в режиме fail |

## Consequences

**Плюсы:** триажер видит, когда exploit-скоры устарели; CI может падать на
протухшем enrichment; без политики поведение не меняется.

**Минусы / риски:** пороги по умолчанию субъективны (EPSS суточный, KEV
недельный) — вынесены в config. В air-gap среде «протухание» ожидаемо —
поэтому `on_stale: warn` по умолчанию, а не `fail`.

**Альтернатива (отклонена):** сетевой дофетч EPSS/KEV прямо в `enrichment`.
Отклонено — `enrichment` намеренно read-only (см. его docstring); загрузка
данных — ответственность сид-шага (`cve_db_audit.seed_*`), сюда же логично
добавить resilient-fetch отдельной фичей, не смешивая с отчётом.
