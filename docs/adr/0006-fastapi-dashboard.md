# ADR-0006: FastAPI-дашборд — живой просмотр прогонов

- Status: Accepted (read-only browser + host-active GUI)
- Date: 2026-06-02 (updated 2026-06-11)
- Decision owners: SCA-pipeline team
- Связанные документы: [adr/0005-unified-cli-scan.md](0005-unified-cli-scan.md),
  [docs/operations.md](../operations.md), [docs/security-notes.md](../security-notes.md)

## Context

Сейчас результаты прогона доступны двумя способами:

- файлы в `artifacts/` — `provenance/<tool>.json`, `reports/<tool>/…`,
  `reports/final/…`, `sbom/…`, корневой `MANIFEST.json`;
- `scripts/report_html.py` — генерирует **статический** self-contained HTML по
  одному набору артефактов.

Чего нет: **живого** интерфейса, где можно листать несколько прогонов,
сравнивать (`scanner_diff`), смотреть provenance/policy-decision и свежесть
БД/EPSS без ручного открывания JSON. Это и есть дашборд.

В отличие от всего, что добавлялось в `resilient_updates` ранее (разовые
функции и CLI-команды), дашборд — **постоянно работающий сетевой сервис**.
Поэтому он оформляется отдельным ADR: новые зависимости, контейнер, порт,
вопросы доступа.

## Decision

FastAPI-приложение поверх `artifacts/` с двумя режимами:

- **host-active** (по умолчанию при запуске `cli dashboard --repo-root .`) —
  drag-and-drop scan/update GUI запускает `docker compose` на хосте, стримит
  стадии и лог через SSE, пишет per-run snapshot/checkpoint;
- **compose read-only** (`docker compose --profile dashboard up`) — только
  просмотр уже записанных артефактов. В контейнере `EL_SCA_DASHBOARD_ACTIVE=0`,
  поэтому `POST /api/scan` и `POST /api/update-db` честно возвращают 403.

Источник правды остаётся файловым: текущий прогон живёт в `artifacts/`, история
прогонов — в `artifacts/runs/<project>-<timestamp>/` или рядом с исходным
артефактом, если runner запущен с режимом `near-source`/`auto`.

### Компонент 1 — App (`resilient_updates/dashboard.py`)

FastAPI-приложение, фабрика `create_app(artifacts_dir: Path) -> FastAPI`:

- `GET /healthz` — liveness;
- `GET /api/runs` — список текущего и сохранённых прогонов (`artifacts/runs/*`);
- `GET /api/runs/{id}` — детали: provenance по каждому tool/layer, summary,
  `scanner_diff`, статус свежести БД/EPSS (через `enrichment.source_freshness`);
- `GET /api/freshness` — текущий вердикт `evaluate_enrichment_policy`;
- `POST /api/scan` — host-active запуск scan job с drag-and-drop upload;
- `POST /api/update-db` — host-active запуск update job;
- `GET /api/jobs/{id}/stream` — SSE snapshot/update stream: стадии, лог,
  progress, `run_dir`, `log_path`.

Парсинг артефактов переиспользует существующие хелперы (`_io.read_json`,
`reporting`/`run_summary`/`scanner_diff`), без дублирования логики.

### Компонент 2 — UI

Server-rendered HTML без JS-фреймворка: drag-and-drop зона, выбор инструментов,
стадии pipeline, live log, карта анализа, embedded report, DB cards и список
сохранённых прогонов.

### Компонент 2.5 — Run snapshots

`resilient_updates.run_layout` создаёт единый per-run layout:

```
<project>-<timestamp>/
  MANIFEST.json
  checkpoint.json
  job.log | run-scan.log
  sbom/
  reports/
  provenance/
  extracted/current/extraction_manifest.json
```

По умолчанию полный `extracted/current` не копируется, чтобы не раздувать диск.
Если нужно сохранить распакованное дерево для resume/debug, включается
`EL_SCA_ARCHIVE_EXTRACTED_TREE=1`.

### Компонент 3 — Зависимости

`requirements.in`: `fastapi`, `uvicorn[standard]`, `python-multipart`, `httpx`. Регенерировать
`requirements.txt`/`.lock` через `make lock`. Это первая веб-зависимость в
проекте — отметить в `docs/security-notes.md`.

### Компонент 4 — Запуск

- CLI: `cli dashboard --host 127.0.0.1 --port 8080 --artifacts-dir artifacts --repo-root .`
  (host-active режим, поднимает uvicorn);
- compose: сервис `dashboard` в **новом профиле `dashboard`**, read-only
  bind-mount `./artifacts:/workspace/artifacts:ro`, публикация порта только на loopback
  (`127.0.0.1:8080:8080`).

### Компонент 5 — Безопасность

- bind по умолчанию на `127.0.0.1`, не `0.0.0.0`;
- compose-сервис **read-only** (нет мутаций, нет запуска сканов из контейнера);
- host-active режим запускает Docker на хосте, поэтому должен слушать loopback и
  использоваться как локальный операторский инструмент;
- аутентификации нет в v1 (внутренний инструмент); для прод-выставления —
  только за reverse-proxy с auth (задокументировать в `security-notes.md`);
- никаких секретов в ответах (provenance не содержит ключей — проверить).

### Компонент 6 — Tests

`fastapi.testclient.TestClient` поверх фикстуры `artifacts/` (без запуска
uvicorn): `/healthz`, `/api/runs` на пустом и заполненном каталоге,
`/api/runs/{id}` шейп, `/api/freshness`. Без сети и контейнера.

## Phasing

| Фаза | Объём | Риск | Acceptance |
|---|---|---|---|
| P1 | read-only JSON API (`create_app`) + TestClient-тесты | низкий | `/api/runs`, `/api/runs/{id}`, `/healthz`, `/api/freshness` отдают корректные данные на фикстуре |
| P2 | Jinja2 UI (индекс + страница прогона) + `cli dashboard` launcher | низкий | `cli dashboard` поднимает сервер; страницы рендерятся |
| P3 | compose-сервис `dashboard` (профиль, ro-mount, loopback) + docs + security-notes | средний | `compose --profile dashboard up` поднимает дашборд; раздел в security-notes |

## Consequences

**Плюсы:** живой обзор прогонов/provenance/диффов/свежести без копания в JSON;
переиспользует существующие парсеры; read-only ⇒ не влияет на пайплайн.

**Минусы / риски:** первый сетевой сервис в проекте — расширяет attack surface;
митигировано read-only + loopback-bind + «auth только через reverse-proxy».
Новые веб-зависимости увеличивают supply-chain поверхность (lock с хешами
обязателен).

**Альтернатива (отклонена):** только расширять статический `report_html.py`.
Отклонено — статика не даёт навигации по нескольким прогонам и live-свежести;
дашборд и `report_html.py` сосуществуют (статика для архива/выгрузки, дашборд
для оперативного просмотра).
