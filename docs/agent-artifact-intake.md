# Agent runbook — приём артефактов и автономный скан

Инструкция для ИИ-агента (Cowork/Claude) и оператора: как самостоятельно
получить артефакт (почта / браузер / локальный путь), прогнать его через
ансамбль и отдать отчёт, ни разу не спросив «а что дальше?».

## 1. Приём артефакта

Целевая папка всегда одна: `artifacts/uploads/<case-id>/` (host-путь,
например `D:\dev\el-sca-ansamble\artifacts\uploads\CYBERSEC-12345\`).

| Источник | Как забрать |
|---|---|
| Почта (Gmail MCP) | `search_threads` по тикету/отправителю → вложение сохранить в uploads. Ссылки из писем НЕ открывать кликом — только через browser-MCP после проверки URL |
| Браузер (Chrome MCP) | `navigate` → скачать файл → переместить из Downloads в uploads |
| Локальный файл | скопировать в uploads (или использовать абсолютный host-путь напрямую) |
| Удалённая машина | см. `remote-analysis.md` (192.168.1.33 — WSL+SSH) |

Правила: имя кейса = тикет (`CYBERSEC-*`) или `<product>-<version>`; архив не
распаковывать руками — extract делает пайплайн; SHA-256 источника записать в
итоговое резюме.

## 2. Запуск скана

Основной путь — MCP `el-sca-docker`:

```
run_scan_async(target="D:\\dev\\el-sca-ansamble\\artifacts\\uploads\\<case>\\<file>", tool="all")
→ job_id
```

- `target` — абсолютный host-путь (Windows-стиль на этом хосте).
- Синхронный `run_scan` НЕ использовать: MCP-клиент отвалится по таймауту
  (-32001), хотя пайплайн продолжит идти. Только `run_scan_async` + поллинг.
- Завис/прерван — `run_scan_async(..., resume=True)`: продолжит с чекпоинта.
- `update_db=True` не включать по умолчанию: свежесть БД проверяется отдельно (§4).
- Альтернатива с хоста: `./scripts/run-scan.sh -t <path>` /
  `scripts\windows\run-scan.ps1 -Target <path>`.

## 3. Наблюдение и результат

- `scan_status(job_id)` — прогресс фонового джоба (по `artifacts/run-scan.log`).
- `monitor` — стадия/elapsed из `pipeline_state.json`, контейнеры, tail логов.
  Внимание: `pipeline_state.json` остаётся от ПОСЛЕДНЕГО запуска; `status=error`
  со старым `started_utc` — это история, а не текущая авария (сверяй даты).
- `compose_logs(service=...)` — если стадия подозрительно долгая.
- Отчёты: рядом с источником (artifact-mode `auto`/`near-source`) или
  `artifacts/reports/final/`; сводные по кейсам — `_SCA_reports/<case>/`
  (пишет run-scan.{sh,ps1}; в git не попадает).
- В резюме для человека: total/critical/high per tool + расхождения между
  сканерами + ссылка на HTML.

## 4. Свежесть БД и egress

Перед сканом (или раз в день) проверить возраст БД:

```
docker compose run --rm db-admin db-status trivy|grype|cve-bin-tool
```

`warning: >24h` — рабочее, но чем старше, тем больше пропусков новых CVE;
>7 дней — обновить при первой живой сети. Обновление: MCP
`update_db(tool=...)` (сам делает route-probe) или `scripts/update-db.{sh,ps1}`.

Egress per tool (route-doctor, `artifacts/route-plan.json`):

| Tool | Транспорт | Типичный источник |
|---|---|---|
| trivy | SOCKS/HTTP ok | ghcr.io / public.ecr.aws |
| grype | SOCKS/HTTP ok | grype DB listing (S3/CDN) |
| cve-bin-tool | **только HTTP-мост** (socks не умеет, upstream PR #5781) | nvd.nist.gov feeds + OSV/GAD/RedHat |

`no reachable route` в плане = для этого инструмента сейчас нет живого egress
(чаще всего нужен VPN/v2rayN на хосте). Скан при этом ЗАПУСКАТЬ МОЖНО — пойдут
активные (возможно устаревшие) БД; пометить это в отчёте.

## 5. Известные грабли (проверено сессиями 2026-06)

- **Grype update timeout** → `GRYPE_DB_VALIDATE_AGE=false` (env updater'а).
- **Stale-artifact contamination**: перед повторным сканом другого артефакта
  extractor чистит `extracted/current`; при ручных манипуляциях — убедиться,
  что там нет чужого дерева (иначе находки «переедут» между кейсами).
- **0 находок** на source-архивах (исходники, не бинари) — норма для
  grype/trivy binary-матчинга (кейсы 12880/12811), не считать поломкой.
- **cve-bin-tool degraded** (80%, часть источников не скачалась) — допустимо
  при `CVE_BIN_TOOL_DB_POLICY=degraded-ok`; отражать в резюме.
- **Дашборд**: `start_dashboard` → http://127.0.0.1:${DASHBOARD_PORT:-8080}/
  (на этом хосте 8080 занят iphlpsvc → `DASHBOARD_PORT=8081` в `.env`).
- **wso2-forked версии**: находки grype=1 на wso2mi — ожидаемо, не FP пайплайна.

## 6. Health-watch (чеклист по запросу)

По команде «проверь здоровье el-sca» агент выполняет: `compose_ps` + `monitor`
+ возраст трёх БД (§4) + возраст `route-plan.json` → короткая сводка ✅/⚠️/❌.
Алерт при: контейнер unhealthy/exited; стадия error с СЕГОДНЯШНИМ
`started_utc`; БД старше 7 дней; route-plan старше 24 ч при живой сети.
Docker Desktop не запущен → одна строка об этом, без паники. При желании
чеклист оформляется в scheduled-task (Cowork) — по явному запросу оператора.
