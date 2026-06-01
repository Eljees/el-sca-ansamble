# ADR-0005: единый `cli scan` — кросс-платформенный оркестратор пайплайна

- Status: Proposed
- Date: 2026-06-01
- Decision owners: SCA-pipeline team
- Связанные документы: [docs/operations.md](../operations.md),
  [docs/windows-powershell.md](../windows-powershell.md),
  [adr/0001-wrapper-first.md](0001-wrapper-first.md)

## Context

Сейчас полный прогон запускается двумя параллельными оркестраторами:

- `scripts/run-scan.sh` (~300 строк bash) — Linux/macOS;
- `scripts/windows/run-scan.ps1` — Windows.

Оба делают одно и то же: парсят флаги (`--tool`, `--extract`,
`--extract-max-depth`, `--sbom-scan`, `--timeout`), вызывают `docker compose
run` по сканерам (syft → grype → trivy → cve-bin-tool) и дёргают уже готовые
Python-кирпичики через `python -m resilient_updates.cli`:
`render-flags`, `db-status`, `extract`, `collect-report`, `write-run-summary`,
`scanner-diff`, `manifest`.

Проблемы двух оркестраторов:

1. **Дублирование логики** на двух языках — расхождения уже случались
   (порядок шагов, дефолты флагов, обработка exit-кодов cve-bin-tool).
2. **Нет структурированного результата** — статус прогона выводится текстом
   в stdout; CI приходится парсить логи.
3. **Парсинг аргументов** и валидация разные в bash и ps1.

## Decision

Ввести `python -m resilient_updates.cli scan --target <path>` — единый
кросс-платформенный оркестратор на Python, который **дирижирует теми же
кирпичиками**, а не переписывает сканеры. Bash/ps1-скрипты становятся тонкими
обёртками (`exec`/dispatch) поверх `cli scan` и со временем выводятся из
эксплуатации. Это «wrapper-first» (ADR-0001), доведённый до самого верхнего
уровня пайплайна.

### Компонент 1 — Оркестратор (`resilient_updates/scan.py`)

`run_scan(config, *, target, tools, extract, sbom_scan, timeout, update_db,
profile) -> dict` выполняет канонический пайплайн (порядок — как в
`run-scan.sh`):

1. preflight: `docker compose version` доступен;
2. optional extract: `compose run --profile extract artifact-extractor`
   (или `cli extract` для нативного слоя);
3. per-tool: optional `compose run --profile update <tool>-updater` →
   `db-status <tool>` → `compose run <tool>-scanner` с флагами из
   `render-flags`;
4. `collect-report` → `write-run-summary` → `scanner-diff` → `manifest`.

Каждый внешний вызов — через `subprocess.run` с явным таймаутом; cve-bin-tool
exit 1 трактуется как «CVEs found» (не ошибка) — единая точка правды вместо
дубля в bash и ps1. Возвращает структуру с per-tool статусами, путями
артефактов и итоговым `policy_decision`.

### Компонент 2 — CLI (`cli.py`)

Под-парсер `scan`:

```
cli scan --target PATH [--tool all|syft|grype|trivy|cve-bin-tool]
         [--extract] [--extract-max-depth N] [--sbom-scan]
         [--timeout SEC] [--update-db] [--profile NAME]
         [--json]   # машинный вывод
         [--dry-run]  # печатает план шагов, ничего не запускает
```

Exit-коды: `0` ok, `2` хотя бы один сканер недоступен/упал,
`EXIT_VALIDATION_FAILED` при `policy_decision != pass`.

### Компонент 3 — Обёртки

`run-scan.sh` / `run-scan.ps1` ужимаются до проверки окружения + вызова
`python -m resilient_updates.cli scan "$@"`. Существующие флаги маппятся 1:1,
чтобы не сломать привычки операторов и smoke-тесты.

### Компонент 4 — Tests

- `scan.py` юнит-тестируется с **замоканным `subprocess.run`** (как ведёт себя
  пайплайн при ok / scanner-fail / cve-bin-tool-exit-1 / timeout) — без docker;
- `--dry-run` тест: печатает корректный план шагов для каждого набора флагов;
- контракт обёрток: `run-scan.sh --help` упоминает те же флаги, что `cli scan`.

## Phasing

| Фаза | Объём | Риск | Acceptance |
|---|---|---|---|
| P1 | `scan.py` скелет + `cli scan --dry-run` (печать плана) + парсинг флагов + юнит-тесты плана | нулевой (ничего не запускает) | `cli scan --target X --dry-run` печатает корректную последовательность шагов |
| P2 | реальная оркестрация через `subprocess` + структурный результат + exit-коды + тесты с моками | средний | `cli scan` повторяет поведение `run-scan.sh` на ok/fail/timeout (моки) |
| P3 | `run-scan.sh`/`run-scan.ps1` → тонкие обёртки; обновить `docs/operations.md`, `windows-powershell.md` | средний | один источник правды; smoke-тесты зелёные на обеих ОС |

## Consequences

**Плюсы:** один кросс-платформенный вход; устранение дубля bash/ps1;
машиночитаемый результат и предсказуемые exit-коды для CI; `--dry-run` для
обучения и отладки; обработка cve-bin-tool exit-кода в одном месте.

**Минусы / риски:** оркестрация docker из Python требует аккуратной передачи
env/volumes (то, что compose уже делает) — поэтому `cli scan` вызывает именно
`docker compose run`, а не `docker run`, переиспользуя `docker-compose.yml`
как источник правды по сервисам/маунтам. Переходный период: обёртки и
`cli scan` сосуществуют до завершения P3.

**Альтернатива (отклонена):** `cli scan` как тонкая обёртка, которая просто
`exec`-ает существующий `run-scan.sh`. Отклонено — не убирает дубль ps1, не
даёт структурированного результата, и на Windows всё равно нужен отдельный
путь. Полноценный Python-оркестратор устраняет оба скрипта как источник логики.
