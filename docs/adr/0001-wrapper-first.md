# ADR-0001: wrapper-first architecture (без форка upstream-сканеров)

- Status: Accepted
- Date: 2026-05-16
- Decision owners: SCA-pipeline team
- Captured retroactively from `docs/architecture.md` и многочисленных комментариев в `resilient_updates/*.py`.

## Context

Trivy, Grype, Syft и cve-bin-tool — самостоятельные, активно развивающиеся opensource-сканеры. У каждого свой релизный цикл, формат БД, политика обновлений, набор флагов CLI и поведение при сетевых ошибках.

Командe el-sca-ansamble требуется:

1. Отказоустойчивость источников: если зеркало `oci://ghcr.io/...` недоступно, перейти на `oci://public.ecr.aws/...` и далее на корпоративный mirror — БЕЗ модификации сканера.
2. Provenance: машинно-читаемая фиксация, какие источники опрошены, какой выбран, какие ошибки были до fallback.
3. Атомарная активация БД: новая версия БД не должна быть видна сканеру, пока не прошла валидацию.
4. Audit БД cve-bin-tool: minimum number of entries, max cache age, required data sources.

## Decision

Вся логика отказоустойчивости, fallback, валидации checksum/age и сборки итогового отчёта вынесена во внешний Python-пакет `resilient_updates` и shell-обвязку `scripts/*.sh` / `scripts/windows/*.ps1`. Сами сканеры запускаются upstream-образами (`aquasec/trivy:0.64.1`, `ghcr.io/anchore/grype:v0.112.0`, `ghcr.io/anchore/syft:v1.20.0`, `cve-bin-tool==3.4` через `pip`) **без модификаций**.

Дизайн состоит из:

- **Python-оркестратор** (`resilient_updates/`): cli.py + специализированные модули (`fallback.py`, `config.py`, `provenance.py`, `cve_db_audit.py`, …).
- **Sidecar-сервисы** для DB-стейджинга и распространения: `grype-static` (HTTP-раздача активного снапшота Grype), `grype-db-importer`, `artifact-extractor`, `report-collector`.
- **Конфиг YAML** (`configs/feed_sources.yaml`) — единственная точка декларации источников, prio, retry-policy.
- **Docker Compose profiles** — отделение update-фаз от scan-фаз без правок compose-файла каждый раз.

## Consequences

### Положительные

- Любое обновление сканера сводится к bump-у тэга образа в `docker-compose.yml`. Без `git rebase` upstream-форка.
- Логика fallback тестируется на чистом Python (моки HTTP), не требует поднимать сканеры.
- Audit-логика cve-bin-tool DB живёт в одном месте; политика «fail-closed if required missing» применима к любым новым data sources.
- Provenance JSON совместим с tooling'ами (jq, schema validation) и легко расширяется.

### Отрицательные

- Слой «wrapper» добавляет когнитивную нагрузку: тот, кто читает CI-логи, должен понимать, что `python -m resilient_updates.cli update grype` — не сам Grype, а орк.
- Любые баги в YAML-схеме или модуле `source_policy.py` затрагивают все четыре сканера сразу.
- При сильном расхождении upstream-CLI (например, breaking change флагов в Trivy 0.65+) обвязку `render-flags` придётся править — это компенсируется тем, что render-flags строит командную строку из YAML, а не дублирует флаги по местам вызова.

## Alternatives considered

- **Форк upstream-сканеров.** Отвергнуто: cost of merge labour > expected benefit; теряется upstream security-fix-pipeline.
- **Один монолитный bash-скрипт.** Подходит для MVP, но не покрывает audit, не имеет тестируемых модулей, плохо переносится между Linux/Windows.
- **Renovate-style каркас на Go.** Излишне для текущего объёма; Python даёт быстрее итерации, тестов на pytest достаточно.
