> [!WARNING]
> Snapshot of 2026-05-25 and is OUTDATED as a defect register: D1-D18 are closed (except D13),
> the suite has grown to 873 tests. For current state see the latest NNN-analysis/NNN-fixups
> in docs/audit/ (now: 640-analysis-2026-07-05.md).

# Audit 2026-05-25 — Tooling, CI, документация

## 1. CI workflow (`.github/workflows/ci.yml`)

Что есть:

- `lint-python` (ruff check + format check + compileall).
- `lint-shell` (shellcheck с severity=warning, scandir=./scripts, исключая `scripts/windows`).
- `lint-docker` (matrix по 5 Dockerfile, hadolint).
- `lint-yaml` (yamllint -c .yamllint).
- `lint-powershell` (PSScriptAnalyzer для `scripts/windows`).
- `compose-config` (`docker compose config -q` base + windows.override).
- `pytest` (только после `lint-python`).

Что **не** делается:

| Пропуск | Последствие |
|---|---|
| `pre-commit run --all-files` не запускается отдельной job | хуки и CI могут разъехаться; «у меня локально проходит, в CI красно» |
| `--cov-fail-under` не задан | регрессы в покрытии не ловятся ([30-tests.md §4](30-tests.md#4-coverage-gate)) |
| `docker compose build` не выполняется | синтаксическая ошибка в Dockerfile, не пойманная hadolint, поймается только в проде |
| Нет matrix Python (только 3.12) | если в `Dockerfile.*` поедет на 3.11 — не заметим |
| `requirements.lock` не сгенерирован | `pip install -r requirements.txt` тянет latest при каждом билд'е |

**Предложение** (фаза F):

```yaml
pre-commit:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with: { python-version: "3.12", cache: pip }
    - run: pip install pre-commit
    - run: pre-commit run --all-files --show-diff-on-failure

docker-build:
  runs-on: ubuntu-latest
  needs: [lint-docker]
  strategy:
    matrix:
      service: [resilient-updater, extractor, cve-bin-tool, apk-analyzer, win-analyzer]
  steps:
    - uses: actions/checkout@v4
    - run: docker compose build ${{ matrix.service }}
```

И в `pytest` job:

```
pytest -q --maxfail=1 --cov=resilient_updates --cov-report=term-missing --cov-fail-under=75
```

## 2. Pre-commit

`.pre-commit-config.yaml` подключает:

- `pre-commit-hooks` (`trailing-whitespace`, `end-of-file-fixer`, `check-merge-conflict`, `check-added-large-files` `--maxkb=5000`, `check-yaml`, `check-json`, `check-toml`).
- `ruff-pre-commit` (`ruff --fix`, `ruff-format`).
- `shellcheck-precommit` (severity=warning, exclude `scripts/windows`).
- `yamllint` (`-c .yamllint`).
- `hadolint-docker`.
- Локальный `python-compileall` для `resilient_updates tests`.

Конфиг корректен. Замечание одно — в CI `pre-commit run --all-files`
не вызывается (см. §1), хуки бьют только на `git commit` локально.

## 3. Расхождения документации и compose

### 3.1 `docs/architecture.md` — состав сервисов

`architecture.md` § 11 «Контейнерные сервисы» перечисляет:

```
- stack-info
- trivy-updater
- trivy-scanner
- grype-updater
- grype-db-importer
- grype-static
- grype-scanner
- syft-sbom
- artifact-extractor
- cve-bin-tool-updater
- cve-bin-tool-scanner
- db-admin
- report-collector
- mock-feed-server
- (нет apk-analyzer, win-analyzer, osv-scanner, proxy-xray, tinyproxy, wireguard)
```

Реально в compose **19 сервисов**. Отсутствуют в архитектуре: `apk-analyzer`, `win-analyzer`, `osv-scanner`, `proxy-xray`, `tinyproxy`, `wireguard`. В README они упомянуты, но в архитектуру не попали.

### 3.2 `docs/architecture.md` — профили

`architecture.md` § 115 «Docker Compose профили»:

```
update, scan, extract, report, offline, test-failover
```

Реально в compose **12 профилей**. Не упомянуты: `default`, `airgap`, `apk`, `win`, `osv`, `proxy`, `vpn`.

### 3.3 `docs/architecture.md` — CLI команды

`architecture.md` § 23 (Python-оркестратор) описывает только часть
команд. Не описаны:

- `db-status` (печатает текущее состояние всех DB)
- `activate` (force-activate cve-bin-tool DB candidate)
- `seed` (заполнение mirror)
- `extract` (распаковка через container)
- `render-flags` (рендеринг trivy flags)
- `scanner-diff` (diff двух прогонов)
- `manifest` (после фазы C)

### 3.4 `docs/operations.md:41-46` — выставленные версии

```
anchore/syft:v1.20.0   ← ok
anchore/grype:v0.82.0  ← compose имеет v0.112.0
aquasec/trivy:0.64.1   ← ok
```

Источник дрейфа — см. [20-architecture.md §7](20-architecture.md#7-версии-сканеров--три-места).

## 4. Устаревшие утверждения

### 4.1 `docs/status-and-roadmap.md` § 2f

> Оставшиеся заглушки в документации: `docs/security-notes.md` (9 строк), `docs/windows-powershell.md` (17 строк), `docs/custom-sources.md` (24 строки).

Реально все три — полноценные документы (`wc -l`):

```
docs/security-notes.md   107
docs/windows-powershell.md   177  (примерно — точный wc после фазы E)
docs/custom-sources.md   174
```

**Действие**: убрать секцию 2f или переписать.

### 4.2 README.md «Что нового (2026-05-17)»

В корне README первая секция датирована 17 мая. После 17 мая были
ещё семь коммитов (см. `git log --oneline`). README не отражает:
batch-runner улучшения (`scripts/batch-scan.sh`), digest helper
(`make-high-critical-report.sh`), и стабилизацию extractor'а
(commit `7a04438`).

**Действие**: либо обновлять «Что нового» на каждый релизный commit (мейнтенанс-боль), либо заменить на «See [CHANGELOG.md](CHANGELOG.md) for full history» с коротким top-3.

### 4.3 `README.md:570` — `pack-artifacts.ps1`

README в § 7 «Полезные команды» отсылает к
`scripts/windows/pack-artifacts.ps1`. Файл существует
(`ls scripts/windows/pack-artifacts.ps1` → ok), но не описан в
`scripts/README.md` (где описаны 12 других скриптов). Inventory
неполный.

**Действие**: добавить запись в `scripts/README.md` или удалить упоминание из README.

## 5. Дубль deployment-документов

```
DEPLOYMENT_GUIDE_FINAL.md     ~17 KB, hardcoded IP 192.168.1.33, пути D:\!ya_drive_sync\...
docs/operations.md            ~15 KB
docs/windows-powershell.md    ~9 KB
docs/airgap.md                ~7 KB
CHANGES_v3.0.md               ~3.8 KB
```

`DEPLOYMENT_GUIDE_FINAL.md` назван «FINAL», но содержит example-values
конкретной тестовой среды. Это сбивает с толку.

**Действие**:

1. Переименовать `DEPLOYMENT_GUIDE_FINAL.md` → `DEPLOYMENT_EXAMPLE.md` (или перенести в `docs/examples/deployment-acme-corp.md`).
2. Добавить дисклеймер в верх: «Этот файл — пример. Замените 192.168.1.33 и пути на свои».
3. В README указать `docs/operations.md` как канонический guide.

## 6. Чего не хватает в docs/

| Файл | Назначение |
|---|---|
| `CONTRIBUTING.md` (корень) | как клонировать, как настроить dev-env, как запускать тесты, как submit PR |
| `SECURITY.md` (корень) | политика disclosure, контакты, embargo |
| `docs/INDEX.md` | sitemap по аудиториям: scanner-user / DevOps / security / maintainer |
| `docs/adr/README.md` | индекс ADR с одной строкой описания |
| `docs/dev/getting-started.md` | dev-setup: pyenv/venv, pre-commit hooks, локальный pytest |
| `docs/dev/release.md` | как делать релиз: tag, build, push, sign, CHANGELOG bump |

## 7. Артефакты в git-tracking

Беглый `git ls-files | grep -E "exps|prompts|comands|deep-research"`:

- `comands.txt` — должен быть в .gitignore (он есть), но если уже трекается — `git rm --cached`.
- `_el_cvebt_source_research/`, `--exps/`, `-prompts/` — в .gitignore, но проверить, не закоммичены ли.
- `deep-research-report(4).md` (66 KB в корне репо) — артефакт исследования, не код. Перенести в `docs/research/` или удалить.
- `Исследование контейнеризации, баз и fallback-механизмов для cve-bin-tool, Trivy, Grype и .docx` (40 KB) — то же самое.

## 8. Финальная сводка по tooling

| Категория | Текущее состояние | Цель |
|---|---|---|
| Линтеры (Python/SH/Docker/YAML/PS) | подключены, в CI работают | без изменений |
| Pre-commit hooks | подключены локально | + job в CI |
| Coverage | term-missing, без gate | `--cov-fail-under=75` |
| Docker build в CI | нет | matrix-job |
| `requirements.lock` | нет | `make lock` + закоммитить |
| `versions.env` | нет (распылены) | один источник правды |
| ADR | 2 есть | + индекс `docs/adr/README.md` |
| CONTRIBUTING/SECURITY | нет | добавить |
| INDEX/sitemap | нет | `docs/INDEX.md` |

---

**См. также:** [00-overview.md](00-overview.md) · [10-defects.md](10-defects.md) · [20-architecture.md](20-architecture.md) · [30-tests.md](30-tests.md)
