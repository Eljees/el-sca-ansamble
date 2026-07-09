> [!WARNING]
> Snapshot of 2026-05-25 and is OUTDATED as a defect register: D1-D18 are closed (except D13),
> the suite has grown to 898 tests. For current state see the latest NNN-analysis/NNN-fixups
> in docs/audit/ (now: 650-analysis-2026-07-06.md).

# Audit 2026-05-25 — Архитектура и связность

## 1. Дублирующиеся утилиты

Три модуля содержат собственные копии hash- и JSON-функций:

- `resilient_updates/reporting.py:26-39` — `_sha256_file`, `_sha512_file`, `_read_json`.
- `resilient_updates/run_summary.py:57-63` — собственная `_short_hash` + parsing JSON.
- `resilient_updates/extractor.py` — `_sha256_member`, `_strip_archive_suffix`.

Любое изменение алгоритма хеширования или формата манифестов нужно
делать в нескольких местах. Часть DRY-долга уже закрыта: `scanner_diff.py` теперь
использует общий `_io.first_json` и `normalize_severity` (см. аудит 640), но
оставшиеся локальные hash/path helpers всё ещё стоит свести к `_io.py`.

**Предложение**: новый модуль `resilient_updates/_io.py` с:

```python
def sha256_file(path: Path) -> str: ...
def sha512_file(path: Path) -> str: ...
def read_json(path: Path) -> Any | None: ...
def collect_json(root: Path, pattern: str) -> Iterable[Any]: ...
```

Переключить три модуля. Тесты — `tests/test_io.py`.

## 2. Retry/timeout-политики рассыпаны

В `configs/feed_sources.yaml` каждый сканер имеет собственный блок с
`retry`/`timeout`/`backoff`:

```yaml
trivy:
  retry: { max_attempts: 3, backoff_seconds: 5 }
grype:
  update:
    retry: { max_attempts: 4, backoff_seconds: 4 }
cve_bin_tool:
  retry: { max_attempts: 2, backoff_seconds: 2 }
```

Внутри `resilient_updates/cli.py` есть как минимум одно место с хардкодом
`backoff_seconds=1` (`cli.py` блок `update cve_bin_tool`), а
`fallback._NON_RETRYABLE_REASONS` ещё одна точка истины.

**Предложение**: dataclass `RetryPolicy(max_attempts: int, backoff_seconds: float, retry_status_codes: frozenset[int], non_retryable_reasons: frozenset[FailureReason])`. Парсить один раз в `config.py`, передавать в `attempt_sources` явно. Дефолты — на уровне YAML, override — на уровне per-source.

## 3. Logging несистематический

Беглый grep:

```
$ grep -rn "print(" resilient_updates/ | wc -l
~30
$ grep -rn "logging\." resilient_updates/ | wc -l
~15
$ grep -rn "except.*: *$" resilient_updates/ | head
… несколько голых except: pass
```

В одном модуле — `print()` для прогресса, в другом — `logger.info`, в третьем — `sys.stderr.write`. CI-логи получаются разнородные, в JSON-парсер их не загнать.

**Предложение**: `resilient_updates/_logging.py`:

```python
def setup_logging(level: str = "INFO", format: Literal["text", "json"] = "text") -> None: ...
```

`LOG_LEVEL` и `LOG_FORMAT` из env. `format=json` для CI. Заменить все
`print(...)` и `sys.stderr.write(...)` на `logger.info/error`.
Голые `except: pass` обвести `logger.exception("…")`.

## 4. Provenance плоский, без `run_id`

Сейчас провенанс одного запуска размазан по шести-восьми файлам:

```
artifacts/extraction_manifest.json
artifacts/summary.json
artifacts/status.json
artifacts/db_snapshot.json
artifacts/run_manifest.json   ← уже есть, но содержит только tools/timestamps
artifacts/provenance/*.json
artifacts/reports/cve-bin-tool/attempts/*.json
```

Нет корневого файла, который сказал бы «эти восемь файлов — один прогон
от 2026-05-25 11:42:33 UTC, run-id=`a3b…f7`». Trace по одному запуску собирается вручную.

**Предложение**: `artifacts/MANIFEST.json` со схемой:

```json
{
  "run_id": "01HZAB7K…",
  "started_at": "2026-05-25T11:42:33Z",
  "finished_at": "2026-05-25T11:48:12Z",
  "case_id": "CYBERSEC-12104",
  "target": { "host": "…", "container": "/scan-target", "sha256": "…" },
  "tools": { "trivy": "0.64.1", "grype": "v0.112.0", "syft": "v1.20.0", "cve-bin-tool": "3.4" },
  "artefacts": {
    "extraction": "extraction_manifest.json",
    "sbom": ["sbom/syft.json", "sbom/cyclonedx.json", "sbom/spdx.json"],
    "reports": ["reports/grype/report.json", "reports/trivy/report.json", "reports/cve-bin-tool/report.json"],
    "provenance": ["provenance/grype-db.json", "provenance/cve-db.json", "provenance/proxy.json"],
    "summary": "summary.json",
    "status": "status.json",
    "final_markdown": "reports/final/cve_analysis_report_generated_ru.md"
  }
}
```

`run_id` — ULID, генерируется один раз на pipeline. Пишется первым
шагом, дописывается финальным. CLI команда `manifest` — для отдельных
сценариев (когда поставка собирается частями).

## 5. Один CLI, много точек входа

Сейчас сосуществуют:

- `python -m resilient_updates.cli` (14 subcommands)
- `scripts/run-scan.sh` (мульти-stage runner, ~362 строки)
- `scripts/scan_archive.sh` (старый short runner, ~118 строк)
- `scripts/run_scan.sh` (минималистичный per-tool wrapper, ~53 строки)
- `scripts/batch-scan.sh` (N кейсов подряд)
- `scripts/windows/run-scan.ps1` (PowerShell-эквивалент)
- `scripts/windows/batch-scan.ps1`

В сумме — четыре POSIX точки входа + две PowerShell. У каждой —
свои env-vars, флаги, конвенции.

**Предложение** (фаза B–D, постепенно):

1. Сделать `cli.py scan --target ...` agregаting-командой, выдаёт тот же результат, что `run-scan.sh -t … -u`.
2. `scripts/run_scan.sh` → `exec ./scripts/run-scan.sh "$@"` (alias-обёртка с warning).
3. `scripts/scan_archive.sh` — пометить deprecated в `scripts/README.md`, оставить ещё одну фазу.
4. PowerShell-эквиваленты оставить как тонкие shims, делегирующие в Python CLI или sh.

## 6. Файловая безопасность контейнеров

Все пять `Dockerfile.*` запускаются от root. Это:

- `Dockerfile.resilient-updater` — оправдано (cross-volume операции).
- `Dockerfile.cve-bin-tool` — оправдано (DB и cache /root/.cache).
- `Dockerfile.extractor` — **не нужно**: на входе read-only mount, на выходе один named volume.
- `Dockerfile.apk-analyzer` — **не нужно** (androguard, pefile — pure Python).
- `Dockerfile.win-analyzer` — **не нужно** (innoextract, msitools под `--input` RO).

**Предложение**: в трёх последних добавить:

```dockerfile
RUN useradd -m -u 1000 scanner
USER scanner
```

…и в compose `user: "1000:1000"` для соответствующих сервисов. С root оставить только resilient-updater и cve-bin-tool с явной пометкой почему.

## 7. Версии сканеров — три места

Сейчас версии живут одновременно в трёх местах:

- `docker-compose.yml` — `aquasec/trivy:0.64.1`, `ghcr.io/anchore/grype:v0.112.0`, `ghcr.io/anchore/syft:v1.20.0`.
- `Dockerfile.cve-bin-tool` — `pip install cve-bin-tool==3.4`.
- `docs/operations.md:41-46` — устаревшие `grype:v0.82.0`.

Если кто-то поднимает grype на новую minor, нужно обновить compose + написать в operations.md + не забыть про docs/airgap.md + не забыть про runbook.md. Источник дрейфа.

**Предложение**: `versions.env` в корне:

```
TRIVY_VERSION=0.64.1
GRYPE_VERSION=v0.112.0
SYFT_VERSION=v1.20.0
CVE_BIN_TOOL_VERSION=3.4
OSV_SCANNER_VERSION=latest
XRAY_VERSION=latest
TINYPROXY_VERSION=1.11.2
WIREGUARD_VERSION=latest
```

`docker-compose.yml` использует `image: aquasec/trivy:${TRIVY_VERSION}`. В CI добавить job, проверяющий, что версии в docs/* совпадают с `versions.env` (простой `grep -F`).

## 8. Сводка по архитектурным темам

1. **DRY** — продолжить вынос общих helpers в `_io.py`; `RetryPolicy` и общий logging уже частично закрыли ранний долг.
2. **Single source of truth** — `versions.env`, `run_manifest.json`, единый CLI.
3. **Безопасность** — рут-пользователи в Dockerfile.* и tmpfs-конфиги.
4. **Provenance** — корневой манифест связывает 8 файлов одного прогона.
5. **Точки входа** — четыре shell-runner'а постепенно сводим к одной Python-команде с тонкими shims.

---

**См. также:** [00-overview.md](00-overview.md) · [10-defects.md](10-defects.md) · [30-tests.md](30-tests.md) · [40-tooling-docs.md](40-tooling-docs.md)
