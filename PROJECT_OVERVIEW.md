# el-sca-ansamble — Project Overview

`el-sca-ansamble` is a Docker-based, wrapper-first **SCA (software composition
analysis) stack** for repeatable vulnerability analysis of archives, binaries,
APKs, Windows installers, container images, and extracted software trees. Drop an
artifact into the web dashboard and get an SBOM + multi-scanner vulnerability
report. Code, scanner images, and vulnerability DBs are all delivered via
`git clone` (Git LFS bundle), so it runs fully offline / air-gapped.

Distribution: **GitHub** `github.com/Eljees/el-sca-ansamble` ·
**GitLab** `gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble`.

## Versions

Single source of truth: `versions.env` (CI enforces agreement with
`pyproject.toml` and `docker-compose.yml`). Latest changes live in
`CHANGELOG.md` under `[Unreleased]`.

| Component | Version |
|-----------|---------|
| Project (`el-sca`, SemVer) | **0.1.5** (Python ≥ 3.10) |
| Trivy | 0.64.1 |
| Grype | v0.112.0 |
| Syft | v1.20.0 |
| cve-bin-tool | 3.4 |
| OSV scanner | latest (optional) |
| Base image | python:3.12-slim |
| Sidecars | Xray / tinyproxy / WireGuard (latest) |

## Features

- **Pipeline:** `extract → SBOM (Syft) → Grype / Trivy / cve-bin-tool / (optional OSV) → report`, with a final Markdown + HTML report.
- **Resilient & offline-first:** runs from bundled images and prewarmed DBs; explicit (never silent) DB updates; `offline` / `airgap` compose profiles.
- **FastAPI dashboard** (`:8088`): drag-drop upload, live per-stage pipeline + logs, report viewer, artifact catalog with `CYBERSEC-XXXXX` case IDs, DB-freshness "barrels", and proxy/route toggles.
- **Run browser & report hand-off:** `/runs` lists every past run grouped by date (newest first); each run's final Markdown report is one click away — copy, download, or fetch it directly via `GET /api/runs/{run_id}/report.md` (served inline as `text/markdown`).
- **Report identifies the object:** every report (web overview + Markdown) names the scanned archive and its `CYBERSEC-id`, and lists **MD5 + SHA-1 + SHA-256** for both the input archive and the final (extracted) target — digests are computed once during extraction and stored in `summary.json`. The Reports button opens the artifact's newest run.
- **Artifact lifecycle:** upload, tag with a `CYBERSEC-XXXXX` case id, rescan, hide — or hard-delete from storage behind three confirmations plus a server-side `?confirm=<artifact_id>` guard. Saved run snapshots are evidence and are never purged.
- **Phosphor CRT skin:** green monochrome, monospace, scanlines. The radioactive mutagen barrels stay acid green.
- **Recoverable long runs:** stage checkpoints + per-run evidence snapshots (`artifacts/runs/<run-id>/`); resume from last completed stage.
- **Network intelligence:** route-doctor probes egress from inside the Docker network and picks direct / proxy / VPN per tool.
- **Internal S3 mirror** (SeaweedFS, compose profile `storage`) for DBs and scan results; provenance + reproducibility metadata (`input_sha256`, `db_snapshot_id`, `policy_decision`).
- **Cross-platform:** POSIX (`scripts/*.sh`) and Windows (`scripts/windows/*.ps1`) entrypoints.
- **CI quality gates:** ruff, format check, compileall, shellcheck, hadolint, yamllint, PSScriptAnalyzer, version-consistency, compose config, docker build, and pytest with an ≥ 88 % coverage gate (**917 tests** green as of 2026-07-09).

## Known Issues & Limitations

- **NVD API key (D1, open):** cve-bin-tool's NVD source needs an API key that must be provisioned/rotated **manually** on `nvd.nist.gov`; keep it only in a local, git-ignored `.env`. Without it the NVD feed degrades (handled by `degraded-ok` policy).
- **cve-bin-tool exit code `1`** means "findings were discovered" and is treated as a **successful** scan stage; hard failures are tracked separately.
- **Large modules:** `cli.py` and `dashboard.py` mix parsing / business logic / config; a split behind focused tests is planned.
- **S3 path overlap:** `resilient_updates/s3_publish.py` and `scripts/s3_storage.sh` partially duplicate behavior — to be unified or clearly bounded.
- **Flaky test under watch:** `test_post_proxy_chain_roundtrip_all_values`.
- **Compatibility shims:** some `datetime.UTC` shims remain for older Python behavior.

## Roadmap / Planned

- Cut **v0.1.6**: move `CHANGELOG [Unreleased]` into a dated release and tag `vX.Y.Z`.
- Stronger preflight automation: stale `.git/index.lock` cleanup and FUSE-truncated-file recovery.
- Add linux + offline compose overlays to the compose-config CI matrix.
- Unify (or clearly document) the Python vs shell S3-publish paths.
- Reduce `cli.py` / `dashboard.py` size behind tests; drop `datetime` shims once the minimum Python rises.
- **Theme switching.** Ten palettes are already shipped as data in
  [`resilient_updates/themes.py`](resilient_updates/themes.py) and previewed by the
  `🎨 Темы` picker in the dashboard header. The picker is intentionally inert
  (every "Выбрать" is `disabled`): switching at runtime — write the chosen
  palette into `:root`, persist the choice per operator — is planned, not shipped.
  The mutagen barrels stay acid green in every variant, because their colour
  encodes DB fill level.
- Continue operator-UX work: container progress, live logs, report viewer, resumable long-run snapshots.

## Getting Started

| Документ | Зачем |
|---|---|
| [`START_HERE.md`](START_HERE.md) | Развернуть с нуля (Windows/Linux) |
| [`QUICK_START.md`](QUICK_START.md) | Первый скан за 5 минут |
| [`00_PROJECT_CONTEXT.md`](00_PROJECT_CONTEXT.md) | Onboarding для агентов: модули, provenance, живая развёртка |
| [`AGENTS.md`](AGENTS.md) | Правила для coding-агентов |
| [`docs/INDEX.md`](docs/INDEX.md) | Полный сайтмап документации |

Устройство и эксплуатация: [`docs/architecture.md`](docs/architecture.md) ·
[`docs/adr/`](docs/adr/) · [`docs/operations.md`](docs/operations.md) ·
[`docs/operator-quickstart-ru.md`](docs/operator-quickstart-ru.md) ·
[`docs/runbook.md`](docs/runbook.md) · [`docs/failure-modes.md`](docs/failure-modes.md)

Сеть и хранилище: [`docs/proxy.md`](docs/proxy.md) ·
[`docs/network-design.md`](docs/network-design.md) ·
[`docs/s3-storage.md`](docs/s3-storage.md) · [`docs/airgap.md`](docs/airgap.md) ·
[`docs/distribution.md`](docs/distribution.md) ·
[`docs/SHIP_AND_DEPLOY.md`](docs/SHIP_AND_DEPLOY.md)

Процесс: [`CONTRIBUTING.md`](CONTRIBUTING.md) ·
[`docs/RELEASING.md`](docs/RELEASING.md) · [`CHANGELOG.md`](CHANGELOG.md) ·
[`SECURITY.md`](SECURITY.md) ·
[`docs/audit/660-analysis-2026-07-09.md`](docs/audit/660-analysis-2026-07-09.md)
