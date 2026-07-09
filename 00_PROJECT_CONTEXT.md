# 00 Project Context

Last updated: 2026-07-09 19:30 Europe/Moscow (after the DB-refresh + audit pass).

This is the fast handoff file for `el-sca-ansamble`. It summarizes the current
project shape, runtime settings, operator workflow, artifact policy, storage,
tooling, repository state, and **the live deployment at `10.2.108.47`**.
Detailed docs remain canonical if they disagree with this snapshot.

This file is **tracked** and is the canonical onboarding doc for agents and
engineers working on `el-sca-ansamble` — keep it current whenever remotes,
storage/artifact layout, deployment facts, or operator commands change.

> ⚠️ The repo is mirrored to a **public** GitHub remote
> (`github.com/Eljees/el-sca-ansamble`). This file deliberately records internal
> deployment specifics (addresses, host, egress) so agents can work the
> `10.2.108.47` box — treat those as internal-only and **never add live secrets
> (tokens, API keys, passwords) here**. If something leaks, rotate it; do not
> just delete it. `PROJECT_OVERVIEW.md` is the lighter, outward-facing summary.

## Current Repository Snapshot

- Repository root: `D:\dev\el-sca-ansamble`.
- Branch: `master`. Pushed to both remotes in lockstep (`0/0` divergence).
- This file is **tracked** (since `d4d6631`) and committed together with the
  work it documents — so the exact tip advances every time; consult the log
  block below and `git log --oneline` for the true HEAD rather than trusting a
  single pinned hash here.
- Worktree normally clean; the only expected untracked item on the deployment
  is the `.env.bak-*` backup.
- Latest audit doc: `docs/audit/660-analysis-2026-07-09.md`.
- Validation at this snapshot: `ruff check` passed, `ruff format --check` passed,
  **910 tests passed** on Windows.

Commits landed after audit 660 (newest first, all on both remotes):

```text
(this doc)  docs/UX: /runs grouped by date + report.md endpoint, docs
a232c5a  feat(dashboard): first-class Markdown report link + copy button per run
d4d6631  docs: track 00_PROJECT_CONTEXT.md as the agent onboarding doc
fc0d59d  fix(dashboard): match cve-bin-tool source names case-insensitively
cff6529  fix(extractor): don't crash on directory input with nested archives
62fc073  fix(trivy): prefer mirror.gcr.io for DB downloads; show real DB date in GUI
c2715ca  docs: add PROJECT_OVERVIEW.md (versions, features, known bugs, roadmap)
029333f  fix(config): align CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS default to 1800
245b7a7  docs: audit 660 (2026-07-09)
```

Remotes:

```text
origin -> https://github.com/Eljees/el-sca-ansamble.git
gitlab -> https://gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble.git
```

Before pushing, inspect status/divergence again. Keep GitHub/GitLab
synchronization as a separate pass from feature/fix work.

## Project Purpose

`el-sca-ansamble` is a Docker-based SCA stack for repeatable analysis of
archives, binaries, APKs, Windows installers, images, and extracted software
trees.

Main scanner stack:

- Syft creates SBOMs.
- Grype scans SBOMs against Anchore vulnerability DB.
- Trivy scans filesystems/images against Trivy DB.
- cve-bin-tool scans binaries and NVD-derived databases.
- Optional OSV scanner can consume the CycloneDX SBOM.
- APK and Windows installer analyzers cover platform-specific artifacts.

The Python package `resilient_updates` owns orchestration, fallbacks,
provenance, reporting, run snapshots, monitor state, S3 publishing, artifact
catalog, and the FastAPI dashboard.

Architectural priority: wrapper-first. Keep resilience and orchestration in
Python/shell wrappers instead of forking upstream scanners.

## Operating Priorities

- Preserve evidence: every meaningful scan should have a saved run snapshot.
- Make long runs recoverable: checkpoint stage state and preserve enough
  artifacts to avoid repeating expensive extraction/scanning after crashes.
- Make operator progress visible: dashboard/monitor should expose stages,
  container state, logs, and saved run/report status.
- Keep scanner updates explicit: plain scan should not silently refresh DBs.
- Keep generated/runtime artifacts out of git.
- Prefer small, validated changes over broad refactors.
- Split large modules only behind focused tests.

## Key Entry Points

- `README.md`: project overview.
- `PROJECT_OVERVIEW.md`: published project description (versions, features,
  known bugs, roadmap) — mirrored to GitHub and GitLab.
- `QUICK_START.md`: first-run path.
- `AGENTS.md`: repo-level instructions for coding agents.
- `docs/INDEX.md`: documentation sitemap.
- `docs/operator-quickstart-ru.md`: Russian operator path, GUI, DB update,
  S3/logs.
- `docs/operations.md`: command reference.
- `docs/operations-guide.md`: Russian operational walkthrough.
- `docs/architecture.md`: service/module architecture.
- `docs/network-design.md` and `docs/proxy.md`: proxy/VPN/route behavior.
- `docs/s3-storage.md`: SeaweedFS/S3 storage layout.
- `docs/remote-analysis.md`: repeatable remote-machine flow.
- `docs/runbook.md`: troubleshooting.
- `docs/failure-modes.md`: error/failure classification.
- `docs/reproducibility.md`: reproducibility contract.
- `docs/RELEASING.md` and `CHANGELOG.md`: release process and changes.
- `docs/audit/660-analysis-2026-07-09.md`: latest audit/fixup state.

## Common Commands

Developer validation before handoff:

```powershell
python -m ruff check .
python -m ruff format --check resilient_updates tests scripts tools
python -m compileall -q resilient_updates tests
python -m pytest -q
```

Compose validation for compose-only changes:

```powershell
docker compose config -q
docker compose -f docker-compose.yml -f docker-compose.windows.override.yml config -q
docker compose -f docker-compose.yml -f docker-compose.linux.override.yml config -q
docker compose -f docker-compose.yml -f docker-compose.offline.yml config -q
```

Make targets:

```sh
make validate
make preflight
make monitor
make update TOOL=all
make scan TARGET=/path/to/artifact
make full TARGET=/path/to/artifact
make test
make lint
```

Dashboard:

```sh
python -m resilient_updates.cli dashboard --repo-root . --port 8080
```

Open:

```text
http://127.0.0.1:8080
```

## Versions

Single source of truth: `versions.env`. `pyproject.toml`, compose fallbacks, and
docs should stay consistent with it.

```text
EL_SCA_VERSION=0.1.5
TRIVY_VERSION=0.64.1
GRYPE_VERSION=v0.112.0
SYFT_VERSION=v1.20.0
CVE_BIN_TOOL_VERSION=3.4
OSV_SCANNER_VERSION=latest
XRAY_VERSION=latest
TINYPROXY_VERSION=latest
WIREGUARD_VERSION=latest
SEAWEEDFS_VERSION=4.38
MINIO_MC_VERSION=RELEASE.2025-08-13T08-35-41Z
PYTHON_BASE_IMAGE=python:3.12-slim
JAVA_XMX=512m
```

Python package:

- Project name: `el-sca-ansamble`.
- Version: `0.1.5`.
- Python requirement: `>=3.10`.
- CLI entry point: `el-sca = resilient_updates.cli:main`.
- Runtime dependencies: `PyYAML`, `requests`, `PySocks`.
- Optional dashboard dependencies: `fastapi`, `uvicorn[standard]`,
  `python-multipart`, `httpx`.

## Important Python Modules

- `resilient_updates/cli.py`: main CLI parser and command dispatch.
- `resilient_updates/orchestrator.py`: host-side scan/update jobs, stages,
  checkpoints, S3-after-run hooks.
- `resilient_updates/dashboard.py`: FastAPI dashboard, active scan/update jobs,
  run browser, Artifact Catalog UI.
- `resilient_updates/artifact_catalog.py`: dashboard-managed uploaded artifacts
  and artifact-to-run mapping.
- `resilient_updates/monitor.py`: container and pipeline status.
- `resilient_updates/pipeline_state.py`: atomic stage state for monitor/resume.
- `resilient_updates/run_layout.py`: per-run layout, manifest, checkpoints,
  snapshot copying.
- `resilient_updates/reporting.py`: final Markdown/HTML reports.
- `resilient_updates/run_summary.py`: `summary.json`, `status.json`,
  `run_manifest.json`, `db_snapshot.json`.
- `resilient_updates/scanner_diff.py`: compare two run artifact directories.
- `resilient_updates/route_plan.py`, `update_doctor.py`, `proxy_chain.py`:
  route probing and proxy chain decisions.
- `resilient_updates/s3_publish.py`: publish saved scan runs to stack-local S3.
- `resilient_updates/extractor.py`: recursive extraction and pre-filter logic.
- `resilient_updates/cve_db_audit.py`: cve-bin-tool DB provenance/health.

Known architecture notes from audit 660:

- `cli.py` is large and mixes parsing/business logic/config/health checks.
- `dashboard.py` is large and grew further with Artifact Catalog.
- `s3_publish.py` and `scripts/s3_storage.sh` partially duplicate S3 behavior;
  either unify or clearly document boundaries.
- Several modules still carry `datetime.UTC` compatibility shims for older
  Python behavior.

`dashboard.tool_status()` specifics (worth knowing before touching the GUI):

- Every card's `db_status` / `db_updated` is derived **only** from
  `artifacts/provenance/<tool>.json`. No provenance file → the barrel is
  permanently empty, even if the DB exists in its volume. That was the Trivy
  bug fixed in `62fc073`.
- Date semantics differ per scanner, so each card also carries
  `db_updated_kind` (`built` | `imported` | `null`) and the GUI labels it
  (`· сборка` / `· импорт`, with a tooltip):
  - Grype → `built` (when upstream built the DB) → `built`;
  - Trivy → `db_updated_at` (`UpdatedAt` from `db/metadata.json`) → `built`,
    falling back to the update-run clock → `imported`;
  - cve-bin-tool → `timestamp_utc` (when *we* ran the import — the NVD JSON
    feeds carry no DB build date) → always `imported`.
- cve-bin-tool per-source counts come from `cve_range_by_source`. cve-bin-tool
  writes its own spelling, and `curl_source.py` uses `SOURCE = "Curl"` while
  the rest are upper-case — the lookup is case-insensitive since `fc0d59d`.
- Sources listed in `CVE_BIN_TOOL_ENRICH_DISABLE` render as a red ✕
  ("unavailable in this contour") instead of a misleading 0% barrel.

## Docker Compose Profiles

Important profiles:

- `default`: base scanner stack.
- `update`: DB update services.
- `scan`: full scan services.
- `extract`: artifact extraction.
- `report`: report collection.
- `offline`: scan with prewarmed caches/mirrors.
- `airgap`: stricter offline path.
- `test-failover`: mock feed/failover checks.
- `apk`: APK analyzer.
- `win`: Windows installer analyzer.
- `osv`: optional OSV scanner.
- `proxy`: Xray + tinyproxy sidecars.
- `vpn`: WireGuard sidecar.
- `dashboard`: containerized read-only dashboard.
- `db-bundle`: DB volume export/import.
- `route`: route-doctor egress probing.
- `volinit`: named volume / artifacts ownership normalization.
- `storage`: SeaweedFS S3 service.
- `storage-tools`: MinIO `mc` client container.

The active dashboard is normally run on the host with Python. The compose
dashboard profile is read-only by default.

## Scan Flow

Typical flow:

```text
target artifact
  -> artifact-extractor
  -> artifacts/extracted/current
  -> Syft SBOM
  -> Grype / Trivy / cve-bin-tool / optional OSV
  -> report-collector
  -> final report + HTML + saved run snapshot
```

Visible stages:

```text
extract -> sbom -> grype -> trivy -> cve-bin-tool -> report
```

cve-bin-tool exit code `1` can mean findings were discovered and is treated as
a successful scan stage. Hard failures are tracked separately.

## Artifact And Snapshot Policy

Do not commit runtime output:

- `artifacts/`
- `_SCA_reports/`
- scanner DB caches
- generated raw reports/logs
- local `.env`
- `.pytest_cache/`, `.ruff_cache/`, `__pycache__/`

Current snapshot behavior:

- Default snapshot mode: `host`.
- Host mode saves under `_SCA_reports/<target-name>-<timestamp>/`.
- Legacy/fallback mode saves under `artifacts/runs/<project>-<timestamp>/`.
- `near-source` mode saves next to the scanned artifact.
- `auto` uses near-source when possible, otherwise `artifacts/runs`.

CLI:

```sh
python -m resilient_updates.cli archive-run --mode host
python -m resilient_updates.cli archive-run --mode artifacts
python -m resilient_updates.cli archive-run --mode near-source
```

`scripts/run-scan.sh` and `scripts/windows/run-scan.ps1` call `archive-run`
after scans. Use `EL_SCA_ARTIFACT_MODE=host|artifacts|near-source|auto` or
`--artifact-mode` to choose layout.

Snapshot contents normally include manifests, checkpoints, SBOMs, raw scanner
reports, final reports, provenance, sidecar JSON files, extraction manifests,
and logs. The full extracted tree is not copied by default.

Enable extracted tree archival only for heavy debug:

```sh
EL_SCA_ARCHIVE_EXTRACTED_TREE=1
```

Long-run checkpoints:

- `artifacts/pipeline_state.json` tracks stages.
- Periodic checkpoint snapshot interval:
  `EL_SCA_CHECKPOINT_INTERVAL_SECONDS`, default `3600`.
- Heartbeat interval: `EL_SCA_HEARTBEAT_SECONDS`, common default `30`.

Resume:

```sh
./scripts/run-scan.sh --resume -t /path/to/artifact
.\scripts\windows\run-scan.ps1 -Target "C:\path\artifact.zip" -Resume
```

## Dashboard And Monitor

Dashboard launch:

```sh
python -m resilient_updates.cli dashboard --repo-root . --port 8080
```

Important APIs:

- `GET /api/tools`: tool versions and DB status cards.
- `POST /api/update-db?target=all|trivy|grype|cve-bin-tool`: DB update job.
- `POST /api/scan`: upload and scan an artifact.
- `POST /api/scan/resume`: resume latest compatible checkpoint.
- `GET /api/jobs/{id}`: job snapshot.
- `GET /api/jobs/{id}/stream`: SSE stream with stage/log/progress updates.
- `GET /api/monitor`: pipeline, containers, DB status, latest run snapshot.
- `GET /api/runs`: current and saved runs (sorted newest-first by the
  `YYYYMMDD-HHMMSS` stamp; each entry carries `markdown_report_path`).
- `GET /api/runs/{run_id}/report.md`: the run's final Markdown report, inline
  as `text/markdown; charset=utf-8` (for copy/hand-off; 404 if the run has no
  `.md`). `GET /runs` (HTML) groups runs by date and links each `report.md`.
- `GET /api/route-plan`: current route plan.
- `POST /api/route-plan`: rerun route-doctor.
- `GET/POST /api/proxy-chain`: inspect/switch proxy chain.
- `GET /api/artifacts`: Artifact Catalog list.
- `POST /api/artifacts/upload`: add artifact to catalog.
- `PATCH /api/artifacts/{artifact_id}`: update catalog metadata.
- `DELETE /api/artifacts/{artifact_id}`: remove catalog artifact.
- `GET /api/artifacts/{artifact_id}/runs`: list runs for one artifact.
- `POST /api/artifacts/{artifact_id}/scan`: scan catalog artifact.

CLI monitor:

```sh
python -m resilient_updates.cli monitor --watch 5
python -m resilient_updates.cli monitor --json
```

## Environment Defaults

Canonical template: `.env.example`. Local `.env` is ignored and may contain
secrets.

Scan target defaults:

```text
SCAN_TARGET_HOST=/absolute/path/to/artifact-or-directory
EXTRACT_INPUT_HOST=/absolute/path/to/artifact-or-directory
SCAN_TARGET_DISPLAY=/absolute/path/to/artifact-or-directory
REPORT_OUTPUT=/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md
TRIVY_TARGET=alpine:latest
GRYPE_TARGET=alpine:latest
SYFT_TARGET=alpine:latest
SYFT_FROM=registry
CVE_BIN_TOOL_TARGET=/scan-target
```

Empty credential placeholders:

```text
TRIVY_INTERNAL_REGISTRY_USERNAME=
TRIVY_INTERNAL_REGISTRY_PASSWORD=
GRYPE_CUSTOM_AUTH_TOKEN=
CVE_BIN_TOOL_MIRROR_TOKEN=
SYFT_REGISTRY_USERNAME=
SYFT_REGISTRY_PASSWORD=
GITHUB_TOKEN=
```

S3 defaults:

```text
EL_SCA_S3_PORT=8333
EL_SCA_S3_ENDPOINT=http://seaweedfs:8333
EL_SCA_S3_BUCKET=el-sca
EL_SCA_S3_ACCESS_KEY=el-sca
EL_SCA_S3_SECRET_KEY=el-sca-secret
EL_SCA_S3_ALIAS=elsca
SEAWEEDFS_VERSION=4.38
MINIO_MC_VERSION=RELEASE.2025-08-13T08-35-41Z
```

Rotate these S3 credentials for any real/shared environment.

Linux ownership defaults:

```text
LOCAL_UID=1000
LOCAL_GID=1000
```

cve-bin-tool defaults from `.env.example`:

```text
CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS=1800
CVE_BIN_TOOL_DB_POLICY=degraded-ok
CVE_BIN_TOOL_DISABLE_SOURCES_ON_RETRY=OSV
CVE_BIN_TOOL_PATCH_OSV_MISSING_TYPE=0
CVE_BIN_TOOL_UPDATE_MODES=feed
CVE_BIN_TOOL_SEED_AUX=0
CVE_BIN_TOOL_UPDATE_TIMEOUT_SECONDS=7200
CVE_BIN_TOOL_PARALLEL=
CVE_BIN_TOOL_AUTO_SBOM=1
CVE_BIN_TOOL_INJECT_GO_RUNTIME=1
CVE_BIN_TOOL_MAX_FILE_MB=256
```

Note: this used to be "two truths" — `.env.example` and
`scripts/update_cve_bin_tool.sh` documented `600` while `scripts/run-scan.sh`,
`scripts/windows/run-scan.ps1` and the `docker-compose.yml` scan-service
fallback all used `1800`. Unified on the runtime value `1800` in `029333f`.

Extractor and Grype:

```text
EXTRACT_MAX_MEMBER_SIZE_MB=0
GRYPE_DB_MAX_ALLOWED_BUILT_AGE=168h
```

Proxy defaults:

```text
HTTP_PROXY=
HTTPS_PROXY=
NO_PROXY=localhost,127.0.0.1,grype-static
ALL_PROXY=
EL_SCA_AUTO_ROUTE=1
```

Sidecar proxy examples:

```text
HTTP_PROXY=http://tinyproxy:8888
HTTPS_PROXY=http://tinyproxy:8888
ALL_PROXY=socks5h://proxy-xray:1080
NO_PROXY=localhost,127.0.0.1,grype-static,tinyproxy,proxy-xray
```

## Updates, Network, Proxy

Default policy: scanner DB updates are explicit. Run update commands before
scan when fresh DBs are required.

Update runner:

```sh
./scripts/update-db.sh all
./scripts/update-db.sh trivy
./scripts/update-db.sh grype
./scripts/update-db.sh cve-bin-tool
```

Auto-route:

- route-doctor probes egress from inside the Docker network.
- It can select direct, proxy, VPN, or sidecar routes per tool.
- It is on by default for update paths.
- Disable with `EL_SCA_AUTO_ROUTE=0` or `--no-auto-route`.
- Existing host proxy variables are honored.

Trivy DB registries (`configs/feed_sources.yaml` → `trivy.db_repositories`,
`trivy.java_db_repositories`), in priority order:

1. `mirror.gcr.io/aquasec/trivy-db:2` / `trivy-java-db:1` — priority `15`,
   upstream Trivy's own default. **Preferred**: manifest *and* blobs are served
   from Google hosts.
2. `ghcr.io/aquasecurity/...` — priority `20`. Works for manifests, but blob
   downloads redirect to `pkg-containers.githubusercontent.com`, which
   TLS-inspecting corporate proxies re-sign with a private CA. Trivy then dies
   with `x509: certificate signed by unknown authority`.
3. `public.ecr.aws/aquasecurity/...` — priority `30`. Resolves, but its blob CDN
   is not reachable from every contour (connection stalls, no error).

`trivy-checks` has no `mirror.gcr.io` copy (404), so it stays on ghcr. That is
harmless: the update path only calls `--download-db-only` and
`--download-java-db-only`.

cve-bin-tool update routing:

- `.env.example` defaults `CVE_BIN_TOOL_UPDATE_MODES=feed` for from-scratch
  deploys.
- `scripts/update_cve_bin_tool.sh` has an internal fallback of
  `json-mirror json-nvd api2` if env is unset.
- `degraded-ok` is the robust out-of-box DB activation policy.
- Use `strict` only when all declared observable sources must be present.

## Internal S3 Storage

S3-compatible storage is provided by SeaweedFS.

> Reality check (verified 2026-07-09):
>
> - **The S3 layer works.** Brought up locally: `mc alias set` + `mb` + `ls`
>   authenticate with the `el-sca` identity from `configs/seaweedfs/s3.json`,
>   and anonymous `GET /` is correctly refused (`403 AccessDenied`).
> - **The startup error is benign.** SeaweedFS ≥ 4.x logs
>   `Failed to load IAM configuration: no signing key found for STS service`.
>   That is the *new STS/assume-role* subsystem, not the static identities the
>   project uses; the S3 API still starts and enforces them. Ignore it (or set
>   `jwt.filer_signing.key` in `security.toml` if you ever want STS).
> - **Versions are pinned** (`SEAWEEDFS_VERSION`, `MINIO_MC_VERSION` in
>   `versions.env`). They used to default to `latest`, which silently drifted
>   the storage layer — the one thing `versions.env` exists to prevent.
> - **It is not deployed on `10.2.108.47`** — the `storage` profile was never
>   brought up, so nothing listens on `8333` and `artifacts/mirror/` is empty;
>   `EL_SCA_RESULTS_TO_S3` and `make s3-*` are inert there. Nothing is broken,
>   it is simply off. There, "the S3 artifacts" are the on-disk tree
>   `artifacts/runs/` + `_SCA_reports/` + `artifacts/uploads/` — that is the evidence.
> - `s3-client` (profile `storage-tools`) `depends_on` `seaweedfs` (profile
>   `storage`), so it must be invoked with **both** profiles and `--no-deps`.
>   `scripts/s3_storage.sh` and `resilient_updates/s3_publish.py` both do this
>   correctly; a bare `--profile storage-tools run s3-client` fails with
>   `depends on undefined service "seaweedfs"`.

Services:

- `seaweedfs`: compose profile `storage`.
- `s3-client`: MinIO `mc`, compose profile `storage-tools`.

Endpoints:

```text
Docker endpoint: http://seaweedfs:8333
Host endpoint:   http://127.0.0.1:8333
Bucket:          el-sca
Alias:           elsca
```

Commands:

```sh
make s3-init
make s3-db-push
make s3-db-pull
make s3-db-pull SLOT=previous
make s3-results-push
make s3-results-push RUN=_SCA_reports/<run-id>
```

Direct script:

```sh
./scripts/s3_storage.sh init
./scripts/s3_storage.sh db-push
./scripts/s3_storage.sh db-pull latest
./scripts/s3_storage.sh cve-source-push nvd artifacts/nvd-feeds
./scripts/s3_storage.sh results-push _SCA_reports/<run-id>
./scripts/s3_storage.sh ls scans/latest
```

Python CLI:

```sh
python -m resilient_updates.cli s3-results-push
python -m resilient_updates.cli s3-results-push _SCA_reports/<run-id>
```

Auto publish after scan:

```sh
EL_SCA_RESULTS_TO_S3=1 ./scripts/run-scan.sh -t /path/to/artifact
EL_SCA_RESULTS_TO_S3=1 python -m resilient_updates.cli dashboard --repo-root . --port 8080
```

Bucket layout:

```text
s3://el-sca/db/<tool>/latest/
s3://el-sca/db/<tool>/previous/
s3://el-sca/db/all/latest/
s3://el-sca/db/all/previous/
s3://el-sca/db/cve-bin-tool/sources/<source>/latest/
s3://el-sca/scans/<run-id>/
s3://el-sca/scans/latest/
s3://el-sca/scans/previous/
```

## Deployment: 10.2.108.47

The working deployment (SOC contour). Verified 2026-07-09.

```text
host      p7701v17redos11.soc.rt.ru (RED OS 8.0.2)
ssh       yuriy.tumanov@10.2.108.47   (key ~/.ssh/rostel-openkey)
repo      /home/SCA/el-sca-ansamble
web UI    http://10.2.108.47:8088/
git       single remote `origin` -> GitLab (there is NO GitHub remote there)
```

Important and easy to trip over:

- `origin` means **different things** locally and on the host: GitHub locally,
  GitLab on the deployment. A blind `git pull origin master` is not the same
  command in both places.
- The dashboard runs as a bare **root** process on `0.0.0.0:8088`, with **no
  authentication**, started by hand (`PPID 1`, no systemd unit). It will not
  survive a reboot, and anyone on the network can upload artifacts, launch
  scans, flip the proxy chain and delete artifacts. Known and accepted for now.
- The dashboard **loads `.env` into its own process environment at startup**,
  and `docker compose` gives the process env precedence over the `.env` file.
  So editing `.env` has no effect until the dashboard is restarted.
- `yuriy.tumanov` is not in the `docker` group but has `sudo NOPASSWD: ALL`.
- Do not touch `artifacts/runs/` and `artifacts/uploads/` — saved analysis
  evidence (`CYBERSEC-*` runs). They are gitignored and survive `git pull`.

Update procedure (local → both remotes → deployment):

```sh
# on the host, as yuriy.tumanov
cd /home/SCA/el-sca-ansamble
git fetch origin master && git merge --ff-only origin/master
# restart the dashboard only if Python code or .env changed
sudo pkill -f 'resilient_updates.cli dashboard'
sudo sh -c 'cd /home/SCA/el-sca-ansamble && nohup python3 -m resilient_updates.cli \
  dashboard --repo-root /home/SCA/el-sca-ansamble --host 0.0.0.0 --port 8088 \
  >> artifacts/logs/dashboard.log 2>&1 &'
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8088/
```

### Egress in this contour

Outbound HTTPS goes through the corporate proxy `http://10.2.204.162:3128/`
(set in `.env`; direct egress times out). A **Fortinet** appliance
(`CN=FG1K5DT920800115`) TLS-inspects *some* hosts, and its CA is **not** in the
host trust store nor on the operator workstation. Empirically:

| Host | Result |
|------|--------|
| `mirror.gcr.io`, `storage.googleapis.com` | clean (Google Trust Services) — **use this** |
| `ghcr.io` | clean, but blobs redirect to `pkg-containers.githubusercontent.com` → **Fortinet-resigned → x509 failure** |
| `public.ecr.aws` | clean manifest, blob CDN **stalls** |
| `grype.anchore.io`, `services.nvd.nist.gov`, `nvd.nist.gov/feeds` | reachable |
| `gitlab.com`, `access.redhat.com`, `curl.se`, `github.com`, `osv-vulnerabilities.storage.googleapis.com` | reachable, clean |

Do **not** "fix" this with `--insecure` / skipping TLS verification. The correct
fix is either a source that is not inspected (`mirror.gcr.io`) or installing the
corporate CA — which nobody currently has.

### Deployment-local `.env` deltas

These live only on the host (`.env` is gitignored). A backup of the pre-change
file is kept as `.env.bak-20260709-145601`.

```text
CVE_BIN_TOOL_UPDATE_MODES=feed
CVE_BIN_TOOL_FEED_ENRICH=1          # was 0 -> aux sources were never fetched at all
CVE_BIN_TOOL_ENRICH_DISABLE=OSV EPSS PURL2CPE
NVD_API_KEY=                        # unset; the feed path does not need it
HTTP_PROXY=http://10.2.204.162:3128/
```

Why those three sources are disabled (all upstream, none fixable by config):

- **OSV** — cve-bin-tool 3.4 downloads 779 232 advisory JSONs and buffers them
  in RAM: it reached 20.5 GiB of 23.7 GiB before being killed. Do not re-enable
  on a 24 GiB box.
- **EPSS** — upstream bug: `get_cve_data()` calls `await self.update_epss()`
  while the signature is `update_epss(self, cursor)`. Guaranteed `TypeError`,
  swallowed by a broad `except` and reported as "Unable to fetch EPSS".
- **PURL2CPE** — `OperationalError: no such table: purl2cpe`, and it aborts the
  **whole** enrichment pass (`exit=1`), taking GAD/RedHat down with it.

With them disabled, enrichment returns `exit=0` and the DB gets NVD + GAD +
REDHAT + Curl. `RSD` yields zero rows without erroring, so it stays an empty
(not ✕) barrel. `cve-bin-tool` therefore sits at `degraded` / 80% by design —
that is `degraded-ok` working as intended, not a failure.

### DB state after the 2026-07-09 refresh

```text
Grype         active     built 2026-07-09T07:25:16Z
Trivy         active     db UpdatedAt 2026-07-09T07:49:39Z (java-db 2026-07-09T01:51:59Z)
cve-bin-tool  degraded   imported 2026-07-09T16:03:47Z
              NVD 2 540 458 · GAD 73 324 · REDHAT 296 836 · Curl 206
              OSV / EPSS / PURL2CPE = ✕ unavailable · RSD = 0
```

### Container code vs mounted code

`docker-compose.yml` mounts the repo at `/workspace` and sets
`PYTHONPATH=/workspace:/opt/app`, so compose runs import the **mounted**
sources, not the ones baked into the image. Verified:

```text
standalone (no mount) -> /opt/app/resilient_updates/extractor.py   (stale)
compose (with mount)  -> /workspace/resilient_updates/extractor.py (current)
```

So a `git pull` is enough for compose-driven scans; standalone runs need the
image rebuilt.

**Rebuilt on the deployment 2026-07-09.** The three images that bake
`resilient_updates` (`extractor`, `cve-bin-tool`, `resilient-updater`) now carry
post-`cff6529` code — verified by hashing the baked file against the git blob
(`sha256 2724076cfd7fb125…`). The previous images are kept as
`:0.1.1-pre-cff6529` for rollback. They were **not** pushed to Docker Hub (that
needs registry credentials).

Build recipe (needs the corporate proxy for PyPI, which is *not* TLS-inspected):

```sh
sudo env DOCKER_BUILDKIT=1 docker build \
  --build-arg HTTP_PROXY=http://10.2.204.162:3128/ \
  --build-arg HTTPS_PROXY=http://10.2.204.162:3128/ \
  --build-arg NO_PROXY=localhost,127.0.0.1,.soc.rt.ru \
  -f Dockerfile.extractor -t elariaphd/el-sca-extractor:0.1.1 .
```

> ⚠️ **Tag drift:** the deployment's `.env` pins `EL_SCA_VERSION=0.1.1` while
> `versions.env`/`pyproject.toml` say `0.1.5`. So the host runs `:0.1.1` images.
> CI's `lint-versions` only compares versions.env / pyproject / compose fallback
> — it cannot see a deployment `.env`. Rebuild with the tag the host actually
> references, or realign both.

## Reports And Result Semantics

Final reports are written to:

- source-adjacent Markdown/HTML for operator handoff when enabled by layout;
- `artifacts/reports/final/` during live runs;
- `_SCA_reports/<run-id>/` or `artifacts/runs/<run-id>/` as saved evidence;
- S3 `scans/<run-id>/` and `scans/latest/` when publishing is enabled.

Important metadata:

- `input_sha256`: original top-level input identity.
- `db_snapshot_id`: DB layer identity for reproducibility.
- `tool_failures`: scanner/update failures.
- `db_drift`: refreshed/cached/missing/degraded/LKG state.
- `policy_decision`: policy gate outcome.
- raw severity totals are preserved for headline counts.

## Logs

Common runtime logs:

```text
artifacts/run-scan.log
artifacts/run-scan.log.1..5
_SCA_reports/<run-id>/job.log
artifacts/db_status/updates/*.log
artifacts/logs/dashboard.log
```

Logging settings:

```text
LOG_LEVEL=INFO
LOG_FORMAT=text
LOG_FILE=artifacts/logs/dashboard.log
LOG_MAX_BYTES=10485760
LOG_BACKUP_COUNT=5
EL_SCA_LOG_BACKUP_COUNT=5
EL_SCA_UPDATE_LOG_KEEP=50
EL_SCA_HEARTBEAT_SECONDS=30
```

Debug handoff:

```sh
docker compose ps
docker compose logs --no-color > artifacts/logs/compose-debug.log
python -m resilient_updates.cli monitor --json > artifacts/logs/monitor.json
```

## Config Files

- `.env.example`: documented env knobs.
- `.env`: local ignored overrides; may contain secrets; do not commit.
- `versions.env`: scanner/project image versions.
- `configs/feed_sources.yaml`: source priorities, retries, mirrors, policies.
- `configs/policy.json`: report policy gate.
- `configs/grype.yaml`, `configs/trivy.yaml`, `configs/syft.yaml`,
  `configs/cve-bin-tool.yaml`: scanner-specific config.
- `configs/xray/config.json`, `configs/tinyproxy/tinyproxy.conf`: proxy
  sidecars.
- `configs/wireguard/wg0.conf.example`: VPN profile template.
- `configs/seaweedfs/s3.json`: SeaweedFS S3 users for MVP storage.
- `configs/examples/*.yaml`: reproducible operator examples, not raw evidence.

## Scripts

Recommended scan entrypoints:

- `scripts/run-scan.sh`: POSIX full pipeline.
- `scripts/windows/run-scan.ps1`: Windows full pipeline.
- `scripts/batch-scan.sh`: POSIX batch runs.
- `scripts/windows/batch-scan.ps1`: Windows batch runs.

Other important scripts:

- `scripts/update-db.sh`: update DBs with route-doctor support.
- `scripts/remote_analysis.sh`: remote-host repeatable flow.
- `scripts/s3_storage.sh`: S3 DB/result publishing.
- `scripts/make-high-critical-report.sh`: Critical/High digest.
- `scripts/export_db_image.sh`, `scripts/import_db_image.sh`: DB image flow.
- `scripts/export_images.sh`, `scripts/import_images.sh`: offline image bundle.
- `scripts/clean_generated.sh`: generated-file cleanup.
- `scripts/bootstrap.sh`: fresh clone deploy path.
- `scripts/preflight_compose.sh`: env/compose guard checks.

Do not treat `run_scan.sh` as the normal full pipeline; use `run-scan.sh`.

## Tooling And CI

Ruff:

- target: Python 3.12;
- line length: 110;
- source dirs: `resilient_updates`, `tests`, `scripts`;
- formatter uses double quotes and spaces;
- selected rules: `E`, `F`, `W`, `I`, `UP`, `B`, `C4`, `SIM`, `PIE`, `RUF`;
- ignored globally: `E501`, `B008`, `SIM108`.

Pytest:

- test root: `tests`;
- strict markers enabled;
- markers: `smoke`, `slow`, `integration`;
- Docker/network-heavy tests should be marked `integration`.

Makefile coverage gate:

```sh
python -m pytest -q --disable-warnings -m "not integration" \
  --cov=resilient_updates --cov-report=term-missing --cov-fail-under=88
```

CI files:

- `.github/workflows/ci.yml`.
- `.gitlab-ci.yml`.
- `.pre-commit-config.yaml`.
- `.yamllint`.
- `.hadolint.yaml`.

CI/check groups include pre-commit, ruff, format check, compileall, shellcheck,
hadolint, yamllint, PSScriptAnalyzer, version consistency, compose config,
docker build, smoke, and pytest with coverage gate.

## Current Carry-Forward (updated 2026-07-09, post audit 660)

Done since audit 660:

- ~~Push current `master` to `origin` and `gitlab`~~ — both remotes at `fc0d59d`, `0/0`.
- ~~cve-bin-tool scan timeout "two truths"~~ — unified on `1800` (`029333f`).
- ~~Trivy DB never updated / no date in GUI~~ — `mirror.gcr.io` + `db_updated_at` (`62fc073`).
- ~~cve-bin-tool source barrels always empty~~ — `FEED_ENRICH=1` on the host + case-insensitive lookup (`fc0d59d`).

Open, security-flavoured (owner action required):

- **NVD API keys are committed in `docs/audit/10-defects.md`** and that file is
  present on `gitlab/master` **and on the public GitHub mirror**
  (`github.com/Eljees/el-sca-ansamble`, `visibility: public`). Introduced by a
  single commit (`39b35d1`, 2026-05-26); the keys never reached a committed
  `.env`. Rotating them at nvd.nist.gov is the only thing that actually
  neutralizes the exposure. Explicitly left untouched on the owner's
  instruction. A `detect-secrets`/pre-commit guard was deliberately **not**
  added, because it would fail CI on exactly these keys.
- Deployment dashboard runs as root on `0.0.0.0:8088` without auth and without
  systemd (see the Deployment section). Hardening deferred by the owner.
- `artifacts/` on the deployment is `0777` (~570 world-writable paths), created
  that way by the `volinit` profile. Evidence integrity risk.

Done since (2026-07-09, later pass):

- ~~Unify GUI date semantics~~ — each card now carries `db_updated_kind` and the
  barrel is labelled `· сборка` / `· импорт` with a tooltip.
- ~~S3 pinning~~ — `SEAWEEDFS_VERSION` / `MINIO_MC_VERSION` moved into
  `versions.env` (were unpinned `latest`).
- `default_report_path` was **not** broken: `/api/artifacts/{id}/runs` returns
  `reports/final/index.html` correctly. The confusion came from `/api/runs`,
  which simply does not carry that field.

Open, engineering:

- ~~Rebuild `elariaphd/el-sca-*` images~~ — done on the deployment (tag `0.1.1`,
  rollback tag `0.1.1-pre-cff6529`). Still **not pushed to Docker Hub** (needs
  registry credentials) and the bundle in `bundle/` still ships the old images.
- Realign `EL_SCA_VERSION`: deployment `.env` says `0.1.1`, repo says `0.1.5`.
- Enable the `storage` profile on the deployment if S3 mirroring is actually
  wanted there; rotate `el-sca` / `el-sca-secret` first (they are committed in
  `configs/seaweedfs/s3.json`, which is on the public GitHub mirror).
- Unify `s3_publish.py` and `scripts/s3_storage.sh` (duplicated S3 behaviour).
- Upstream cve-bin-tool 3.4 bugs to report or work around: EPSS `TypeError`,
  PURL2CPE `no such table`, OSV unbounded memory. Currently sidestepped with
  `CVE_BIN_TOOL_ENRICH_DISABLE`.
- Add stronger preflight automation for stale `.git/index.lock` cleanup.
- Add guard for FUSE-truncated files recovery if the environment needs it.
- Consider moving `[Unreleased]` to `v0.1.6` when release is ready.
- Add linux+offline compose overlays to compose-config CI if not already done.
- Monitor flaky `test_post_proxy_chain_roundtrip_all_values`.
- Eventually remove Python compatibility shims when minimum Python moves high
  enough.
- Windows `ssh.exe` (System32 and Program Files) is silently non-functional on
  the operator workstation: exits 1, prints nothing, will not even write an
  `-E` log. WSL `ssh` works. Runbooks that assume native Windows ssh will fail.

## Safe Cleanup

Before deleting large runtime output, preserve needed evidence:

```sh
python -m resilient_updates.cli archive-run --mode host --stage pre-clean --status archived
```

Then clean only ignored/generated files. Do not delete source, configs,
examples, or saved run snapshots without an explicit reason.

Makefile cleanup:

```sh
make clean
make clean-deep
```

`make clean-deep` removes Docker volumes/caches. Use it only when DB loss is
acceptable.

## Git Hygiene

Inspect before any push/pull/sync:

```sh
git status --short --branch --untracked-files=all
git remote -v
git branch -vv
git rev-list --left-right --count master...origin/master
git rev-list --left-right --count master...gitlab/master
```

Avoid force push unless explicitly approved. This repository often has local
commits ahead of one or both remotes.

## Do Not Commit

- `.env` or other local secret-bearing files.
- `_SCA_reports/`.
- raw runtime `artifacts/reports`, `artifacts/logs`, `artifacts/db_status`.
- `artifacts/run-scan.log*`.
- scanner DB caches and Docker volume dumps unless explicitly packaged.
- large/generated HTML/JSON evidence unless it is an intentional small example.

## Next Best Actions

1. Rotate the NVD API keys (owner-only, nvd.nist.gov) and decide whether to
   redact `docs/audit/10-defects.md` and/or make the GitHub mirror private.
2. Rebuild the `elariaphd/el-sca-*` images so standalone runs pick up
   `cff6529`.
3. Keep this file updated when storage layout, artifact layout, remotes,
   deployment facts, or operator commands change.
4. Continue GUI/operator work around visible container progress, live logs,
   report viewer, and resumable long-run snapshots.
