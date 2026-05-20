# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
loosely adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Delta from 2026-05-17 (PLAN_2026-05-17.md)

- **#22 Run-summary derivation.** New module
  `resilient_updates/run_summary.py` (`derive`, `write_to_disk`) computes
  the four sidecar JSONs (`summary.json`, `status.json`,
  `run_manifest.json`, `db_snapshot.json`) from existing scanner
  artefacts.  New CLI subcommand `python -m resilient_updates.cli
  write-run-summary --reports-dir <dir>` writes them to disk;
  `scripts/collect_reports.sh` calls it before assembling the final
  Markdown so the header stops showing `UNKNOWN` for DB snapshot, DB
  drift, tool failures, update policy, and input archive SHA-256.
  `reporting.build_report` also does the same derivation in-memory as a
  fallback when the files don't exist, so external invocations stay
  honest too.
- **#5.12 SBOM sanitiser.** `scripts/update_cve_bin_tool.sh` now always
  patches the SBOM before `--sbom-file`: it filters components whose
  `version` is empty / `null` / `unknown` (case-insensitive) so
  cve-bin-tool 3.4 no longer aborts mid-scan with
  `UnknownVersion('version string = UNKNOWN')`.  The same patcher
  injects Go runtime versions when found.
- **#5.14 -UpdateDb warning.** `scripts/windows/run-scan.ps1` prints a
  loud yellow banner when `-UpdateDb` is passed (5–15 min wait expected,
  link to `.env.local` NVD keys, instruction to drop the flag if not
  intentional).  Pairs with the existing DB freshness banner.
- **#5.13 Tests for new modules.**
  - `tests/test_scanner_diff.py` — components added/removed/version-change
    /severity-delta / Markdown headers.
  - `tests/test_enrichment.py` — EPSS CSV parser (incl. malformed rows),
    CISA KEV in both JSON shapes, `enrich_findings`.
  - `tests/test_proxy_chain.py` — Hop / ProxyChain / Policies dataclasses,
    `validate_chains` happy + 2 failure cases, ProxyRouter per-source pin,
    failover, session.proxies, `write_provenance`.
  - `tests/test_run_summary.py` — counts, single + multi-input sha,
    db_snapshot_id, empty root (no exception), timeout flag detection,
    `write_to_disk` creates 4 files, `overwrite=False` respected.
- **#5.15 `scripts/windows/batch-scan.ps1`** — reusable batch runner
  (inline `-Jobs`, `-JobsCsv`, `-JobsJson`).  Wraps each
  `run-scan.ps1` call in try/catch so a single failure doesn't abort the
  rest; prints a colour-coded SUMMARY (`syft / grype / cbt / sev`) per
  case; exit 2 if any case failed (CI-friendly).  `-UpdateDbOnce`
  refreshes DBs only for the first job; `-UpdateDbEvery` is opt-in for
  the truly paranoid.
- **#5.18 `scripts/batch-scan.sh`** — Linux/macOS mirror of `batch-scan.ps1`.
  Accepts `--case/--target` pairs (repeatable), `--jobs-json`, or
  `--jobs-csv`.  Same try-style continue-on-error semantics, same
  SUMMARY table, same exit code contract.
- **#5.20 `make batch`** — Makefile target.  `JOBS_JSON=…` or
  `JOBS_CSV=…`, optional `UPDATE_DB_ONCE=1`.  Delegates to
  `scripts/batch-scan.sh`.
- **#5.21 `--case-id` thread-through.** `scripts/run-scan.sh` already
  accepted `--case-id`; `scripts/batch-scan.sh` now passes it explicitly
  so the Markdown header is correct on the first try (the in-script
  regex rewrite is preserved as a safety net for older runs).
- **#5.22 `batches/` directory.** `example.csv`, `example.json`, and a
  `README.md` so users have a ready-to-edit shape for the runners.
  `.gitignore` keeps committed examples while preventing accidental
  upload of `daily.*` job lists.
- **#5.23 README "Что нового".** Top-level README now opens with a
  short pointer to the day's headline changes: batch-scan, sidecar
  JSON-derivation, DB freshness banner, no-update-by-default,
  `-UpdateDb` warning.
- **#5.26 CLI smoke for `write-run-summary`.** `tests/test_cli.py` got
  two new tests covering happy-path (4 sidecars created) and
  `--no-overwrite` (existing summary survives).
- **#5.28 `scripts/benchmark.sh`** — Linux/macOS mirror of
  `scripts/windows/benchmark.ps1`.  N back-to-back runs with `time`
  capture, JSON summary, host snapshot.

### Changed — Delta from 2026-05-17

- **#24 No-update-by-default profile policy.** `docker-compose.yml`:
  `trivy-updater` now sits in `["update"]`, `grype-updater` in
  `["update", "test-failover"]`, `cve-bin-tool-updater` in `["update"]`.
  All three have been removed from `default` and `offline` profiles.
  Plain `docker compose up` (without `--profile`) no longer attempts to
  reach out to upstream DB sources, and `offline` now genuinely means
  "scan only with local DB" — same semantics `airgap` already had.
- **`scripts/windows/run-scan.ps1` Clean step rewritten** to run via a
  one-shot `alpine sh -c 'find /cleanme -type f ! -name .gitkeep
  -delete'` container.  PowerShell's `Remove-Item` chokes on NTFS-illegal
  names like `app.\AvandocClient.cmd` that innoextract leaves when
  unpacking NSIS installers.  Docker sees the same paths through the 9P
  bind mount as plain ext4 and deletes them happily.  Fallback to
  in-process PowerShell + cmd.exe is preserved when Docker isn't
  reachable.

- **#5.24 `grype-static` healthcheck timing.** `start_period` 3s → 10s,
  `retries` 5 → 10.  Grace window for `grype-scanner` while DB-server
  warms up is now ≈ 60 s (matches `docs/runbook.md` §3.4 observation of
  5–20 s cold-start stabilisation on Docker Desktop).

### Fixed — Delta from 2026-05-17

- **cve-bin-tool binary scan crashed with `invalid choice: '8'`.** Phase
  3.4 mistakenly wired the worker count to cve-bin-tool's `-n` flag, but
  in v3.4 `-n` is reserved for `--nvd <mode>`.  Removed the
  `PARALLEL_FLAGS` from the binary-scan call site; binary scan still
  runs in parallel via cve-bin-tool's internal `multiprocessing.Pool`,
  sized to the host CPU count.  `CVE_BIN_TOOL_PARALLEL` is preserved as
  an env knob with a no-op note for the day upstream ships a real
  `--workers N` flag.

### Added — Phase 0–4 of PLAN_2026-05-16.md

- **Network / proxy / VPN layer.**
  - New optional sidecars in `docker-compose.yml`: `proxy-xray` (SOCKS5:1080
    + HTTP:8118), `tinyproxy` (HTTP front:8888, SOCKS5 upstream), `wireguard`
    (profile `vpn`).
  - Configurations under `configs/xray/` and `configs/tinyproxy/`.
  - YAML chains in `configs/feed_sources.yaml`:
    `proxy.chains`, `proxy.policies` (failover_order, healthcheck TTL,
    retry budget), `proxy.per_source` mapping.
  - New module `resilient_updates/proxy_chain.py` (`ProxyRouter`,
    `ProxyChain`, `Hop`, `Policies`, `validate_chains`).
  - New CLI command `python -m resilient_updates.cli proxy-status`
    writing `artifacts/provenance/proxy.json`.
  - `validate_proxy_config` now validates both flat and chained styles.
  - Documentation: `docs/network-design.md`, `docs/adr/0001-wrapper-first.md`,
    `docs/adr/0002-proxy-sidecar.md`.
  - `.env.example` block for the sidecar chain.

- **Windows acceleration (Phase 3).**
  - `scripts/windows/setup-defender-exclusions.ps1` — idempotent Defender
    exclusions for project + Docker VHDX + WSL helpers; writes provenance.
  - `scripts/windows/benchmark.ps1` — wall-clock benchmark harness writing
    `artifacts/provenance/benchmark.json`.
  - `docker-compose.windows.override.yml` — tmpfs `/tmp` (4 GB for
    cve-bin-tool-scanner, 2 GB elsewhere) plus named volume
    `extracted-staging` so extractor scratch stays on ext4.
  - BuildKit cache mounts (`--mount=type=cache`) in every Dockerfile;
    `# syntax=docker/dockerfile:1.7` header on each.
  - cve-bin-tool parallelism: `CVE_BIN_TOOL_PARALLEL` env knob, auto-default
    to `nproc/2` (capped at 8).
  - Extractor pre-filter: `EXTRACT_MAX_MEMBER_SIZE_MB` and the existing
    `--skip-ext`/`--max-member-size-mb` CLI flags.

- **Quality / tooling (Phase 4).**
  - GitHub Actions workflow `.github/workflows/ci.yml`: lint (ruff,
    shellcheck, hadolint, yamllint, PSScriptAnalyzer), compose schema
    check, pytest with coverage.
  - Linter configs: `.ruff.toml`, `.hadolint.yaml`, `.yamllint`,
    `PSScriptAnalyzerSettings.psd1`.
  - `.pre-commit-config.yaml` with ruff, shellcheck, yamllint, hadolint,
    generic hygiene hooks.
  - `Makefile` with targets `validate`, `update`, `scan`, `report`, `full`,
    `test`, `lint`, `lint-py`, `lint-sh`, `lint-docker`, `lint-yaml`,
    `lock`, `hooks`, `clean`, `clean-deep`.
  - `requirements.in` (pip-tools source of truth) + workflow documentation
    inside `requirements.txt`.

### Changed

- **cve-bin-tool Go runtime injection now multi-version** (Phase 5.7).
  `scripts/update_cve_bin_tool.sh` previously took the first `go1.X.Y`
  string it saw in any binary and injected it as the single
  `golang:go` SBOM component, then `break`ed out of the binary walk.
  When a target ships several binaries built with different Go
  toolchains (e.g. Prometheus 3.11 had go1.23.0 and go1.26.1), only the
  first match made it into the SBOM and only one Go-runtime CVE
  matched per scan — silently undercounting.  The injection now:
  detects ELF files by magic bytes 0x7F-E-L-F (works on Windows
  NTFS bind-mounts where the executable bit is not preserved),
  collects every unique `go1.X.Y` across all ELFs, and adds each
  version as a separate `golang:go` CycloneDX component.  Result:
  a clean `run-scan.ps1 -Clean` against the reference Prometheus
  tarball now produces one finding per unique Go runtime, matching
  the binary-scan baseline.

- `docker-compose.yml`:
  - `grype-static` now has a `healthcheck` (Python urllib probe on `:8080`);
    `grype-scanner` gains a `depends_on: grype-static (service_healthy)`.
  - `cve-bin-tool-scanner` `SCAN_TARGET_HOST` default changed from `.`
    (a silent footgun mounting the whole repo) to fail-fast `:?`.
- `resilient_updates/healthcheck.py` extended to probe grype-db and
  cve-bin-tool-mirror layers in addition to the existing three trivy
  layers; the response now carries a `proxy` block with the active session
  settings.
- `scripts/run-scan.sh` / `scripts/run_scan.sh` got header banners to make
  the dash-vs-underscore naming collision obvious; `scripts/README.md`
  spells out who is who.
- `configs/feed_sources.yaml` proxy section reorganised to support both
  legacy flat form and the new chain form.

### Fixed

- `.env.example` no longer defines `HTTP_PROXY=` twice (the second blank
  declaration silently shadowed the corporate-proxy example).
- `.env.example` ordering: cve-bin-tool timeout block no longer embeds
  itself inside the proxy comment block.

### Documentation

- `PLAN_2026-05-16.md` — full audit + phased plan (root of repo).
- `docs/network-design.md` — sidecar topology, YAML chain schema,
  diagnostics, security notes.
- `docs/adr/0001-wrapper-first.md` — retroactive ADR capturing the
  wrapper-first decision.
- `docs/adr/0002-proxy-sidecar.md` — rationale and alternatives for the
  proxy chain.
- `scripts/README.md` — index of every shell/PS script with purpose,
  Docker dependency, and Windows mirror.

## [3.0.0] — 2026-05-15

Baseline: see `CHANGES_v3.0.md`.  Highlights:

- cve-bin-tool exit-code handling in `scripts/windows/run-scan.ps1` fixed
  (exit 1 = "CVEs found", not failure).
- Comprehensive deployment guide `DEPLOYMENT_GUIDE_FINAL.md` covering
  X-Ray SOCKS5 setup, SSH reverse tunnel, Docker proxy configuration.

## [2.0.0] — 2026-04-14

Internal release (see `docs/status-and-roadmap.md` Phase 1):

- Provenance handling rewritten (path resolved via `Path.resolve()` + `rglob`).
- `InvalidSchema` no longer retried for OCI sources.
- Deduplication of `attempted_sources` in provenance.
- Initial proxy support (flat env / yaml form).
- cve-bin-tool scan timeout wrapper.

[Unreleased]: https://example.invalid/el-sca-ansamble/compare/v3.0.0...HEAD
[3.0.0]: https://example.invalid/el-sca-ansamble/releases/tag/v3.0.0
[2.0.0]: https://example.invalid/el-sca-ansamble/releases/tag/v2.0.0
