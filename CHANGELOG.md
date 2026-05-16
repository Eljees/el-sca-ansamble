# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
loosely adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
