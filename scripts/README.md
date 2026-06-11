# scripts/ — index of orchestration scripts

| Script | Purpose | Runs Docker? | Mirror on Windows |
|---|---|---|---|
| `run-scan.sh` *(dash)* | Full SCA pipeline: extract → scan (syft/trivy/grype/cve-bin-tool) → MD + HTML report + per-run snapshot (`--artifact-mode artifacts\|near-source\|auto`). Recommended entry point on Linux/macOS. | Yes (`docker compose`) | `windows/run-scan.ps1` |
| `batch-scan.sh` | Run `run-scan.sh` against multiple `{case, target}` pairs in one go. Loads jobs from `--case/--target`, `--jobs-json`, or `--jobs-csv`; tolerates per-job failures; prints SUMMARY; exit 2 if any job failed. | Yes (delegates) | `windows/batch-scan.ps1` |
| `benchmark.sh` | N consecutive runs of `run-scan.sh` against the same target with wall-clock timing.  Writes `artifacts/provenance/benchmark.json` (host snapshot + per-run timings + summary stats). Use to validate Phase-3 optimisations (`COMPOSE_FILE`, BuildKit cache, SBOM fast-path). | Yes (delegates) | `windows/benchmark.ps1` |
| `make-high-critical-report.sh` | Parses an existing `*_report_<DATE>.md` (and computes SHA-256 of the source archive) to produce a compact CYBERSEC-11531-style digest with only Critical/High findings, written next to the source report as `*_high_critical_<DATE>_ru.md`. Invoked automatically by `batch-scan.sh` after each successful job; can also be run standalone (`--target` / `--report` / `--jobs-json` / `--jobs-csv`). | No | `windows/make-high-critical-report.ps1` |
| `run_scan.sh` *(underscore)* | Native per-tool wrapper for the resilient-updater container or a developer host with tools already installed. Not the full pipeline. | No | — |
| `scan_archive.sh` | Stripped-down full pipeline focused on archive-style targets (extract → scan → report). Mostly superseded by `run-scan.sh`; kept for backward compatibility. | Yes | — |
| `preflight_compose.sh` | Preflight env/render validation for compose runs: normalizes `EXTRACT_INPUT_HOST`, checks absolute paths, catches unresolved `${...}` and trailing-brace path artifacts. | Yes (`docker compose config`) | — |
| `remote_analysis.sh` | Host-side operator wrapper for the repeatable remote-machine sequence: preflight, pull, proxy-status, DB refresh, freshness checks, then the full scan. | Yes | — |
| `update_trivy.sh` | Trivy update / scan stage entrypoint used by the `trivy-updater` / `trivy-scanner` services. Renders DB-repository flags via Python. | Inside container | `windows/update-trivy.ps1` |
| `update_grype.sh` | Grype DB update stage. Calls `python -m resilient_updates.cli update grype`. | Inside container | `windows/update-grype.ps1` |
| `update_cve_bin_tool.sh` | cve-bin-tool update + scan stages. Handles the multi-mode NVD fallback, audit, SBOM fast-path, and the scan timeout wrapper. | Inside container | `windows/update-cve-bin-tool.ps1` |
| `cvebt_export_bundle.sh` | Export cve-bin-tool DB cache into `artifacts/cve-bin-tool-bundles/` (`.tar.zst` + manifest + sha256) for offline transport. | Yes | — |
| `cvebt_import_bundle.sh` | Import a previously exported cve-bin-tool DB bundle, verify sha256, and activate via DB audit policy. | Yes | — |
| `diagnose_cvebt_update.sh` | Capability and optional network diagnostics for cve-bin-tool update modes (`api2/json-mirror/json-nvd`). | Yes | — |
| `run_syft.sh` | Thin wrapper around the `syft` CLI used by the SBOM step. | Inside container | `windows/run-syft.ps1` |
| `collect_reports.sh` | Aggregates raw scanner JSON into the final Markdown report (used by the `report-collector` service). | Inside container | — |
| `extract_artifacts.sh` | Thin wrapper around `resilient_updates.cli extract`. | Inside container | — |
| `clean_generated.sh` | Removes generated artifacts under `artifacts/` while preserving `.gitkeep`. | No | `windows/clean-generated.ps1` |
| `report_html.py` | Renders an HTML report from the Markdown one. | No | — |
| `smoke_test.sh` | Local smoke test (`validate-config`, basic CLI commands). | Yes | `windows/smoke-test.ps1` |
| `analyze_apk.py` | APK analyzer (extract, identify libs, synthesize SBOM). Runs inside `apk-analyzer` container. | Inside container | — |
| `analyze_win_installer.py` | Windows MSI/NSIS analyzer (extract, PE metadata, synthesize SBOM). Runs inside `win-analyzer` container. | Inside container | — |

## Why two scripts that look like `run scan`?

The dash/underscore variants exist on purpose. They sit in the same folder and look almost identical to a human eye, so each file now carries a header banner explaining its role. If you came here looking for "the entry point", you almost certainly want **`run-scan.sh`** (dash).

## Per-run artifacts

`run-scan.sh` and `windows/run-scan.ps1` keep the human MD/HTML reports next to the scanned source file. They also call `python -m resilient_updates.cli archive-run` to save a machine-readable snapshot with `MANIFEST.json` and `checkpoint.json`.

The default mode is `auto`: save next to the source artifact when possible, otherwise use `artifacts/runs/<project>-<timestamp>/`. Override with `--artifact-mode artifacts|near-source|auto` on POSIX or `-ArtifactMode artifacts|near-source|auto` on Windows. Set `EL_SCA_ARCHIVE_EXTRACTED_TREE=1` only when you intentionally want to copy the full extracted tree.

## Windows-specific notes

PowerShell mirrors live under [`scripts/windows/`](./windows/). They take the same arguments as their POSIX twins so cross-platform documentation stays straightforward.

A planned Phase-3 helper script — `windows/setup-defender-exclusions.ps1` — will register the project and its hot cache paths with Windows Defender so per-file scan overhead drops sharply on `artifacts/extracted/...` and the Docker Desktop VHDX. Not yet committed.
