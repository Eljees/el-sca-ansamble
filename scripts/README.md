# scripts/ — index of orchestration scripts

| Script | Purpose | Runs Docker? | Mirror on Windows |
|---|---|---|---|
| `run-scan.sh` *(dash)* | Full SCA pipeline: extract → scan (syft/trivy/grype/cve-bin-tool) → MD + HTML report. Recommended entry point on Linux/macOS. | Yes (`docker compose`) | `windows/run-scan.ps1` |
| `run_scan.sh` *(underscore)* | Native per-tool wrapper for the resilient-updater container or a developer host with tools already installed. Not the full pipeline. | No | — |
| `scan_archive.sh` | Stripped-down full pipeline focused on archive-style targets (extract → scan → report). Mostly superseded by `run-scan.sh`; kept for backward compatibility. | Yes | — |
| `update_trivy.sh` | Trivy update / scan stage entrypoint used by the `trivy-updater` / `trivy-scanner` services. Renders DB-repository flags via Python. | Inside container | `windows/update-trivy.ps1` |
| `update_grype.sh` | Grype DB update stage. Calls `python -m resilient_updates.cli update grype`. | Inside container | `windows/update-grype.ps1` |
| `update_cve_bin_tool.sh` | cve-bin-tool update + scan stages. Handles the multi-mode NVD fallback, audit, SBOM fast-path, and the scan timeout wrapper. | Inside container | `windows/update-cve-bin-tool.ps1` |
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

## Windows-specific notes

PowerShell mirrors live under [`scripts/windows/`](./windows/). They take the same arguments as their POSIX twins so cross-platform documentation stays straightforward.

A planned Phase-3 helper script — `windows/setup-defender-exclusions.ps1` — will register the project and its hot cache paths with Windows Defender so per-file scan overhead drops sharply on `artifacts/extracted/...` and the Docker Desktop VHDX. Not yet committed.
