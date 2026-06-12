#!/usr/bin/env sh
# ---------------------------------------------------------------------------
# run_scan.sh  (underscore!)  — NATIVE per-tool wrapper.
#
# This script invokes scanners (trivy / grype / syft / cve-bin-tool) that are
# installed DIRECTLY on the current host — no Docker, no compose, no
# resilient_updates orchestration.  Intended for ad-hoc smoke tests inside
# the resilient-updater container or on a developer machine where the tools
# are already on PATH.
#
# If you want the full pipeline (docker compose, profiles, MD/HTML reports,
# proxy support, provenance) — use the sibling script:
#
#       scripts/run-scan.sh        ← dash, full Linux pipeline
#       scripts/windows/run-scan.ps1  ← PowerShell equivalent
#
# Sibling-name disambiguation:
#       run-scan.sh   dash      = full pipeline, docker compose, reports
#       run_scan.sh   underscore = native per-tool wrapper, no docker
# ---------------------------------------------------------------------------
set -eu

TOOL="${1:-grype}"
TARGET="${2:-${GRYPE_TARGET:-alpine:latest}}"
FROM="${3:-${SYFT_FROM:-dir}}"

mkdir -p artifacts/reports/grype artifacts/reports/trivy artifacts/reports/cve-bin-tool artifacts/sbom

case "$TOOL" in
  trivy)
    /bin/sh scripts/update_trivy.sh scan "$TARGET"
    ;;
  grype)
    if command -v grype >/dev/null 2>&1 && [ -f artifacts/sbom/syft.json ]; then
      grype "sbom:artifacts/sbom/syft.json" -o json > artifacts/reports/grype/report.json
    elif command -v grype >/dev/null 2>&1; then
      grype "$TARGET" -o json > artifacts/reports/grype/report.json
    else
      echo "grype is not installed in this environment" >&2
      exit 3
    fi
    ;;
  syft)
    /bin/sh scripts/run_syft.sh "$TARGET" "$FROM" artifacts/sbom
    ;;
  cve-bin-tool)
    /bin/sh scripts/update_cve_bin_tool.sh scan "$TARGET"
    ;;
  *)
    echo "Unsupported tool: $TOOL" >&2
    exit 2
    ;;
esac
