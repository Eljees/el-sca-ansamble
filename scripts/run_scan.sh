#!/usr/bin/env sh
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
