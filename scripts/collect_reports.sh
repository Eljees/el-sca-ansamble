#!/usr/bin/env sh
set -eu

REPORTS_DIR="${REPORTS_DIR:-artifacts}"
REPORT_OUTPUT="${REPORT_OUTPUT:-artifacts/reports/final/cve_analysis_report_generated_ru.md}"
SCAN_TARGET="${SCAN_TARGET:-${SCAN_TARGET_CONTAINER:-}}"
SCAN_TARGET_DISPLAY="${SCAN_TARGET_DISPLAY:-${SCAN_TARGET_HOST:-$SCAN_TARGET}}"
CASE_ID="${CASE_ID:-CYBERSEC-11531}"

mkdir -p artifacts/reports/final artifacts/provenance artifacts/sbom
python -m resilient_updates.cli collect-report \
  --reports-dir "$REPORTS_DIR" \
  --output "$REPORT_OUTPUT" \
  --target "$SCAN_TARGET" \
  --display-target "$SCAN_TARGET_DISPLAY" \
  --case-id "$CASE_ID"
