#!/usr/bin/env sh
set -eu

REPORTS_DIR="${REPORTS_DIR:-artifacts}"
REPORT_OUTPUT="${REPORT_OUTPUT:-artifacts/reports/final/cve_analysis_report_generated_ru.md}"
HTML_REPORT_OUTPUT="${HTML_REPORT_OUTPUT:-artifacts/reports/final/index.html}"
SCAN_TARGET="${SCAN_TARGET:-${SCAN_TARGET_CONTAINER:-}}"
SCAN_TARGET_DISPLAY="${SCAN_TARGET_DISPLAY:-${SCAN_TARGET_HOST:-$SCAN_TARGET}}"
CASE_ID="${CASE_ID:-CYBERSEC-UNKNOWN}"

mkdir -p artifacts/reports/final artifacts/provenance artifacts/sbom \
         artifacts/reports/cve-bin-tool artifacts/reports/trivy artifacts/reports/grype artifacts/sbom

# Создать пустые плейсхолдеры для отчётов, которые сканеры не сформировали
# (например, cve-bin-tool упал без цели или trivy не смог подключиться к БД).
# build_report() требует наличия файлов; плейсхолдер явно отразится в Consistency warnings.
_ensure_report() {
  report_path="$1"
  tool_name="$2"
  empty_json="$3"
  if [ ! -f "$report_path" ]; then
    printf '%s' "$empty_json" > "$report_path"
    echo "[collect_reports] WARN: ${tool_name} report missing — created empty placeholder at ${report_path}" >&2
  fi
}

_ensure_report "artifacts/reports/cve-bin-tool/report.json" "cve-bin-tool" "[]"
_ensure_report "artifacts/reports/trivy/report.json"        "trivy"        '{"Results":[]}'
_ensure_report "artifacts/sbom/syft.json"                   "syft"         '{"artifacts":[],"source":{},"schema":{}}'
_ensure_report "artifacts/reports/grype/report.json"        "grype"        '{"matches":[]}'

# Phase 5.8 — derive summary.json / status.json / run_manifest.json /
# db_snapshot.json from existing artefacts so the report header stops
# showing "UNKNOWN".  Best-effort: failure here doesn't block the report.
python -m resilient_updates.cli --config "${CONFIG_PATH:-configs/feed_sources.yaml}" \
  write-run-summary --reports-dir "$REPORTS_DIR" \
  || echo "[collect_reports] WARN: write-run-summary failed, header may show UNKNOWN fields" >&2

# Deliverable names carry the case and the package: <CYBERSEC>_<pkg>_report.*
# instead of the historical generic cve_analysis_report_generated_ru.md /
# sca_report.xlsx that operators had to rename by hand for every ticket.
# Only applied when the caller kept the generic defaults — an explicit
# REPORT_OUTPUT/XLSX_REPORT_OUTPUT override wins.  Best-effort: with no
# case/package known the generic names stay.
REPORT_STEM="$(python -m resilient_updates.cli report-name \
  --case-id "$CASE_ID" --target "$SCAN_TARGET_DISPLAY" 2>/dev/null || true)"
if [ -n "$REPORT_STEM" ]; then
  FINAL_DIR="$REPORTS_DIR/reports/final"
  # Names vary per scan now, so the previous scan's deliverables must not
  # linger next to this one's (scans are serialised by ScanBusyError).
  rm -f "$FINAL_DIR"/*_report.md "$FINAL_DIR"/*_report.xlsx \
        "$FINAL_DIR/cve_analysis_report_generated_ru.md" "$FINAL_DIR/sca_report.xlsx" 2>/dev/null || true
  case "$REPORT_OUTPUT" in
    */cve_analysis_report_generated_ru.md) REPORT_OUTPUT="$FINAL_DIR/${REPORT_STEM}.md" ;;
  esac
  case "${XLSX_REPORT_OUTPUT:-}" in
    ""|*/sca_report.xlsx) XLSX_REPORT_OUTPUT="$FINAL_DIR/${REPORT_STEM}.xlsx" ;;
  esac
fi

python -m resilient_updates.cli collect-report \
  --reports-dir "$REPORTS_DIR" \
  --output "$REPORT_OUTPUT" \
  --target "$SCAN_TARGET" \
  --display-target "$SCAN_TARGET_DISPLAY" \
  --case-id "$CASE_ID"

if ! python /workspace/scripts/report_html.py \
  --artifacts-dir "$REPORTS_DIR" \
  --output "$HTML_REPORT_OUTPUT" \
  --target "$SCAN_TARGET_DISPLAY"; then
  echo "[collect_reports] WARN: HTML report generation failed" >&2
fi

# Excel workbook for triage (sort/filter by severity, cut a slice for the
# customer).  Non-fatal like the HTML step: the Markdown report is the
# contractual artefact, the spreadsheet is a convenience.
XLSX_REPORT_OUTPUT="${XLSX_REPORT_OUTPUT:-artifacts/reports/final/sca_report.xlsx}"
if ! python -m resilient_updates.cli report-xlsx \
  --reports-dir "$REPORTS_DIR" \
  --output "$XLSX_REPORT_OUTPUT" \
  --target "$SCAN_TARGET" \
  --display-target "$SCAN_TARGET_DISPLAY" \
  --case-id "$CASE_ID"; then
  echo "[collect_reports] WARN: XLSX report generation failed" >&2
fi
