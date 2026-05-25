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

python -m resilient_updates.cli collect-report \
  --reports-dir "$REPORTS_DIR" \
  --output "$REPORT_OUTPUT" \
  --target "$SCAN_TARGET" \
  --display-target "$SCAN_TARGET_DISPLAY" \
  --case-id "$CASE_ID"

if ! python /opt/app/scripts/report_html.py \
  --artifacts-dir "$REPORTS_DIR" \
  --output "$HTML_REPORT_OUTPUT" \
  --target "$SCAN_TARGET_DISPLAY"; then
  echo "[collect_reports] WARN: HTML report generation failed" >&2
fi
