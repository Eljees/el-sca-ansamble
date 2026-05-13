#!/usr/bin/env sh
set -eu

MODE="${1:-update}"
TARGET="${2:-${CVE_BIN_TOOL_TARGET:-/scan-target}}"
CONFIG_PATH="${CONFIG_PATH:-configs/feed_sources.yaml}"
REPORT_DIR="${REPORT_DIR:-artifacts/reports/cve-bin-tool}"
DB_ROOT="${CVE_BIN_TOOL_DB_ROOT:-/root/.cache/cve-bin-tool}"

mkdir -p "$REPORT_DIR" "artifacts/provenance" "artifacts/mirror"
if [ "${CVE_BIN_TOOL_WRAPPER_HEALTHCHECK:-0}" = "1" ]; then
  python -m resilient_updates.cli --config "$CONFIG_PATH" update cve-bin-tool >/dev/null
fi

if ! command -v cve-bin-tool >/dev/null 2>&1; then
  echo "cve-bin-tool is not installed in this environment" >&2
  exit 3
fi

case "$MODE" in
  update)
    cve-bin-tool --update now
    python -m resilient_updates.cli --config "$CONFIG_PATH" audit cve-bin-tool-db --db-root "$DB_ROOT"
    ;;
  scan)
    if [ "${CVE_BIN_TOOL_VERIFY_DB:-1}" = "1" ]; then
      python -m resilient_updates.cli --config "$CONFIG_PATH" audit cve-bin-tool-db --db-root "$DB_ROOT" >/dev/null
    fi
    cve-bin-tool --offline --format json --output-file "$REPORT_DIR/report.json" "$TARGET"
    ;;
  export)
    cve-bin-tool --export "artifacts/mirror/cve-bin-tool-export.json"
    ;;
  import)
    cve-bin-tool --import "artifacts/mirror/cve-bin-tool-export.json"
    ;;
  *)
    echo "Unsupported mode: $MODE" >&2
    exit 2
    ;;
esac
