#!/usr/bin/env sh
set -eu

MODE="${1:-update}"
TARGET="${2:-${CVE_BIN_TOOL_TARGET:-/scan-target}}"
CONFIG_PATH="${CONFIG_PATH:-configs/feed_sources.yaml}"
REPORT_DIR="${REPORT_DIR:-artifacts/reports/cve-bin-tool}"
DB_ROOT="${CVE_BIN_TOOL_DB_ROOT:-/root/.cache/cve-bin-tool}"
CVE_DISABLE_ARGS="--disable-data-source OSV --disable-data-source EPSS"
CVE_UPDATE_MODES="${CVE_BIN_TOOL_UPDATE_MODES:-json-mirror json-nvd api2}"
CVE_OSV_ECOSYSTEMS="${CVE_BIN_TOOL_OSV_ECOSYSTEMS:-Debian Ubuntu Alpine Go PyPI Maven npm Rust}"
NVD_API_KEY_PRIMARY="${NVD_API_KEY:-}"
NVD_API_KEY_SECONDARY="${NVD_API_KEY_FALLBACK:-}"

mkdir -p "$REPORT_DIR" "artifacts/provenance" "artifacts/mirror"
if [ "${CVE_BIN_TOOL_WRAPPER_HEALTHCHECK:-0}" = "1" ]; then
  python -m resilient_updates.cli --config "$CONFIG_PATH" update cve-bin-tool >/dev/null
fi

if ! command -v cve-bin-tool >/dev/null 2>&1; then
  echo "cve-bin-tool is not installed in this environment" >&2
  exit 3
fi

run_cve_update() {
  nvd_mode="$1"
  api_key="${2:-}"
  if [ -n "$api_key" ]; then
    cve-bin-tool --update now --nvd "$nvd_mode" --nvd-api-key "$api_key" $CVE_DISABLE_ARGS
  else
    cve-bin-tool --update now --nvd "$nvd_mode" $CVE_DISABLE_ARGS
  fi
}

case "$MODE" in
  update)
    updated=0
    for nvd_mode in $CVE_UPDATE_MODES; do
      if [ "$nvd_mode" = "api" ] || [ "$nvd_mode" = "api2" ]; then
        for api_key in "$NVD_API_KEY_PRIMARY" "$NVD_API_KEY_SECONDARY"; do
          [ -n "$api_key" ] || continue
          if run_cve_update "$nvd_mode" "$api_key"; then
            updated=1
            break
          fi
        done
        if [ "$updated" -eq 1 ]; then
          break
        fi
        if [ -z "$NVD_API_KEY_PRIMARY" ] && [ -z "$NVD_API_KEY_SECONDARY" ]; then
          if run_cve_update "$nvd_mode"; then
            updated=1
            break
          fi
        fi
      else
        if run_cve_update "$nvd_mode"; then
          updated=1
          break
        fi
      fi
    done
    [ "$updated" -eq 1 ] || exit 1
    if [ "${CVE_BIN_TOOL_SEED_AUX:-1}" = "1" ]; then
      set -- python -m resilient_updates.cli --config "$CONFIG_PATH" seed cve-bin-tool-aux --db-root "$DB_ROOT" --seed-epss
      for ecosystem in $CVE_OSV_ECOSYSTEMS; do
        set -- "$@" --osv-ecosystem "$ecosystem"
      done
      "$@"
    fi
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
