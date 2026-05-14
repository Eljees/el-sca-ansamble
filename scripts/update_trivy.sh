#!/usr/bin/env sh
set -eu

MODE="${1:-update}"
TARGET="${2:-${TRIVY_TARGET:-alpine:latest}}"
CONFIG_PATH="${CONFIG_PATH:-configs/feed_sources.yaml}"
REPORT_DIR="${REPORT_DIR:-artifacts/reports/trivy}"
CACHE_DIR="${TRIVY_CACHE_DIR:-/var/lib/resilient-db/trivy}"
FLAGS="${TRIVY_RENDERED_FLAGS:-}"
SCAN_KIND="${TRIVY_SCAN_KIND:-fs}"

mkdir -p "$REPORT_DIR" "artifacts/provenance" "$CACHE_DIR"

if [ -z "$FLAGS" ]; then
  if command -v python >/dev/null 2>&1; then
    FLAGS="$(python -m resilient_updates.cli --config "$CONFIG_PATH" render-flags trivy)"
  else
    echo "TRIVY_RENDERED_FLAGS is required when python is unavailable in the trivy image" >&2
    exit 3
  fi
fi
if [ "${TRIVY_WRAPPER_HEALTHCHECK:-0}" = "1" ]; then
  python -m resilient_updates.cli --config "$CONFIG_PATH" update trivy >/dev/null
fi

case "$MODE" in
  update)
    # shellcheck disable=SC2086
    trivy image --cache-dir "$CACHE_DIR" --download-db-only $FLAGS
    # shellcheck disable=SC2086
    trivy image --cache-dir "$CACHE_DIR" --download-java-db-only $FLAGS
    ;;
  scan)
    # shellcheck disable=SC2086
    trivy "$SCAN_KIND" --cache-dir "$CACHE_DIR" $FLAGS --skip-db-update --skip-java-db-update --skip-check-update --format json --output "$REPORT_DIR/report.json" "$TARGET"
    ;;
  offline)
    # shellcheck disable=SC2086
    trivy "$SCAN_KIND" --cache-dir "$CACHE_DIR" $FLAGS --skip-db-update --skip-java-db-update --skip-check-update --offline-scan --format json --output "$REPORT_DIR/report.json" "$TARGET"
    ;;
  *)
    echo "Unsupported mode: $MODE" >&2
    exit 2
    ;;
esac
