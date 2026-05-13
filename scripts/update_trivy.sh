#!/usr/bin/env sh
set -eu

MODE="${1:-update}"
TARGET="${2:-${TRIVY_TARGET:-alpine:latest}}"
CONFIG_PATH="${CONFIG_PATH:-configs/feed_sources.yaml}"
REPORT_DIR="${REPORT_DIR:-artifacts/reports/trivy}"

mkdir -p "$REPORT_DIR" "artifacts/provenance" "artifacts/cache/trivy"

FLAGS="$(python -m resilient_updates.cli --config "$CONFIG_PATH" render-flags trivy)"
if [ "${TRIVY_WRAPPER_HEALTHCHECK:-0}" = "1" ]; then
  python -m resilient_updates.cli --config "$CONFIG_PATH" update trivy >/dev/null
fi

case "$MODE" in
  update)
    # shellcheck disable=SC2086
    trivy image --download-db-only --download-java-db-only $FLAGS
    ;;
  scan)
    # shellcheck disable=SC2086
    trivy image $FLAGS --skip-db-update --skip-java-db-update --skip-check-update --format json --output "$REPORT_DIR/report.json" "$TARGET"
    ;;
  offline)
    # shellcheck disable=SC2086
    trivy image $FLAGS --skip-db-update --skip-java-db-update --skip-check-update --offline-scan --format json --output "$REPORT_DIR/report.json" "$TARGET"
    ;;
  *)
    echo "Unsupported mode: $MODE" >&2
    exit 2
    ;;
esac
