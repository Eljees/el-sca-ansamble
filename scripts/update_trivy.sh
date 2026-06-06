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

# Convert the rendered flag string into POSIX positional parameters so that
# every subsequent invocation can use the correctly-quoted "$@" instead of
# the unquoted FLAGS variable.  Reference: docs/audit/10-defects.md section 8.
# shellcheck disable=SC2086
set -- $FLAGS

case "$MODE" in
  update)
    trivy image --cache-dir "$CACHE_DIR" --download-db-only "$@"
    trivy image --cache-dir "$CACHE_DIR" --download-java-db-only "$@"
    # Record provenance so the dashboard barrel reflects the refreshed DB.
    # The trivy image has no python; write a minimal JSON with /bin/sh.  The
    # DB's own build time (db/metadata.json -> UpdatedAt) is pulled in when
    # available, otherwise we fall back to the wall-clock download time.
    NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    DB_META="$CACHE_DIR/db/metadata.json"
    DB_UPDATED="$NOW"
    if [ -f "$DB_META" ]; then
      _u="$(sed -n 's/.*"UpdatedAt"[ ]*:[ ]*"\([^"]*\)".*/\1/p' "$DB_META" | head -n1)"
      [ -n "$_u" ] && DB_UPDATED="$_u"
    fi
    cat > "artifacts/provenance/trivy.json" <<EOF
{
  "activation_status": "active",
  "artifact_type": "trivy-db",
  "timestamp_utc": "$NOW",
  "db_updated_at": "$DB_UPDATED",
  "cache_dir": "$CACHE_DIR"
}
EOF
    ;;
  scan)
    trivy "$SCAN_KIND" --cache-dir "$CACHE_DIR" "$@" --skip-db-update --skip-java-db-update --skip-check-update --format json --output "$REPORT_DIR/report.json" "$TARGET"
    ;;
  offline)
    trivy "$SCAN_KIND" --cache-dir "$CACHE_DIR" "$@" --skip-db-update --skip-java-db-update --skip-check-update --offline-scan --format json --output "$REPORT_DIR/report.json" "$TARGET"
    ;;
  *)
    echo "Unsupported mode: $MODE" >&2
    exit 2
    ;;
esac
