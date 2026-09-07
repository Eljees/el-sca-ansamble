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
# `set -f` guards the split: an unquoted expansion is also a glob expansion,
# so any rendered value containing `*` or `?` (a --skip-files pattern, a VEX
# path with a wildcard) would be matched against /workspace before Trivy ever
# saw it.  The server-side hotfix for CYBERSEC-14277 passed exactly such a glob
# through here and only survived because nothing under /workspace matched.
set -f
# shellcheck disable=SC2086
set -- $FLAGS
set +f

# CYBERSEC-14277: an exploded jar carries META-INF/maven/<g>/<a>/pom.xml —
# maven-archiver's copy of the *build* descriptor.  It declares compile/test/
# provided/optional dependencies that were resolved on the build machine and
# are NOT inside the jar, yet Trivy's pom analyzer reads it like a project
# manifest and reports each of them as a shipped package (on
# agent-3.29.3.tar.gz: bcprov-jdk18on, woodstox-core, ... "found" via the pom
# of xmlsec-2.3.4.jar; every CRITICAL in the report was such paper).  The jar
# itself is still recorded by the jar analyzer from pom.properties, so nothing
# real is lost.  TRIVY_SKIP_EMBEDDED_POM=0 restores the old behaviour.
# The pattern is single-quoted on purpose: it must reach Trivy unexpanded.
case "$MODE" in
  scan|offline)
    if [ "${TRIVY_SKIP_EMBEDDED_POM:-1}" != "0" ]; then
      set -- "$@" --skip-files '**/META-INF/maven/**/pom.xml'
    fi
    ;;
esac

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
    # --offline-scan is NOT optional in this contour.  Without it Trivy tries to
    # resolve Java POM parents from repo.maven.apache.org; egress here goes
    # through a corporate proxy, the request comes back "429 Too Many Requests",
    # and Trivy treats that as FATAL -> the whole stage dies and the report stays
    # empty.  Observed the moment we moved 0.64.1 -> 0.73.0 (2026-08-10): the
    # scan silently dropped from 6 findings to 0.  The trade-off is accepted:
    # offline mode may miss a JAR that carries no embedded pom.properties, which
    # is strictly better than a hard failure that reports nothing at all.
    trivy "$SCAN_KIND" --cache-dir "$CACHE_DIR" "$@" --skip-db-update --skip-java-db-update --skip-check-update --offline-scan --format json --output "$REPORT_DIR/report.json" "$TARGET"
    ;;
  offline)
    trivy "$SCAN_KIND" --cache-dir "$CACHE_DIR" "$@" --skip-db-update --skip-java-db-update --skip-check-update --offline-scan --format json --output "$REPORT_DIR/report.json" "$TARGET"
    ;;
  *)
    echo "Unsupported mode: $MODE" >&2
    exit 2
    ;;
esac
