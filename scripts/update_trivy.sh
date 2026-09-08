#!/usr/bin/env sh
set -eu

MODE="${1:-update}"
TARGET="${2:-${TRIVY_TARGET:-alpine:latest}}"
CONFIG_PATH="${CONFIG_PATH:-configs/feed_sources.yaml}"
REPORT_DIR="${REPORT_DIR:-artifacts/reports/trivy}"
CACHE_DIR="${TRIVY_CACHE_DIR:-/var/lib/resilient-db/trivy}"
FLAGS="${TRIVY_RENDERED_FLAGS:-}"
# rootfs, not fs (CYBERSEC-14277): Trivy analyses JAR/WAR/EAR files only in the
# image, rootfs and vm modes (the `jar` analyzer is TypeIndividualPkgs, disabled
# in fs/repo); `fs`/`repo` read manifests and lockfiles, and for an unpacked
# Java delivery that means exactly one kind of file -- the pom.xml that
# maven-archiver embedded into each jar under META-INF/maven/<g>/<a>/.
#
# That pom records the versions the jar was *built* against, which dependency
# mediation then overrides in the delivery.  Measured on agent-3.29.3.tar.gz
# (558 jars): fs = 406 pom packages / 19 findings, and five of the six
# (product, version) pairs behind them do not exist anywhere in the delivery --
# the pom declares jackson-databind 2.17.2, kafka-clients 3.7.1, commons-lang3
# 3.14.0/3.16.0/3.17.0, while the jars actually shipped are 2.21.5, 3.9.2 and
# 3.20.0 (only lz4-java 1.10.2 matched).  rootfs = 677 jar packages / 134
# findings against the versions that are really there.
#
# Every target this pipeline scans is a built delivery, so rootfs is the
# default; set TRIVY_SCAN_KIND=fs for a source tree (requirements.txt, go.mod,
# pom.xml as a real manifest).
SCAN_KIND="${TRIVY_SCAN_KIND:-rootfs}"

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
# through here and survived only because nothing under /workspace matched it.
set -f
# shellcheck disable=SC2086
set -- $FLAGS
set +f

# No --skip-files guard for embedded poms here, deliberately.  An earlier
# version of this script skipped `**/META-INF/maven/**/pom.xml` in the scan
# modes; aquasecurity/trivy#11203 established that the guard is both
# unnecessary and harmful:
#   * unnecessary, because the pom analyzer never runs in rootfs (it is
#     TypeLockfiles) and because it already drops every dependency outside
#     compile/runtime scope and every optional one -- parse.go filters them,
#     so test/provided declarations were never reported in the first place;
#   * harmful, because the path alone cannot separate the delivery's own
#     descriptor from an unpacked third-party jar's.  On an exploded WAR whose
#     META-INF/maven pom declares log4j-core 2.14.1, with the jar in
#     WEB-INF/lib, skipping the file removed log4j-core and its 7 findings
#     (CVE-2021-44228 among them) from the default report -- in fs mode that
#     pom is the only source of information about WEB-INF/lib.
# The mode above is the actual fix.  See CHANGELOG for the full correction.

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
