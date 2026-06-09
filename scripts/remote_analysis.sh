#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/remote_analysis.sh -t /abs/path/to/artifact [--case-id CYBERSEC-12345]

What it does:
  1) validates compose rendering and target paths,
  2) pulls the prod images from Docker Hub,
  3) refreshes Trivy / Grype / cve-bin-tool DBs,
  4) checks DB freshness and proxy routing,
  5) runs the full scan pipeline without re-updating DBs,
  6) leaves reports next to the target artifact.
EOF
}

TARGET=""
CASE_ID=""
SKIP_PULL=0
SKIP_UPDATE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target)
      TARGET="${2:-}"
      shift 2
      ;;
    --case-id)
      CASE_ID="${2:-}"
      shift 2
      ;;
    --skip-pull)
      SKIP_PULL=1
      shift
      ;;
    --skip-update)
      SKIP_UPDATE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "ERROR: -t/--target is required" >&2
  usage >&2
  exit 2
fi

if [[ ! -e "$TARGET" ]]; then
  echo "ERROR: target does not exist: $TARGET" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -f ".env" && -f ".env.example" ]]; then
  echo "[remote-analysis] WARN: .env is missing; copy .env.example before running on a remote host" >&2
fi

TARGET_RESOLVED="$(realpath "$TARGET")"
export COMPOSE_FILE="docker-compose.yml:docker-compose.prod.yml"
export SCAN_TARGET_HOST="$TARGET_RESOLVED"
export EXTRACT_INPUT_HOST="$TARGET_RESOLVED"
export SCAN_TARGET_DISPLAY="$TARGET_RESOLVED"
export REPORT_OUTPUT="/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md"
export CASE_ID="${CASE_ID:-}"

compose=(docker compose -f docker-compose.yml -f docker-compose.prod.yml)

echo "[remote-analysis] repo        : $REPO_ROOT"
echo "[remote-analysis] target      : $TARGET_RESOLVED"
echo "[remote-analysis] compose file: $COMPOSE_FILE"

./scripts/preflight_compose.sh

if [[ "$SKIP_PULL" -eq 0 ]]; then
  "${compose[@]}" pull
fi

set +e
"${compose[@]}" run --rm db-admin proxy-status
proxy_rc=$?
set -e
if [[ "$proxy_rc" -ne 0 ]]; then
  echo "[remote-analysis] WARN: proxy-status exited with $proxy_rc; continuing with the scan route already configured in .env" >&2
fi

if [[ "$SKIP_UPDATE" -eq 0 ]]; then
  TRIVY_RENDERED_FLAGS="$(python3 -m resilient_updates.cli render-flags trivy)" \
    "${compose[@]}" --profile update run --rm trivy-updater
  "${compose[@]}" --profile update run --rm grype-updater
  "${compose[@]}" --profile update run --rm grype-db-importer
  "${compose[@]}" --profile update run --rm cve-bin-tool-updater
fi

"${compose[@]}" run --rm db-admin db-status trivy --path /var/lib/resilient-db/trivy --warning-age 24h
"${compose[@]}" run --rm db-admin db-status grype --path /var/lib/resilient-db/grype/active --warning-age 24h
"${compose[@]}" run --rm db-admin db-status cve-bin-tool --path /root/.cache/cve-bin-tool --warning-age 24h

scan_args=(-t "$TARGET_RESOLVED" -c)
if [[ -n "$CASE_ID" ]]; then
  scan_args+=(--case-id "$CASE_ID")
fi
./scripts/run-scan.sh "${scan_args[@]}"
