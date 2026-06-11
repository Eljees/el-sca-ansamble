#!/usr/bin/env bash
# update-db.sh — refresh scanner vulnerability DBs WITHOUT running a scan.
#
# Updates one tool or all of them, from any network location: before the
# updaters run, the in-network route-doctor (ADR-0007 P2) probes which egress
# is alive (sidecars / host proxy via host.docker.internal / direct) and the
# chosen plan is applied automatically.  Explicitly set HTTP_PROXY/ALL_PROXY
# always win over auto-discovery.
#
# Usage:
#   ./scripts/update-db.sh [all|trivy|grype|cve-bin-tool] [options]
#
# Options:
#       --no-auto-route     Skip route-doctor (use .env / current env as-is)
#       --auto-route        Force route discovery (default)
#   -h, --help              This help
#
# Env:
#   EL_SCA_AUTO_ROUTE=0     Same as --no-auto-route
#
# Exit codes: 0 = every requested DB updated; 1 = at least one updater failed.
set -euo pipefail

TOOL="${1:-all}"
case "$TOOL" in
  -h|--help)
    sed -n '/^# Usage:/,/^[^#]/p' "$0" | grep "^#" | sed 's/^# \?//'; exit 0 ;;
  all|trivy|grype|cve-bin-tool) shift || true ;;
  --*) TOOL="all" ;;  # options only — keep default tool
  *) echo "ERROR: unknown tool '$TOOL' (all|trivy|grype|cve-bin-tool)" >&2; exit 2 ;;
esac

AUTO_ROUTE=1
[[ "${EL_SCA_AUTO_ROUTE:-1}" =~ ^(0|false|no|off)$ ]] && AUTO_ROUTE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --auto-route)    AUTO_ROUTE=1; shift ;;
    --no-auto-route) AUTO_ROUTE=0; shift ;;
    -h|--help)
      sed -n '/^# Usage:/,/^[^#]/p' "$0" | grep "^#" | sed 's/^# \?//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")/.."
ARTIFACTS_DIR="$(pwd)/artifacts"
mkdir -p "$ARTIFACTS_DIR"

# Updater containers bind SCAN_TARGET_HOST-independent volumes, but compose
# still interpolates these for config validation — give them safe defaults.
export SCAN_TARGET_HOST="${SCAN_TARGET_HOST:-.}"
export EXTRACT_INPUT_HOST="${EXTRACT_INPUT_HOST:-.}"

die() { echo "ERROR: $*" >&2; exit 1; }

# Host Python (same fallback dance as run-scan.sh: a bare `python` can be a
# broken shim on some WSL hosts).
PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  for _py in python3 python; do
    if command -v "$_py" >/dev/null 2>&1 && "$_py" -c 'import sys' >/dev/null 2>&1; then
      PYTHON_BIN="$_py"; break
    fi
  done
fi
[[ -n "$PYTHON_BIN" ]] || PYTHON_BIN="python3"

compose_checked() {
  local rc=0
  docker compose "$@" || rc=$?
  if [[ $rc -ne 0 ]]; then
    die "docker compose failed (exit $rc): $*"
  fi
}

# ── Route discovery (any tunnel/proxy/VPN) ────────────────────────────────────
if [[ $AUTO_ROUTE -eq 1 && -z "${HTTP_PROXY:-}${ALL_PROXY:-}" ]]; then
  echo "[route] discovering a live egress via route-doctor..."
  rc=0
  docker compose --profile route run --rm route-doctor >/dev/null 2>&1 || rc=$?
  plan_env="$ARTIFACTS_DIR/route-plan.env"
  # Apply only a FRESH plan: an old file left by a previous run while THIS
  # doctor crashed must not steer the updaters at dead proxies.
  if [[ -f "$plan_env" ]] && find "$plan_env" -newermt '-10 minutes' | grep -q .; then
    # rc=2 means SOME tool had no route — the plan is still valid for the rest.
    [[ $rc -ne 0 ]] && echo "[route] route-doctor exit $rc (partial routes); applying what was found."
    while IFS= read -r line; do
      [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
      [[ "$line" == *"="* ]] || continue
      export "${line?}"
    done < "$plan_env"
    echo "[route] plan: HTTP_PROXY=${HTTP_PROXY:-<none>} ALL_PROXY=${ALL_PROXY:-<none>} CVE_BIN_TOOL_ENRICH_PROXY=${CVE_BIN_TOOL_ENRICH_PROXY:-<none>}"
  else
    echo "[route] route-doctor produced no plan (rc=$rc); proceeding with current env."
  fi
elif [[ $AUTO_ROUTE -eq 1 ]]; then
  echo "[route] HTTP_PROXY/ALL_PROXY already set; skipping auto-route."
fi

# Normalise named-volume / artifacts ownership to uid 1001 so the appuser
# updaters can write (Docker creates volumes root-owned). Idempotent; best-effort.
echo "[volinit] normalising volume ownership..."
docker compose --profile volinit run --rm volume-init || \
  echo "[volinit] WARN: volume-init failed (continuing; updates may hit permission errors)"

FAILED=()

update_trivy() {
  echo "[update] trivy DB..."
  local flags
  flags="$("$PYTHON_BIN" -m resilient_updates.cli render-flags trivy 2>/dev/null || true)"
  if docker compose --profile update run --rm -e "TRIVY_RENDERED_FLAGS=$flags" trivy-updater; then
    echo "[update] trivy OK"
  else
    echo "[update] trivy FAILED" >&2; FAILED+=(trivy)
  fi
}

update_grype() {
  echo "[update] grype DB..."
  if docker compose --profile update run --rm grype-updater \
     && docker compose --profile update run --rm grype-db-importer; then
    echo "[update] grype OK"
  else
    echo "[update] grype FAILED" >&2; FAILED+=(grype)
  fi
}

update_cve_bin_tool() {
  echo "[update] cve-bin-tool DB..."
  if docker compose --profile update run --rm cve-bin-tool-updater; then
    echo "[update] cve-bin-tool OK"
  else
    echo "[update] cve-bin-tool FAILED" >&2; FAILED+=(cve-bin-tool)
  fi
}

case "$TOOL" in
  all)          update_trivy; update_grype; update_cve_bin_tool ;;
  trivy)        update_trivy ;;
  grype)        update_grype ;;
  cve-bin-tool) update_cve_bin_tool ;;
esac

# ── Freshness summary (best-effort) ──────────────────────────────────────────
for pair in "trivy:/var/lib/resilient-db/trivy/active" \
            "grype:/var/lib/resilient-db/grype/active" \
            "cve-bin-tool:/home/appuser/.cache/cve-bin-tool"; do
  t="${pair%%:*}"; p="${pair#*:}"
  [[ "$TOOL" == "all" || "$TOOL" == "$t" ]] || continue
  docker compose run --rm db-admin db-status "$t" --path "$p" --warning-age 24h 2>/dev/null || true
done

if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "[update] FAILED: ${FAILED[*]}" >&2
  exit 1
fi
echo "[update] all requested DBs updated."
