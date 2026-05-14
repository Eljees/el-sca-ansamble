#!/usr/bin/env sh
set -eu

MODE="${1:-update}"
TARGET="${2:-${CVE_BIN_TOOL_TARGET:-/scan-target}}"
CONFIG_PATH="${CONFIG_PATH:-configs/feed_sources.yaml}"
REPORT_DIR="${REPORT_DIR:-artifacts/reports/cve-bin-tool}"
DB_ROOT="${CVE_BIN_TOOL_DB_ROOT:-/root/.cache/cve-bin-tool}"
STAGING_ROOT="${CVE_BIN_TOOL_STAGING_ROOT:-/var/lib/resilient-db/cve-bin-tool}"
ATTEMPTS_DIR="$REPORT_DIR/attempts"
UPDATE_TIMEOUT_SECONDS="${CVE_BIN_TOOL_UPDATE_TIMEOUT_SECONDS:-420}"
SEED_TIMEOUT_SECONDS="${CVE_BIN_TOOL_SEED_TIMEOUT_SECONDS:-120}"
CVE_DISABLE_ARGS="--disable-data-source OSV --disable-data-source EPSS"
CVE_UPDATE_MODES="${CVE_BIN_TOOL_UPDATE_MODES:-json-mirror json-nvd api2}"
CVE_OSV_ECOSYSTEMS="${CVE_BIN_TOOL_OSV_ECOSYSTEMS:-Debian Ubuntu Alpine Go PyPI Maven npm Rust}"
NVD_API_KEY_PRIMARY="${NVD_API_KEY:-}"
NVD_API_KEY_SECONDARY="${NVD_API_KEY_FALLBACK:-}"

mkdir -p "$REPORT_DIR" "$ATTEMPTS_DIR" "artifacts/provenance" "artifacts/mirror" "$STAGING_ROOT/candidates" "$STAGING_ROOT/tmp" "$STAGING_ROOT/previous"
if [ "${CVE_BIN_TOOL_WRAPPER_HEALTHCHECK:-0}" = "1" ]; then
  python -m resilient_updates.cli --config "$CONFIG_PATH" update cve-bin-tool >/dev/null
fi

if ! command -v cve-bin-tool >/dev/null 2>&1; then
  echo "cve-bin-tool is not installed in this environment" >&2
  exit 3
fi

attempt_update() {
  nvd_mode="$1"
  api_label="$2"
  api_key="${3:-}"
  attempt_id="${nvd_mode}-${api_label}"
  candidate_home="$STAGING_ROOT/candidates/$attempt_id"
  candidate_root="$candidate_home/.cache/cve-bin-tool"
  attempt_log="$ATTEMPTS_DIR/${attempt_id}.log"
  rm -rf "$candidate_home"
  mkdir -p "$candidate_home/.cache"

  {
    echo "[attempt] mode=$nvd_mode api_label=$api_label started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    set +e
    HOME="$candidate_home" XDG_CACHE_HOME="$candidate_home/.cache" NVD_MODE="$nvd_mode" ATTEMPT_API_KEY="$api_key" CVE_DISABLE_ARGS="$CVE_DISABLE_ARGS" UPDATE_TIMEOUT_SECONDS="$UPDATE_TIMEOUT_SECONDS" \
      python - <<'PY'
import os
import shlex
import subprocess
import sys

mode = os.environ["NVD_MODE"]
api_key = os.environ.get("ATTEMPT_API_KEY", "")
timeout_seconds = int(os.environ["UPDATE_TIMEOUT_SECONDS"])
env = os.environ.copy()
cmd = ["cve-bin-tool", "--update", "now", "--nvd", mode]
if api_key:
    cmd.extend(["--nvd-api-key", api_key])
cmd.extend(shlex.split(os.environ.get("CVE_DISABLE_ARGS", "")))
try:
    raise SystemExit(subprocess.run(cmd, env=env, timeout=timeout_seconds).returncode)
except subprocess.TimeoutExpired:
    print(f"[attempt] timeout_after_seconds={timeout_seconds}", file=sys.stderr)
    raise SystemExit(124)
PY
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
      echo "[attempt] update_failed exit_code=$rc"
      return "$rc"
    fi
    echo "[attempt] update_completed"
    if [ "${CVE_BIN_TOOL_SEED_AUX:-1}" = "1" ]; then
      set +e
      set -- python -m resilient_updates.cli --config "$CONFIG_PATH" seed cve-bin-tool-aux --db-root "$candidate_root" --seed-epss --timeout "$SEED_TIMEOUT_SECONDS"
      for ecosystem in $CVE_OSV_ECOSYSTEMS; do
        set -- "$@" --osv-ecosystem "$ecosystem"
      done
      "$@"
      seed_rc=$?
      set -e
      echo "[attempt] seed_exit_code=$seed_rc"
    fi
    python -m resilient_updates.cli --config "$CONFIG_PATH" audit cve-bin-tool-db --db-root "$candidate_root"
  } >"$attempt_log" 2>&1
}

case "$MODE" in
  update)
    updated=0
    candidate_count=0
    set --
    for nvd_mode in $CVE_UPDATE_MODES; do
      if [ "$nvd_mode" = "api" ] || [ "$nvd_mode" = "api2" ]; then
        for api_key in "$NVD_API_KEY_PRIMARY" "$NVD_API_KEY_SECONDARY"; do
          [ -n "$api_key" ] || continue
          api_label="key1"
          if [ "$api_key" = "$NVD_API_KEY_SECONDARY" ]; then
            api_label="key2"
          fi
          candidate_root="$STAGING_ROOT/candidates/${nvd_mode}-${api_label}/.cache/cve-bin-tool"
          candidate_count=$((candidate_count + 1))
          set -- "$@" --candidate-root "$candidate_root"
          if attempt_update "$nvd_mode" "$api_label" "$api_key"; then
            updated=1
            break
          fi
        done
        if [ "$updated" -eq 1 ]; then
          break
        fi
        if [ -z "$NVD_API_KEY_PRIMARY" ] && [ -z "$NVD_API_KEY_SECONDARY" ]; then
          candidate_root="$STAGING_ROOT/candidates/${nvd_mode}-no-key/.cache/cve-bin-tool"
          candidate_count=$((candidate_count + 1))
          set -- "$@" --candidate-root "$candidate_root"
          if attempt_update "$nvd_mode" "no-key"; then
            updated=1
            break
          fi
        fi
      else
        candidate_root="$STAGING_ROOT/candidates/${nvd_mode}-default/.cache/cve-bin-tool"
        candidate_count=$((candidate_count + 1))
        set -- "$@" --candidate-root "$candidate_root"
        if attempt_update "$nvd_mode" "default"; then
          updated=1
          break
        fi
      fi
    done
    [ "$candidate_count" -gt 0 ] || exit 1
    set +e
    python -m resilient_updates.cli --config "$CONFIG_PATH" activate cve-bin-tool-db "$@" --active-root "$DB_ROOT" --previous-root "$STAGING_ROOT/previous" --temp-root "$STAGING_ROOT/tmp" --provenance-path "artifacts/provenance/cve-bin-tool-db.json"
    activate_code=$?
    set -e
    if [ "$activate_code" -eq 5 ]; then
      echo "cve-bin-tool updater fell back to last-known-good database" >&2
      exit 0
    fi
    exit "$activate_code"
    ;;
  scan)
    if [ "${CVE_BIN_TOOL_VERIFY_DB:-1}" = "1" ]; then
      python -m resilient_updates.cli --config "$CONFIG_PATH" audit cve-bin-tool-db --db-root "$DB_ROOT" >/dev/null
    fi
    SCAN_TIMEOUT="${CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS:-600}"
    echo "[cve-bin-tool] scan timeout=${SCAN_TIMEOUT}s target=$TARGET"
    set +e
    timeout "$SCAN_TIMEOUT" cve-bin-tool --offline --format json --output-file "$REPORT_DIR/report.json" "$TARGET"
    scan_rc=$?
    set -e
    if [ "$scan_rc" -eq 124 ]; then
      echo "[cve-bin-tool] WARN: scan timed out after ${SCAN_TIMEOUT}s -- writing empty report" >&2
      # Ensure a valid empty report exists so collect_reports.sh can proceed.
      if [ ! -f "$REPORT_DIR/report.json" ]; then
        printf '[]' > "$REPORT_DIR/report.json"
      fi
      exit 0
    fi
    if [ "$scan_rc" -ne 0 ]; then
      echo "[cve-bin-tool] scan exited with code $scan_rc" >&2
      exit "$scan_rc"
    fi
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
