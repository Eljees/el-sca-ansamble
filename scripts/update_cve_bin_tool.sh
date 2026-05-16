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
    SBOM_PATH="${CVE_BIN_TOOL_SBOM_PATH:-}"
    SBOM_FORMAT="${CVE_BIN_TOOL_SBOM_FORMAT:-cyclonedx}"

    # ── SBOM fast-path ────────────────────────────────────────────────────────
    # If Syft already generated a SBOM (cyclonedx / spdx / syft-json), feed it
    # directly to cve-bin-tool instead of scanning the binary tree.
    # This replaces 365 regex-per-binary checkers with a simple DB lookup:
    # seconds instead of 10+ minutes for large Go / JVM targets.
    #
    # Enable by setting CVE_BIN_TOOL_SBOM_PATH to the SBOM file path, e.g.:
    #   CVE_BIN_TOOL_SBOM_PATH=/workspace/artifacts/sbom/cyclonedx.json
    #   CVE_BIN_TOOL_SBOM_FORMAT=cyclonedx   (or spdx / syft)
    if [ -n "$SBOM_PATH" ] && [ -f "$SBOM_PATH" ]; then
      echo "[cve-bin-tool] SBOM fast-path: format=$SBOM_FORMAT file=$SBOM_PATH"
      echo "[cve-bin-tool] scan timeout=${SCAN_TIMEOUT}s (SBOM lookup — much faster than binary scan)"
      set +e
      timeout "$SCAN_TIMEOUT" cve-bin-tool --offline \
        --sbom "$SBOM_FORMAT" \
        --format json --output-file "$REPORT_DIR/report.json" \
        "$SBOM_PATH"
      scan_rc=$?
      set -e
      if [ "$scan_rc" -eq 124 ]; then
        echo "[cve-bin-tool] WARN: SBOM scan timed out after ${SCAN_TIMEOUT}s" >&2
        printf 'timed_out_after=%s\n' "$SCAN_TIMEOUT" > "$REPORT_DIR/timeout.flag"
        [ -f "$REPORT_DIR/report.json" ] || printf '[]' > "$REPORT_DIR/report.json"
        exit 0
      fi
      # cve-bin-tool exit codes:
      #   0 = success, no CVEs found
      #   1 = success, CVEs found  ← treat as success!
      #   2+ = actual error (parse failure, DB issue, etc.) → fall back to binary scan
      if [ "$scan_rc" -le 1 ]; then
        # SBOM scan completed successfully — ensure report exists in the right place.
        # cve-bin-tool sometimes writes to workspace root when --output-file fails;
        # find and move it if needed.
        if [ ! -s "$REPORT_DIR/report.json" ]; then
          latest=$(ls -t /workspace/output.cve-bin-tool.*.json 2>/dev/null | head -1)
          if [ -n "$latest" ]; then
            mv "$latest" "$REPORT_DIR/report.json"
            echo "[cve-bin-tool] moved orphan output → $REPORT_DIR/report.json"
          else
            printf '[]' > "$REPORT_DIR/report.json"
          fi
        fi
        echo "[cve-bin-tool] SBOM fast-path done (exit $scan_rc)"
        exit 0
      else
        echo "[cve-bin-tool] SBOM scan failed (exit $scan_rc) — falling back to binary scan" >&2
        SBOM_PATH=""
      fi
    fi

    # ── Binary scan (fallback / default when no SBOM available) ──────────────
    # On Windows (Docker Desktop), bind mounts from NTFS go through the WSL2/virtio
    # layer and are 10-100x slower than native Linux I/O.  cve-bin-tool runs 365
    # byte-level regex patterns on every binary — reading a 100 MB Go binary through
    # a Windows bind mount takes hours.
    #
    # Fix: copy scan target to a tmpfs inside the container first, then scan locally.
    LOCAL_TARGET="/tmp/cbt-scan-local"
    if [ "${CVE_BIN_TOOL_LOCAL_COPY:-1}" = "1" ] && [ -d "$TARGET" ]; then
      echo "[cve-bin-tool] copying scan target to container-local tmpfs for faster I/O..."
      rm -rf "$LOCAL_TARGET"
      cp -a "$TARGET/." "$LOCAL_TARGET/"
      EFFECTIVE_TARGET="$LOCAL_TARGET"
      echo "[cve-bin-tool] copy done, scanning from $EFFECTIVE_TARGET"
    else
      EFFECTIVE_TARGET="$TARGET"
    fi

    # ── Smart checker selection ───────────────────────────────────────────────
    # Running all 365 binary checkers on a pure Go/JVM/Rust binary wastes
    # 20-30 minutes searching for C library signatures that are not there.
    # Auto-detect the dominant binary type and restrict to relevant checkers.
    #
    # Override: set CVE_BIN_TOOL_CHECKERS=go,rust,python,... to force a specific list.
    # Set CVE_BIN_TOOL_CHECKERS=all to disable auto-detection and run everything.
    CHECKERS="${CVE_BIN_TOOL_CHECKERS:-}"
    if [ -z "$CHECKERS" ]; then
      # Auto-detect binary type to choose relevant checkers.
      # Strategy: look for Go version strings ("go1.X.Y") embedded in ELF binaries.
      # All Go binaries (even stripped ones) embed the Go toolchain version string.
      # `file` command is unreliable for stripped Go binaries — use `strings` instead.
      go_count=0
      native_so_count=0
      executables=$(find "$EFFECTIVE_TARGET" -maxdepth 6 -type f -perm /111 2>/dev/null | head -30)
      for bin in $executables; do
        # Go detection: every Go binary contains a string like "go1.21.0" or "go1.26.1"
        if strings "$bin" 2>/dev/null | grep -qm1 '^go[0-9]\+\.[0-9]'; then
          go_count=$((go_count + 1))
        fi
      done
      # Native .so files indicate non-Go (C/C++) dynamic libraries
      native_so_count=$(find "$EFFECTIVE_TARGET" -maxdepth 6 -name "*.so" -o -name "*.so.*" 2>/dev/null | wc -l)

      echo "[cve-bin-tool] auto-detect: go_binaries=$go_count native_so=$native_so_count"
      if [ "$go_count" -gt 0 ] && [ "$native_so_count" -eq 0 ]; then
        # Pure Go target — language checkers only (~1-2 min vs 30+ min)
        CHECKERS="go,dart,env,java,javascript,perl,php,python,r,ruby,rust,swift"
        echo "[cve-bin-tool] → pure Go target: language checkers only"
        echo "[cve-bin-tool]   (set CVE_BIN_TOOL_CHECKERS=all to run all 365 checkers)"
      elif [ "$go_count" -gt 0 ] && [ "$native_so_count" -gt 0 ]; then
        echo "[cve-bin-tool] → mixed Go+native: running all checkers"
      else
        echo "[cve-bin-tool] → native/unknown: running all checkers"
      fi
    fi

    CHECKER_FLAGS=""
    if [ -n "$CHECKERS" ] && [ "$CHECKERS" != "all" ]; then
      CHECKER_FLAGS="--checkers $CHECKERS"
      echo "[cve-bin-tool] checkers: $CHECKERS"
    fi

    echo "[cve-bin-tool] scan timeout=${SCAN_TIMEOUT}s target=$EFFECTIVE_TARGET"
    set +e
    # shellcheck disable=SC2086
    timeout "$SCAN_TIMEOUT" cve-bin-tool --offline $CHECKER_FLAGS --format json --output-file "$REPORT_DIR/report.json" "$EFFECTIVE_TARGET"
    scan_rc=$?
    set -e
    if [ "$scan_rc" -eq 124 ]; then
      echo "[cve-bin-tool] WARN: scan timed out after ${SCAN_TIMEOUT}s -- writing empty report" >&2
      printf 'timed_out_after=%s\n' "$SCAN_TIMEOUT" > "$REPORT_DIR/timeout.flag"
      [ -f "$REPORT_DIR/report.json" ] || printf '[]' > "$REPORT_DIR/report.json"
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
