#!/usr/bin/env bash
# scripts/benchmark.sh — wall-clock benchmark for el-sca-ansamble on Linux/macOS.
# Linux mirror of scripts/windows/benchmark.ps1.
#
# Runs scripts/run-scan.sh against the same target N times and writes a
# JSON summary to artifacts/provenance/benchmark.json.  Use this to
# quantify the impact of Phase 3 optimisations (Defender exclusions
# don't apply on Linux but tmpfs overlay, BuildKit cache, parallelism,
# SBOM fast-path do).
#
# The first run is treated as a "cold" cache and EXCLUDED from the
# averages by default — extractor's named volume, scanner DB volumes,
# and OS page cache all warm up during it.  Override with --include-cold.
#
# Usage:
#   ./scripts/benchmark.sh --target /path/to/sample.tar.gz [--runs 3] [...]
#
# Options:
#   --target PATH          Archive or directory to scan (required).
#   --runs N               Total runs (default 3).
#   --include-cold         Include run #1 in averages.
#   --update-db-once       Pass -u to the first run only.
#   --extra-arg ARG        Forwarded verbatim to run-scan.sh (repeatable).
#   --output PATH          JSON output path (default artifacts/provenance/benchmark.json).
#   -h | --help            Print this help.
#
# Exit codes:
#   0  all runs OK
#   2  at least one run failed (best-effort: averages still computed)
#   3  bad usage

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RUN_SCAN="$REPO_ROOT/scripts/run-scan.sh"
[[ -x "$RUN_SCAN" ]] || { echo "ERROR: $RUN_SCAN is not executable" >&2; exit 3; }

TARGET=""
RUNS=3
INCLUDE_COLD=0
UPDATE_DB_ONCE=0
EXTRA_ARGS=()
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --runs) RUNS="$2"; shift 2 ;;
    --include-cold) INCLUDE_COLD=1; shift ;;
    --update-db-once) UPDATE_DB_ONCE=1; shift ;;
    --extra-arg) EXTRA_ARGS+=("$2"); shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 3 ;;
  esac
done

[[ -n "$TARGET" ]] || { echo "ERROR: --target is required" >&2; exit 3; }
[[ -e "$TARGET" ]] || { echo "ERROR: target does not exist: $TARGET" >&2; exit 3; }
[[ "$RUNS" -ge 1 ]] || { echo "ERROR: --runs must be >= 1" >&2; exit 3; }
[[ -z "$OUTPUT" ]] && OUTPUT="$REPO_ROOT/artifacts/provenance/benchmark.json"
mkdir -p "$(dirname "$OUTPUT")"

TARGET_RESOLVED="$(readlink -f "$TARGET" 2>/dev/null || python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$TARGET")"
TARGET_SIZE_MB="$(du -m "$TARGET_RESOLVED" 2>/dev/null | awk '{print $1}' || echo 0)"

# Snapshot of relevant environment for the report header.
SNAP_HOSTNAME="$(hostname)"
SNAP_KERNEL="$(uname -srm)"
SNAP_COMPOSE_FILE="${COMPOSE_FILE:-}"
SNAP_COMPOSE_PROFILES="${COMPOSE_PROFILES:-}"
SNAP_NPROC="$(nproc 2>/dev/null || echo 1)"
SNAP_MEM_KB="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
SNAP_HTTP_PROXY="${HTTP_PROXY:-}"
SNAP_ALL_PROXY="${ALL_PROXY:-}"
SNAP_CBT_AUTO_SBOM="${CVE_BIN_TOOL_AUTO_SBOM:-}"
SNAP_CBT_MAX_FILE_MB="${CVE_BIN_TOOL_MAX_FILE_MB:-}"
SNAP_CBT_TIMEOUT="${CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS:-}"

echo
echo "Benchmark target  : $TARGET_RESOLVED ($TARGET_SIZE_MB MB)"
echo "Runs              : $RUNS"
echo "Include cold run  : $INCLUDE_COLD"
echo "Update DB on run 1: $UPDATE_DB_ONCE"
echo

declare -a RUN_RESULTS_LINES   # JSON object per run
BAD=0

for ((i=1; i<=RUNS; i++)); do
  printf '%.0s─' {1..60}; echo
  echo "Run $i/$RUNS starting at $(date '+%H:%M:%S')"

  ARGS=(-t "$TARGET_RESOLVED")
  if [[ $UPDATE_DB_ONCE -eq 1 && $i -eq 1 ]]; then
    ARGS+=(-u)
  fi
  ARGS+=("${EXTRA_ARGS[@]}")

  START_EPOCH="$(date +%s)"
  set +e
  "$RUN_SCAN" "${ARGS[@]}"
  rc=$?
  set -e
  END_EPOCH="$(date +%s)"
  ELAPSED=$(( END_EPOCH - START_EPOCH ))
  [[ $rc -ne 0 && $rc -ne 1 ]] && BAD=$((BAD + 1))

  printf 'Run %d/%d finished: %ds (exit %d)\n' "$i" "$RUNS" "$ELAPSED" "$rc"

  # Build a JSON object for this run.
  COLD="false"; [[ $i -eq 1 ]] && COLD="true"
  RUN_RESULTS_LINES+=("$(python3 -c '
import json, sys
print(json.dumps({
  "index":     int(sys.argv[1]),
  "is_cold":   sys.argv[2] == "true",
  "seconds":   int(sys.argv[3]),
  "exit_code": int(sys.argv[4]),
  "started_unix": int(sys.argv[5]),
}))
' "$i" "$COLD" "$ELAPSED" "$rc" "$START_EPOCH")")
done

# ── Aggregate ──────────────────────────────────────────────────────────────
python3 - <<PYEOF >"$OUTPUT"
import json, statistics, sys

runs = [json.loads(s) for s in $(printf '%s\n' "${RUN_RESULTS_LINES[@]}" | python3 -c '
import sys, json
items = [line.strip() for line in sys.stdin if line.strip()]
print(json.dumps(items))
')]
considered = [r for r in runs if r.get("is_cold") is False or ${INCLUDE_COLD}]
success = [r for r in considered if r["exit_code"] in (0, 1)]
summary = {"runs_considered": len(considered), "runs_successful": len(success)}
if success:
  vals = sorted(r["seconds"] for r in success)
  summary["min_seconds"]    = min(vals)
  summary["max_seconds"]    = max(vals)
  summary["median_seconds"] = statistics.median(vals)
  summary["avg_seconds"]    = round(statistics.mean(vals), 1)
payload = {
  "benchmark_kind": "linux-wall-clock",
  "config": {
    "target":              "$TARGET_RESOLVED",
    "target_size_mb":      $TARGET_SIZE_MB,
    "hostname":            "$SNAP_HOSTNAME",
    "kernel":              "$SNAP_KERNEL",
    "logical_cpu_count":   $SNAP_NPROC,
    "physical_mem_gib":    round($SNAP_MEM_KB / 1024 / 1024, 2),
    "compose_file":        "$SNAP_COMPOSE_FILE",
    "compose_profiles":    "$SNAP_COMPOSE_PROFILES",
    "http_proxy":          "$SNAP_HTTP_PROXY",
    "all_proxy":           "$SNAP_ALL_PROXY",
    "cve_bin_auto_sbom":   "$SNAP_CBT_AUTO_SBOM",
    "cve_bin_max_file_mb": "$SNAP_CBT_MAX_FILE_MB",
    "cve_bin_timeout_s":   "$SNAP_CBT_TIMEOUT",
  },
  "runs": runs,
  "summary": summary,
}
print(json.dumps(payload, indent=2, ensure_ascii=False))
PYEOF

# ── Pretty summary ─────────────────────────────────────────────────────────
echo
printf '%.0s─' {1..60}; echo
echo "Summary:"
python3 -c '
import json, sys
data = json.load(open(sys.argv[1]))
s = data["summary"]
for k in ("runs_considered","runs_successful","min_seconds","max_seconds","median_seconds","avg_seconds"):
    if k in s:
        print(f"  {k:<18} {s[k]}")
' "$OUTPUT"
echo
echo "Provenance: $OUTPUT"

exit $(( BAD > 0 ? 2 : 0 ))
