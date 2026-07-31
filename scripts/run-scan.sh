#!/usr/bin/env bash
# run-scan.sh — Linux/macOS entry point for el-sca-ansamble (FULL pipeline).
# Mirrors scripts/windows/run-scan.ps1 in behaviour and flags.
#
# Sibling-name disambiguation (see scripts/README.md):
#   run-scan.sh    dash       = full pipeline via docker compose + reports  (this file)
#   run_scan.sh    underscore = native per-tool wrapper, no docker
#
# Usage:
#   ./scripts/run-scan.sh -t /path/to/target [options]
#
# Options:
#   -t, --target PATH       Path to file or directory to scan (required)
#       --case-id CASE      Case identifier for the final report (auto-detected)
#   -p, --profile NAME      Docker Compose profile (default: scan)
#       --tool TOOL         Run only one tool: all|syft|grype|trivy|cve-bin-tool (default: all)
#       --format FORMAT     Target format: auto|apk|win (default: auto)
#   -u, --update-db         Pull fresh CVE databases before scanning
#   -e, --extract           Unpack archive before scanning (auto-detected for archives)
#       --extract-max-depth N  Max recursion depth for extraction (default: 0)
#   -c, --clean             Remove previous artifacts before this run
#   -r, --resume            Resume from the last checkpoint: skip stages already
#                           completed for the SAME target+tool (pipeline_state.json)
#       --heartbeat N       Print a liveness line every N seconds during long
#                           stages (default: 30; 0 disables)
#       --sbom-scan         Feed Syft SBOM to cve-bin-tool instead of binary scan (experimental)
#       --auto-route        Before --update-db, run route-doctor to pick a live egress (default on)
#       --no-auto-route     Disable egress auto-discovery (use .env/direct as-is)
#       --timeout N         cve-bin-tool scan timeout in seconds (default: 1800)
#       --checkers LIST     Comma-separated cve-bin-tool checker list (default: all enabled)
#       --artifact-mode M   Save run snapshot: host|artifacts|near-source|auto (default: host)
#
# Requires: docker, docker compose, bash >= 4
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
TARGET=""
CASE_ID=""
PROFILE="scan"
TOOL="all"
FORMAT="auto"
UPDATE_DB=0
EXTRACT=0
EXTRACT_MAX_DEPTH=0
CLEAN=0
RESUME=0
HEARTBEAT="${EL_SCA_HEARTBEAT_SECONDS:-30}"
SBOM_SCAN=0
CBT_TIMEOUT=1800
CBT_CHECKERS=""
ARTIFACT_MODE="${EL_SCA_ARTIFACT_MODE:-host}"
# Auto-route: when updating DBs, run route-doctor first to pick a live egress
# (any tunnel/proxy/VPN) and source its plan before the updaters. On by default
# for --update-db runs; disable with --no-auto-route or EL_SCA_AUTO_ROUTE=0.
AUTO_ROUTE=1
[[ "${EL_SCA_AUTO_ROUTE:-1}" =~ ^(0|false|no|off)$ ]] && AUTO_ROUTE=0

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target)           TARGET="$2"; shift 2 ;;
    --case-id)             CASE_ID="$2"; shift 2 ;;
    -p|--profile)          PROFILE="$2"; shift 2 ;;
    --tool)                TOOL="$2"; shift 2 ;;
    --format)              FORMAT="$2"; shift 2 ;;
    -u|--update-db)        UPDATE_DB=1; shift ;;
    -e|--extract)          EXTRACT=1; shift ;;
    --extract-max-depth)   EXTRACT_MAX_DEPTH="$2"; shift 2 ;;
    -c|--clean)            CLEAN=1; shift ;;
    -r|--resume)           RESUME=1; shift ;;
    --heartbeat)           HEARTBEAT="$2"; shift 2 ;;
    --sbom-scan)           SBOM_SCAN=1; shift ;;
    --auto-route)          AUTO_ROUTE=1; shift ;;
    --no-auto-route)       AUTO_ROUTE=0; shift ;;
    --timeout)             CBT_TIMEOUT="$2"; shift 2 ;;
    --checkers)            CBT_CHECKERS="$2"; shift 2 ;;
    --artifact-mode)       ARTIFACT_MODE="$2"; shift 2 ;;
    -h|--help)
      sed -n '/^# Usage:/,/^[^#]/p' "$0" | grep "^#" | sed 's/^# \?//'
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "ERROR: -t/--target is required" >&2
  exit 2
fi
if [[ ! -e "$TARGET" ]]; then
  echo "ERROR: Target does not exist: $TARGET" >&2
  exit 2
fi
if [[ $CLEAN -eq 1 && $RESUME -eq 1 ]]; then
  echo "ERROR: --clean and --resume are mutually exclusive (clean wipes the checkpoint)" >&2
  exit 2
fi
# Run-key salt: inputs that change WHAT the stages produce (format/sbom mode).
# Captured from the CLI values BEFORE auto-detection mutates FORMAT, so the
# original and the resumed invocation derive the same key.
RUN_EXTRA="fmt=${FORMAT};sbom=${SBOM_SCAN}"

# ── Helpers ───────────────────────────────────────────────────────────────────
die() { echo "ERROR: $*" >&2; exit 1; }

# Host Python interpreter. A bare `python` can be a broken / permission-denied
# shim on some WSL hosts (errno 13), which silently breaks render-flags and the
# final report stages. Pick the first interpreter that actually executes.
PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  for _py in python3 python; do
    if command -v "$_py" >/dev/null 2>&1 && "$_py" -c 'import sys' >/dev/null 2>&1; then
      PYTHON_BIN="$_py"; break
    fi
  done
fi
[[ -n "$PYTHON_BIN" ]] || PYTHON_BIN="python3"

# ── Stage runner: heartbeat + checkpoints (pipeline_state.json) ──────────────
# Long stages (extraction, cve-bin-tool) can be silent for many minutes; the
# heartbeat prints a liveness line with elapsed time so the run never LOOKS
# hung.  Every stage transition is checkpointed to artifacts/pipeline_state.json
# so an interrupted run restarts from the last completed stage via --resume.
STATE_OK=0
LAST_STEP_RC=0

state_cli() {
  # Best-effort: checkpoint bookkeeping must never fail the pipeline itself.
  "$PYTHON_BIN" -m resilient_updates.cli run-state "$@" --artifacts-dir "$ARTIFACTS_DIR" \
    >/dev/null 2>&1 || true
}

state_begin() {
  local resume_flag=()
  [[ $RESUME -eq 1 ]] && resume_flag=(--resume)
  if "$PYTHON_BIN" -m resilient_updates.cli run-state begin \
       --artifacts-dir "$ARTIFACTS_DIR" --target "$TARGET_RESOLVED" \
       --tool "$TOOL" --case-id "$CASE_ID" --extra "$RUN_EXTRA" \
       "${resume_flag[@]}" >/dev/null 2>&1; then
    STATE_OK=1
    [[ $RESUME -eq 1 ]] && echo "[state] resume: завершённые этапы будут пропущены (pipeline_state.json)"
  else
    echo "[state] WARN: checkpoint state unavailable (host python?); --resume/monitor degraded"
  fi
  # MUST return 0: this function is called as a bare statement under
  # `set -e`, and its last command above is `[[ $RESUME -eq 1 ]] && echo …`,
  # which evaluates to FALSE (rc 1) on every non-resume run — that would abort
  # the whole pipeline right after the banner.  Pin success explicitly.
  return 0
}

stage_should_skip() {
  [[ $RESUME -eq 1 && $STATE_OK -eq 1 ]] || return 1
  "$PYTHON_BIN" -m resilient_updates.cli run-state should-skip \
    --artifacts-dir "$ARTIFACTS_DIR" --target "$TARGET_RESOLVED" \
    --tool "$TOOL" --extra "$RUN_EXTRA" --stage "$1" >/dev/null 2>&1
}

# run_step <label> <ok_codes> <cmd...> — run a command with a liveness
# heartbeat and elapsed-time reporting.  Exit codes in <ok_codes> (space-
# separated) count as success; sets LAST_STEP_RC; returns 1 on failure.
run_step() {
  local label="$1" ok_codes="$2"; shift 2
  local t0 rc=0 hb_pid="" cmd_pid elapsed code ok=0
  t0=$(date +%s)
  echo "[stage] $label — старт $(date +%H:%M:%S)"
  "$@" &
  cmd_pid=$!
  if [[ "${HEARTBEAT:-0}" =~ ^[0-9]+$ ]] && [[ "${HEARTBEAT:-0}" -gt 0 ]]; then
    (
      while sleep "$HEARTBEAT"; do
        kill -0 "$cmd_pid" 2>/dev/null || break
        echo "[stage] $label … выполняется, прошло $(( $(date +%s) - t0 ))s"
      done
    ) &
    hb_pid=$!
  fi
  wait "$cmd_pid" || rc=$?
  if [[ -n "$hb_pid" ]]; then
    kill "$hb_pid" 2>/dev/null || true
    wait "$hb_pid" 2>/dev/null || true
  fi
  elapsed=$(( $(date +%s) - t0 ))
  LAST_STEP_RC=$rc
  for code in $ok_codes; do [[ $rc -eq $code ]] && ok=1; done
  if [[ $ok -eq 1 ]]; then
    echo "[stage] $label ✓ завершён за ${elapsed}s (rc=$rc)"
    return 0
  fi
  echo "[stage] $label ✗ ошибка rc=$rc (${elapsed}s)"
  return 1
}

# run_stage <stage-key> <ok_codes> <cmd...> — checkpointed run_step: on
# --resume a stage already completed for the same target+tool is skipped; a
# failure is recorded in the checkpoint before the pipeline dies, so the next
# --resume restarts exactly at the failed stage.
run_stage() {
  local stage="$1" ok_codes="$2"; shift 2
  if stage_should_skip "$stage"; then
    echo "[stage] $stage ✓ пропущен — уже выполнен (чекпоинт, --resume)"
    state_cli stage-skip --stage "$stage"
    return 0
  fi
  state_cli stage-start --stage "$stage"
  if run_step "$stage" "$ok_codes" "$@"; then
    state_cli stage-end --stage "$stage" --ok true --rc "$LAST_STEP_RC"
    return 0
  fi
  state_cli stage-end --stage "$stage" --ok false --rc "$LAST_STEP_RC"
  state_cli finish --status error
  die "stage $stage failed (exit $LAST_STEP_RC); перезапуск с этого места: --resume"
}

# run_stage_soft <stage-key> <ok_codes> <cmd...> — like run_stage but a stage
# failure is NON-FATAL: it is recorded and a warning printed, then the pipeline
# CONTINUES.  cve-bin-tool is a supplementary scanner — when its DB build/offline
# scan fails (e.g. the feed-built cve.db is not recognised by cve-bin-tool's
# --offline reader) it must NOT block the grype/trivy report.  Set
# EL_SCA_CVEBT_REQUIRED=1 to restore hard-fail behaviour.
run_stage_soft() {
  local stage="$1" ok_codes="$2"; shift 2
  if stage_should_skip "$stage"; then
    echo "[stage] $stage ✓ пропущен — уже выполнен (чекпоинт, --resume)"
    state_cli stage-skip --stage "$stage"
    return 0
  fi
  state_cli stage-start --stage "$stage"
  if run_step "$stage" "$ok_codes" "$@"; then
    state_cli stage-end --stage "$stage" --ok true --rc "$LAST_STEP_RC"
    return 0
  fi
  state_cli stage-end --stage "$stage" --ok false --rc "$LAST_STEP_RC"
  if [[ "${EL_SCA_CVEBT_REQUIRED:-0}" == "1" ]]; then
    state_cli finish --status error
    die "stage $stage failed (exit $LAST_STEP_RC); перезапуск с этого места: --resume"
  fi
  echo "[stage] $stage ⚠ не фатально — продолжаю, отчёт будет без $stage (rc=$LAST_STEP_RC)" >&2
  echo "        (вернуть жёсткий режим: EL_SCA_CVEBT_REQUIRED=1)" >&2
  return 0
}

db_status() {
  local tool="$1" path="$2" out
  out="$(docker compose run --rm db-admin db-status "$tool" --path "$path" --warning-age 24h 2>/dev/null || true)"
  printf '%s\n' "$out"
  # Persist the JSON object so run_summary can surface cached DB freshness on
  # scan-only runs (no updater → no provenance). Best-effort; never fatal.
  mkdir -p "$ARTIFACTS_DIR/db_status"
  printf '%s\n' "$out" | sed -n '/^{/,/^}/p' > "$ARTIFACTS_DIR/db_status/$tool.json" 2>/dev/null || true
}

# Run the in-network route-doctor and source its plan so the updater containers
# inherit HTTP_PROXY / ALL_PROXY / CVE_BIN_TOOL_ENRICH_PROXY for the chosen
# egress. Best-effort: any failure leaves the environment untouched (direct /
# .env-configured), exactly as before. Idempotent; runs at most once per run.
ROUTE_PLAN_DONE=0
# Normalise named-volume / artifacts ownership to uid 1001 so the appuser
# containers (extractor, scanners, updaters, report-collector) can always write
# - Docker creates named volumes root-owned and the host owns ./artifacts.
# Committed, cross-platform replacement for manual chown/ACL; once per pipeline.
VOLINIT_DONE=0
volume_init_once() {
  [[ $VOLINIT_DONE -eq 1 ]] && return 0
  VOLINIT_DONE=1
  echo "[volinit] normalising volume/artifacts ownership..."
  docker compose --profile volinit run --rm volume-init >/dev/null 2>&1 \
    || echo "[volinit] WARN: volume-init failed (updates/scan may hit permission errors)"
}

auto_route_once() {
  [[ $AUTO_ROUTE -eq 1 ]] || return 0
  [[ $ROUTE_PLAN_DONE -eq 1 ]] && return 0
  ROUTE_PLAN_DONE=1
  # If the operator already pinned a proxy explicitly, don't override it.
  if [[ -n "${HTTP_PROXY:-}${ALL_PROXY:-}" ]]; then
    echo "[route] HTTP_PROXY/ALL_PROXY already set in env; skipping auto-route."
    return 0
  fi
  echo "[route] discovering a live egress via route-doctor..."
  local rc=0
  docker compose --profile route run --rm route-doctor >/dev/null 2>&1 || rc=$?
  local plan_env="$ARTIFACTS_DIR/route-plan.env"
  # rc=2 means SOME tool had no reachable route — the plan file is still
  # written and still valid for the tools that do have one. Only a missing
  # (or stale — left over from an earlier run while THIS doctor crashed)
  # plan file means "nothing to apply".
  if [[ ! -f "$plan_env" ]] || ! find "$plan_env" -newermt '-10 minutes' | grep -q .; then
    echo "[route] route-doctor produced no fresh plan (rc=$rc); proceeding direct."
    return 0
  fi
  [[ $rc -ne 0 ]] && echo "[route] route-doctor exit $rc (partial routes); applying what was found."
  # shellcheck disable=SC1090
  while IFS= read -r line; do
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
    [[ "$line" == *"="* ]] || continue
    export "${line?}"
  done < "$plan_env"
  echo "[route] applied plan: HTTP_PROXY=${HTTP_PROXY:-<none>} ALL_PROXY=${ALL_PROXY:-<none>} CVE_BIN_TOOL_ENRICH_PROXY=${CVE_BIN_TOOL_ENRICH_PROXY:-<none>}"
}

import_local_env() {
  local envfile=".env.local"
  [[ -f "$envfile" ]] || return 0
  while IFS= read -r line; do
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
    export "${line?}"
  done < "$envfile"
}

# ── Pre-flight ────────────────────────────────────────────────────────────────
docker --version > /dev/null
docker compose version > /dev/null
import_local_env

TARGET_RESOLVED="$(realpath "$TARGET")"
TARGET_DIR="$(dirname "$TARGET_RESOLVED")"
RAW_NAME="$(basename "$TARGET_RESOLVED")"
TARGET_LOWER="${TARGET_RESOLVED,,}"
IS_STANDALONE_APK=0
case "$TARGET_LOWER" in
  *.apk) IS_STANDALONE_APK=1 ;;
esac

if [[ -z "$CASE_ID" ]]; then
  if [[ "$TARGET_RESOLVED" =~ (CYBERSEC-[0-9]+) ]]; then
    CASE_ID="${BASH_REMATCH[1]}"
  else
    CASE_ID="CYBERSEC-UNKNOWN"
  fi
fi

# Strip known archive extensions (compound first)
BASE_NAME="$RAW_NAME"
for ext in .tar.gz .tar.bz2 .tar.xz .tar.zst .tar .tgz .zip .gz .bz2 .xz .zst .jar .war .ear .apk .ipa; do
  case "${BASE_NAME,,}" in
    *"$ext") BASE_NAME="${BASE_NAME%"${BASE_NAME: -${#ext}}"}"; break ;;
  esac
done

DATE="$(date +%Y-%m-%d)"
REPORT_MD="${TARGET_DIR}/${BASE_NAME}_report_${DATE}.md"
REPORT_HTML="${TARGET_DIR}/${BASE_NAME}_report_${DATE}.html"
ARTIFACTS_DIR="$(pwd)/artifacts"

# Mirror all pipeline output to a log file so a non-interactive caller can
# inspect progress/errors even when its own request times out.
# Rotated locally: run-scan.log -> .1 -> .2 ... up to EL_SCA_LOG_BACKUP_COUNT.
mkdir -p "$ARTIFACTS_DIR"
LOG_BACKUPS="${EL_SCA_LOG_BACKUP_COUNT:-5}"
if [[ "$LOG_BACKUPS" =~ ^[0-9]+$ && "$LOG_BACKUPS" -gt 0 ]]; then
  rm -f "$ARTIFACTS_DIR/run-scan.log.$LOG_BACKUPS" 2>/dev/null || true
  for ((i=LOG_BACKUPS-1; i>=1; i--)); do
    if [[ -f "$ARTIFACTS_DIR/run-scan.log.$i" ]]; then
      mv -f "$ARTIFACTS_DIR/run-scan.log.$i" "$ARTIFACTS_DIR/run-scan.log.$((i+1))" 2>/dev/null || true
    fi
  done
  if [[ -f "$ARTIFACTS_DIR/run-scan.log" ]]; then
    mv -f "$ARTIFACTS_DIR/run-scan.log" "$ARTIFACTS_DIR/run-scan.log.1" 2>/dev/null || true
  fi
fi
exec > >(tee "$ARTIFACTS_DIR/run-scan.log") 2>&1
echo "[run-scan] $(date -u +%Y-%m-%dT%H:%M:%SZ) start  py=$PYTHON_BIN tool=$TOOL target=$TARGET"

echo ""
printf '\e[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n'
printf '\e[36m SCA Pipeline\e[0m\n'
printf '\e[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n'
printf ' Case    : %s\n' "$CASE_ID"
printf ' Target  : %s\n' "$TARGET_RESOLVED"
printf ' MD out  : %s\n' "$REPORT_MD"
printf ' HTML out: %s\n' "$REPORT_HTML"
printf '\e[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n'
echo ""

# ── Clean ────────────────────────────────────────────────────────────────────
if [[ $CLEAN -eq 1 ]]; then
  echo "[clean] Removing previous artifacts..."
  find "$ARTIFACTS_DIR" -type f ! -name ".gitkeep" -delete
  # Remove empty subdirectories (deepest first)
  find "$ARTIFACTS_DIR" -mindepth 1 -type d -empty -delete 2>/dev/null || true
  # Remove orphan cve-bin-tool output files in workspace root
  find "$(pwd)" -maxdepth 1 -name "output.cve-bin-tool.*.json" -delete 2>/dev/null || true
  echo "[clean] Done."
  echo ""
fi

# Initialise the checkpoint state (fresh run, or load completed stages on --resume).
state_begin

# Always remove stale SBOM files so Syft writes fresh ones — unless we are
# resuming past an already-completed sbom stage (they ARE the checkpoint then).
if ! stage_should_skip sbom; then
  for f in syft.json cyclonedx.json spdx.json; do
    rm -f "$ARTIFACTS_DIR/sbom/$f"
  done
fi

# Pick a live egress before any updater runs (only when refreshing DBs).
# Ensure volumes/artifacts are writable by the appuser containers first.
volume_init_once

[[ $UPDATE_DB -eq 1 ]] && auto_route_once

# ── Render Trivy flags (standard pipeline only) ───────────────────────────────
TRIVY_FLAGS=""
if [[ "$FORMAT" == "auto" ]]; then
  TRIVY_FLAGS="$("$PYTHON_BIN" -m resilient_updates.cli render-flags trivy 2>/dev/null || true)"
fi

# ── Environment for containers ────────────────────────────────────────────────
export SCAN_TARGET_HOST="$TARGET_RESOLVED"
export SCAN_TARGET_CONTAINER="/scan-target"
export SCAN_TARGET_DISPLAY="$TARGET_RESOLVED"
export EXTRACT_INPUT_HOST="$TARGET_RESOLVED"
export SYFT_TARGET="/scan-target"
export SYFT_FROM="dir"
export TRIVY_TARGET="/scan-target"
export CVE_BIN_TOOL_TARGET="/scan-target"
export CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS="$CBT_TIMEOUT"
export CVE_BIN_TOOL_CHECKERS="$CBT_CHECKERS"
export REPORT_OUTPUT="/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md"

if [[ $SBOM_SCAN -eq 1 ]]; then
  export CVE_BIN_TOOL_SBOM_PATH="/workspace/artifacts/sbom/cyclonedx.json"
  export CVE_BIN_TOOL_SBOM_FORMAT="cyclonedx"
  echo " SbomScan: ENABLED (cve-bin-tool will read cyclonedx.json)"
else
  export CVE_BIN_TOOL_SBOM_PATH=""
  export CVE_BIN_TOOL_SBOM_FORMAT=""
fi

# ── Auto-detect format ────────────────────────────────────────────────────────
if [[ "$FORMAT" == "auto" ]]; then
  ext="${TARGET_RESOLVED##*.}"
  ext="${ext,,}"
  case "$ext" in
    apk) FORMAT="apk" ;;
    msi|exe) FORMAT="win" ;;
    zip)
      # Peek inside ZIP for .apk or .exe/.msi
      if command -v unzip &>/dev/null; then
        inner=$(unzip -l "$TARGET_RESOLVED" 2>/dev/null | awk '{print $NF}' || true)
        if echo "$inner" | grep -qi '\.apk$'; then FORMAT="apk"
        elif echo "$inner" | grep -qiE '\.(msi|exe)$'; then FORMAT="win"
        fi
      fi ;;
  esac
  [[ "$FORMAT" != "auto" ]] && echo " Format  : $FORMAT (auto-detected)"
fi

# ── Auto-enable extract for archives ──────────────────────────────────────────
if [[ "$FORMAT" != "apk" && $EXTRACT -eq 0 && -f "$TARGET_RESOLVED" ]]; then
  case "$TARGET_LOWER" in
    *.tar|*.tar.gz|*.tgz|*.tar.bz2|*.tar.xz|*.tar.zst|*.zip|*.rpm|*.deb)
      EXTRACT=1
      echo " Extract : enabled automatically for archive target"
      ;;
  esac
fi

# APK analyzer can inspect standalone .apk files directly.  ZIP wrappers still
# need generic extraction first because Docker bind-mounts the wrapper at
# /scan-target without the original .zip suffix.
if [[ "$FORMAT" == "apk" ]]; then
  if [[ $IS_STANDALONE_APK -eq 1 ]]; then
    EXTRACT=0
    echo " Extract : disabled for standalone APK (apk-analyzer extracts internally)"
  else
    EXTRACT=1
    echo " Extract : enabled for APK archive wrapper"
  fi
fi

# ── Extract ───────────────────────────────────────────────────────────────────
if [[ $EXTRACT -eq 1 ]]; then
  EXTRACT_REL="artifacts/extracted/current"
  EXTRACT_HOST="$(pwd)/$EXTRACT_REL"
  # NOTE: the extractor purges `current/` itself (in-container) before writing
  # — see resilient_updates.extractor.extract_artifacts. A host-side rm is
  # avoided here because the extracted tree may be owned by a different uid.
  # The extractor image runs as appuser (uid 1001); this bind dir is created by
  # the host user (often uid 1000), so it MUST be world-writable or the
  # in-container user cannot write extraction_manifest.json (EACCES). chmod 0777
  # the extract subtree so any container uid can write regardless of host uid.
  mkdir -p "$EXTRACT_HOST"
  chmod -R 0777 "$(pwd)/artifacts/extracted" 2>/dev/null || true
  export EXTRACT_INPUT_HOST="$SCAN_TARGET_HOST"
  export EXTRACT_OUTPUT="/workspace/$EXTRACT_REL"
  export EXTRACT_MAX_DEPTH="$EXTRACT_MAX_DEPTH"
  # On --resume an already-extracted tree is reused only when its manifest is
  # still in place (the extractor purges current/ itself on a real re-run).
  if stage_should_skip extract && [[ -f "$EXTRACT_HOST/extraction_manifest.json" ]]; then
    echo "[stage] extract ✓ пропущен — распакованное дерево уже на месте (чекпоинт, --resume)"
    state_cli stage-skip --stage extract
  else
    run_stage extract 0 docker compose --profile extract run --rm artifact-extractor
  fi
  SCAN_TARGET_HOST="$(realpath "$EXTRACT_HOST")"
  export SCAN_TARGET_HOST
  export SCAN_TARGET_DISPLAY="$TARGET_RESOLVED -> $SCAN_TARGET_HOST"
  export SYFT_TARGET="/scan-target"
  export SYFT_FROM="dir"
fi

# ── Specialized format pipelines ─────────────────────────────────────────────
if [[ "$FORMAT" == "apk" ]]; then
  echo "[apk] Running APK analyzer..."
  run_stage apk-analyzer 0 docker compose --profile apk run --rm apk-analyzer

  echo "[apk] Running grype on generated SBOM..."
  export SYFT_TARGET="/workspace/artifacts/sbom/syft.json"
  export SYFT_FROM="sbom"
  if [[ $UPDATE_DB -eq 1 ]]; then
    run_step "update:grype" 0        docker compose --profile update run --rm grype-updater || die "grype-updater failed (exit $LAST_STEP_RC)"
    run_step "update:grype-import" 0 docker compose --profile update run --rm grype-db-importer || die "grype-db-importer failed (exit $LAST_STEP_RC)"
  fi
  db_status grype /var/lib/resilient-db/grype/active
  run_stage grype 0 docker compose --profile "$PROFILE" run --rm grype-scanner

  NATIVE_DIR="$ARTIFACTS_DIR/extracted/apk-native"
  if [[ -d "$NATIVE_DIR" ]] && [[ -n "$(find "$NATIVE_DIR" -name '*.so' 2>/dev/null)" ]]; then
    echo "[apk] Running cve-bin-tool on native .so files..."
    export CVE_BIN_TOOL_TARGET="/workspace/artifacts/extracted/apk-native"
    SCAN_TARGET_HOST="$(realpath "$NATIVE_DIR")"
    export SCAN_TARGET_HOST
    db_status cve-bin-tool /home/appuser/.cache/cve-bin-tool
    run_stage_soft cve-bin-tool "0 1" docker compose --profile "$PROFILE" run --rm cve-bin-tool-scanner
  fi

elif [[ "$FORMAT" == "win" ]]; then
  echo "[win] Running Windows installer analyzer..."
  run_stage win-analyzer 0 docker compose --profile win run --rm win-analyzer

  echo "[win] Running grype on generated SBOM..."
  export SYFT_TARGET="/workspace/artifacts/sbom/syft.json"
  export SYFT_FROM="sbom"
  if [[ $UPDATE_DB -eq 1 ]]; then
    run_step "update:grype" 0        docker compose --profile update run --rm grype-updater || die "grype-updater failed (exit $LAST_STEP_RC)"
    run_step "update:grype-import" 0 docker compose --profile update run --rm grype-db-importer || die "grype-db-importer failed (exit $LAST_STEP_RC)"
    run_step "update:cve-bin-tool" 0 docker compose --profile update run --rm cve-bin-tool-updater || die "cve-bin-tool-updater failed (exit $LAST_STEP_RC)"
  fi
  db_status grype /var/lib/resilient-db/grype/active
  db_status cve-bin-tool /home/appuser/.cache/cve-bin-tool
  run_stage grype 0 docker compose --profile "$PROFILE" run --rm grype-scanner

  WIN_EXTRACT_DIR="$ARTIFACTS_DIR/extracted/win-installer"
  if [[ -d "$WIN_EXTRACT_DIR" ]]; then
    cve_scan_host="$(realpath "$WIN_EXTRACT_DIR")"
    cve_scan_container="/workspace/artifacts/extracted/win-installer"
    force_direct_scan=0

    win_analysis_txt="$ARTIFACTS_DIR/reports/win/win_analysis.txt"
    if [[ -f "$win_analysis_txt" ]]; then
      binary_count="$(grep -Eo 'Binaries[[:space:]]*:[[:space:]]*[0-9]+[[:space:]]+total' "$win_analysis_txt" | head -n1 | sed -E 's/.*Binaries[[:space:]]*:[[:space:]]*([0-9]+).*/\1/' || true)"
      if [[ "${binary_count:-}" == "0" ]]; then
        force_direct_scan=1
        echo "[win] win-analyzer reported 0 PE binaries; switching cve-bin-tool to direct installer scan fallback..."
      fi
    fi

    if [[ $force_direct_scan -eq 1 ]]; then
      target_lower="${TARGET_RESOLVED,,}"
      if [[ "$target_lower" == *.exe || "$target_lower" == *.msi ]]; then
        cve_scan_host="$TARGET_RESOLVED"
        cve_scan_container="/scan-target"
      else
        candidate="$(find "$ARTIFACTS_DIR/extracted/current" -type f \( -iname '*.exe' -o -iname '*.msi' \) 2>/dev/null | head -n1 || true)"
        if [[ -n "${candidate:-}" ]]; then
          cve_scan_host="$(realpath "$candidate")"
          cve_scan_container="/scan-target"
        else
          echo "[win] No installer file candidate found for direct fallback; keeping extracted directory scan."
          force_direct_scan=0
        fi
      fi
    fi

    if [[ $force_direct_scan -eq 1 ]]; then
      echo "[win] Running cve-bin-tool on installer file fallback..."
    else
      echo "[win] Running cve-bin-tool on extracted installer contents..."
    fi
    export CVE_BIN_TOOL_TARGET="$cve_scan_container"
    export SCAN_TARGET_HOST="$cve_scan_host"
    run_stage_soft cve-bin-tool "0 1" docker compose --profile "$PROFILE" run --rm cve-bin-tool-scanner
  fi

else
  # ── Standard pipeline ───────────────────────────────────────────────────────
  case "$TOOL" in
    all)
      if [[ $UPDATE_DB -eq 1 ]]; then
        run_step "update:trivy" 0        docker compose --profile update run --rm -e "TRIVY_RENDERED_FLAGS=$TRIVY_FLAGS" trivy-updater || die "trivy-updater failed (exit $LAST_STEP_RC)"
        run_step "update:grype" 0        docker compose --profile update run --rm grype-updater || die "grype-updater failed (exit $LAST_STEP_RC)"
        run_step "update:grype-import" 0 docker compose --profile update run --rm grype-db-importer || die "grype-db-importer failed (exit $LAST_STEP_RC)"
        run_step "update:cve-bin-tool" 0 docker compose --profile update run --rm cve-bin-tool-updater || die "cve-bin-tool-updater failed (exit $LAST_STEP_RC)"
      fi
      db_status trivy /var/lib/resilient-db/trivy
      db_status grype /var/lib/resilient-db/grype/active
      db_status cve-bin-tool /home/appuser/.cache/cve-bin-tool
      run_stage sbom 0           docker compose --profile "$PROFILE" run --rm syft-sbom
      run_stage trivy 0          docker compose --profile "$PROFILE" run --rm -e "TRIVY_RENDERED_FLAGS=$TRIVY_FLAGS" trivy-scanner
      run_stage grype 0          docker compose --profile "$PROFILE" run --rm grype-scanner
      run_stage_soft cve-bin-tool "0 1" docker compose --profile "$PROFILE" run --rm cve-bin-tool-scanner
      ;;
    syft)
      run_stage sbom 0 docker compose --profile "$PROFILE" run --rm syft-sbom ;;
    grype)
      if [[ $UPDATE_DB -eq 1 ]]; then
        run_step "update:grype" 0        docker compose --profile update run --rm grype-updater || die "grype-updater failed (exit $LAST_STEP_RC)"
        run_step "update:grype-import" 0 docker compose --profile update run --rm grype-db-importer || die "grype-db-importer failed (exit $LAST_STEP_RC)"
      fi
      db_status grype /var/lib/resilient-db/grype/active
      run_stage sbom 0  docker compose --profile "$PROFILE" run --rm syft-sbom
      run_stage grype 0 docker compose --profile "$PROFILE" run --rm grype-scanner
      ;;
    trivy)
      if [[ $UPDATE_DB -eq 1 ]]; then
        run_step "update:trivy" 0 docker compose --profile update run --rm -e "TRIVY_RENDERED_FLAGS=$TRIVY_FLAGS" trivy-updater || die "trivy-updater failed (exit $LAST_STEP_RC)"
      fi
      db_status trivy /var/lib/resilient-db/trivy
      run_stage trivy 0 docker compose --profile "$PROFILE" run --rm -e "TRIVY_RENDERED_FLAGS=$TRIVY_FLAGS" trivy-scanner
      ;;
    cve-bin-tool)
      if [[ $UPDATE_DB -eq 1 ]]; then
        run_step "update:cve-bin-tool" 0 docker compose --profile update run --rm cve-bin-tool-updater || die "cve-bin-tool-updater failed (exit $LAST_STEP_RC)"
      fi
      db_status cve-bin-tool /home/appuser/.cache/cve-bin-tool
      run_stage_soft cve-bin-tool "0 1" docker compose --profile "$PROFILE" run --rm cve-bin-tool-scanner
      ;;
  esac
fi

# ── Collect reports ─────────────────────────────────────────────────
# report-collector runs as root (-u 0) so it can always aggregate into the
# bind-mounted artifacts/ regardless of which uid the scanners left report dirs
# as (mirrors orchestrator._run_scan and scripts/windows/run-scan.ps1).
export CASE_ID="$CASE_ID"
run_stage report 0 docker compose --profile report run --rm -u 0 report-collector

echo "[stage] collect-report (host $PYTHON_BIN)"
"$PYTHON_BIN" -m resilient_updates.cli collect-report \
  --reports-dir "$ARTIFACTS_DIR" \
  --target      "$SCAN_TARGET_HOST" \
  --display-target "$SCAN_TARGET_DISPLAY" \
  --case-id     "$CASE_ID" \
  --output      "$REPORT_MD"

echo "[stage] report-html (host $PYTHON_BIN)"
"$PYTHON_BIN" scripts/report_html.py \
  --artifacts-dir "$ARTIFACTS_DIR" \
  --target        "$SCAN_TARGET_DISPLAY" \
  --output        "$REPORT_HTML" || echo "[warn] HTML report generation failed -- skipping"

# ── Archive run history ───────────────────────────────────────────────────────
# Snapshot per-run evidence into a project-timestamp directory.  By default the
# helper places it under _SCA_reports/ on the scanner host.  Best-effort: never
# fails the scan.
{
  archive_args=(
    -m resilient_updates.cli archive-run
    --artifacts-dir "$ARTIFACTS_DIR"
    --target-host "$TARGET_RESOLVED"
    --target-container "$SCAN_TARGET_HOST"
    --case-id "$CASE_ID"
    --mode "$ARTIFACT_MODE"
    --stage final
    --status "done"
  )
  if [[ "${EL_SCA_ARCHIVE_EXTRACTED_TREE:-0}" =~ ^(1|true|yes|on)$ ]]; then
    archive_args+=(--include-extracted-tree)
  fi
  "$PYTHON_BIN" "${archive_args[@]}"
} || echo "[history] WARN: archive-run failed" >&2

# Mark the checkpoint state as finished (the NEXT --resume starts fresh only
# after a new `run-state begin` rewrites it for a new run-key).
state_cli finish --status "done"

# ── Done ──────────────────────────────────────────────────────────────────────────────────
echo ""
printf '\e[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n'
printf '\e[32m Reports ready:\e[0m\n'
printf '   MD  : %s\n' "$REPORT_MD"
printf '   HTML: %s\n' "$REPORT_HTML"
printf '\e[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n'
echo ""
