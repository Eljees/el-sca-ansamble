#!/usr/bin/env sh
set -eu

MODE="${1:-update}"
TARGET="${2:-${CVE_BIN_TOOL_TARGET:-/scan-target}}"
CONFIG_PATH="${CONFIG_PATH:-configs/feed_sources.yaml}"
REPORT_DIR="${REPORT_DIR:-artifacts/reports/cve-bin-tool}"
DB_ROOT="${CVE_BIN_TOOL_DB_ROOT:-/home/appuser/.cache/cve-bin-tool}"
STAGING_ROOT="${CVE_BIN_TOOL_STAGING_ROOT:-/var/lib/resilient-db/cve-bin-tool}"
ATTEMPTS_DIR="$REPORT_DIR/attempts"
UPDATE_TIMEOUT_SECONDS="${CVE_BIN_TOOL_UPDATE_TIMEOUT_SECONDS:-1800}"
SEED_TIMEOUT_SECONDS="${CVE_BIN_TOOL_SEED_TIMEOUT_SECONDS:-120}"
CVE_DISABLE_SOURCES="${CVE_BIN_TOOL_DISABLE_SOURCES:-}"
CVE_DISABLE_SOURCES_ON_RETRY="${CVE_BIN_TOOL_DISABLE_SOURCES_ON_RETRY:-OSV}"
CVE_UPDATE_MODES="${CVE_BIN_TOOL_UPDATE_MODES:-json-mirror json-nvd api2}"
CVE_OSV_ECOSYSTEMS="${CVE_BIN_TOOL_OSV_ECOSYSTEMS:-Debian Ubuntu Alpine Go PyPI Maven npm Rust}"
UPDATE_SCAN_DIR="${CVE_BIN_TOOL_UPDATE_SCAN_DIR:-/tmp/cvebt-update-empty}"
NVD_API_KEY_PRIMARY="${NVD_API_KEY:-}"
NVD_API_KEY_SECONDARY="${NVD_API_KEY_FALLBACK:-}"
DB_POLICY="${CVE_BIN_TOOL_DB_POLICY:-strict}"
BUNDLE_PATH="${CVE_BIN_TOOL_BUNDLE_PATH:-}"
USE_INTERNAL_MIRROR="${CVE_BIN_TOOL_USE_INTERNAL_MIRROR:-0}"
INTERNAL_MIRROR_URL="${CVE_BIN_TOOL_MIRROR_URL:-}"
STATUS_PATH="${CVE_BIN_TOOL_STATUS_PATH:-artifacts/provenance/cve-bin-tool-update-status.json}"
PRESEED_ACTIVE="${CVE_BIN_TOOL_PRESEED_ACTIVE:-1}"

mkdir -p "$REPORT_DIR" "$ATTEMPTS_DIR" "artifacts/provenance" "artifacts/mirror" "$STAGING_ROOT/candidates" "$STAGING_ROOT/tmp" "$STAGING_ROOT/previous"
if [ "${CVE_BIN_TOOL_WRAPPER_HEALTHCHECK:-0}" = "1" ]; then
  python -m resilient_updates.cli --config "$CONFIG_PATH" update cve-bin-tool >/dev/null
fi

if ! command -v cve-bin-tool >/dev/null 2>&1; then
  echo "cve-bin-tool is not installed in this environment" >&2
  exit 3
fi

_disable_sources_to_args() {
  # cve-bin-tool's --disable-data-source uses StringToListAction (store, not
  # append): repeating the flag overwrites the previous value, so only the LAST
  # invocation is honoured.  Pass all sources as a single comma-separated list
  # in ONE flag: "--disable-data-source A,B,C".
  _ds_raw="$1"
  _ds_csv=""
  for source in $_ds_raw; do
    [ -n "$source" ] || continue
    if [ -z "$_ds_csv" ]; then
      _ds_csv="$source"
    else
      _ds_csv="${_ds_csv},$source"
    fi
  done
  if [ -n "$_ds_csv" ]; then
    printf -- '--disable-data-source %s' "$_ds_csv"
  fi
}

BASE_DISABLE_ARGS="$(_disable_sources_to_args "$CVE_DISABLE_SOURCES")"
RETRY_DISABLE_ARGS="$(_disable_sources_to_args "$CVE_DISABLE_SOURCES_ON_RETRY")"
# Combined arg for retry attempts: BASE sources + RETRY sources in one CSV flag.
BASE_PLUS_RETRY_DISABLE_ARGS="$(_disable_sources_to_args "$CVE_DISABLE_SOURCES $CVE_DISABLE_SOURCES_ON_RETRY")"

write_status() {
  status="$1"
  reason="$2"
  mkdir -p "$(dirname "$STATUS_PATH")"
  python - "$STATUS_PATH" "$status" "$reason" "$DB_POLICY" <<'PY'
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

path = Path(sys.argv[1])
payload = {
    "tool": "cve-bin-tool",
    "db_policy": sys.argv[4],
    "status": sys.argv[2],
    "reason": sys.argv[3],
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
}
path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
PY
}

import_bundle_if_present() {
  _bundle_candidate_home="$1"
  [ -n "$BUNDLE_PATH" ] || return 1
  [ -f "$BUNDLE_PATH" ] || return 1
  mkdir -p "$_bundle_candidate_home/.cache"
  echo "[bundle] importing DB bundle from $BUNDLE_PATH"
  set +e
  HOME="$_bundle_candidate_home" XDG_CACHE_HOME="$_bundle_candidate_home/.cache" cve-bin-tool --import "$BUNDLE_PATH"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "[bundle] import failed with code $rc" >&2
    return "$rc"
  fi
  return 0
}

import_from_internal_mirror() {
  _mirror_candidate_home="$1"
  [ "$USE_INTERNAL_MIRROR" = "1" ] || return 1
  [ -n "$INTERNAL_MIRROR_URL" ] || return 1
  _mirror_bundle="$_mirror_candidate_home/internal-mirror-bundle.json"
  mkdir -p "$_mirror_candidate_home/.cache"
  echo "[mirror] fetching bundle from $INTERNAL_MIRROR_URL"
  set +e
  curl -fsSL "$INTERNAL_MIRROR_URL" -o "$_mirror_bundle"
  curl_rc=$?
  set -e
  if [ "$curl_rc" -ne 0 ]; then
    echo "[mirror] download failed with code $curl_rc" >&2
    return "$curl_rc"
  fi
  set +e
  HOME="$_mirror_candidate_home" XDG_CACHE_HOME="$_mirror_candidate_home/.cache" cve-bin-tool --import "$_mirror_bundle"
  import_rc=$?
  set -e
  if [ "$import_rc" -ne 0 ]; then
    echo "[mirror] import failed with code $import_rc" >&2
    return "$import_rc"
  fi
  return 0
}

preseed_candidate_from_active() {
  _candidate_home="$1"
  [ "$PRESEED_ACTIVE" = "1" ] || return 0
  [ -f "$DB_ROOT/cve.db" ] || return 0

  echo "[attempt] preseeding candidate cache from active DB root: $DB_ROOT"
  rm -rf "$_candidate_home/.cache/cve-bin-tool"
  mkdir -p "$_candidate_home/.cache"
  if ! cp -a "$DB_ROOT" "$_candidate_home/.cache/"; then
    echo "[attempt] WARN preseed copy failed, continuing with empty candidate cache" >&2
  fi
}

attempt_update() {
  nvd_mode="$1"
  api_label="$2"
  api_key="${3:-}"
  disable_args="${4:-$BASE_DISABLE_ARGS}"
  attempt_id="${nvd_mode}-${api_label}"
  candidate_home="$STAGING_ROOT/candidates/$attempt_id"
  candidate_root="$candidate_home/.cache/cve-bin-tool"
  attempt_log="$ATTEMPTS_DIR/${attempt_id}.log"
  rm -rf "$candidate_home"
  mkdir -p "$candidate_home/.cache"

  {
    echo "[attempt] mode=$nvd_mode api_label=$api_label started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    preseed_candidate_from_active "$candidate_home"
    set +e
    HOME="$candidate_home" XDG_CACHE_HOME="$candidate_home/.cache" NVD_MODE="$nvd_mode" ATTEMPT_API_KEY="$api_key" CVE_DISABLE_ARGS="$disable_args" UPDATE_TIMEOUT_SECONDS="$UPDATE_TIMEOUT_SECONDS" UPDATE_SCAN_DIR="$UPDATE_SCAN_DIR" \
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
scan_dir = os.environ.get("UPDATE_SCAN_DIR", "/tmp/cvebt-update-empty")
os.makedirs(scan_dir, exist_ok=True)
cmd.append(scan_dir)
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

feed_import_attempt() {
  # Build the NVD half of cve.db straight from the static NVD 2.0 JSON feeds
  # (https://nvd.nist.gov/feeds/json/cve/2.0/) instead of the rate-limited REST
  # API that returns 403 in some egress contours.  Reuses cve-bin-tool's own
  # parser via resilient_updates/nvd_feed_import.py (no fork).  Optionally enriches with
  # the non-NVD sources on top.  Mirrors attempt_update's logging/audit so the
  # existing activation flow consumes the produced candidate root unchanged.
  attempt_id="feed-default"
  candidate_home="$STAGING_ROOT/candidates/$attempt_id"
  candidate_root="$candidate_home/.cache/cve-bin-tool"
  attempt_log="$ATTEMPTS_DIR/${attempt_id}.log"
  rm -rf "$candidate_home"
  mkdir -p "$candidate_root"
  feed_import="${CVE_BIN_TOOL_FEED_IMPORT:-resilient_updates/nvd_feed_import.py}"

  feed_rc_file="$candidate_home/feed_rc"
  echo "[feed] start $(date -u +%Y-%m-%dT%H:%M:%SZ) db-root=$candidate_root" | tee "$attempt_log"

  # 1) Enrichment FIRST — while the candidate cve.db does NOT yet exist, so
  #    cve-bin-tool actually FETCHES the non-NVD sources.  (If we imported NVD
  #    first, the resulting cve.db would be <24h old and cve-bin-tool's
  #    get_cvelist_if_stale would skip the whole update — the source fetch would
  #    never run.)  cve-bin-tool's Python client cannot use a SOCKS proxy, so
  #    route it through an HTTP proxy (CVE_BIN_TOOL_ENRICH_PROXY, e.g. the xray
  #    sidecar at http://proxy-xray:8118).  NVD is disabled (it comes from the
  #    feeds in step 2); CVE_BIN_TOOL_ENRICH_DISABLE drops sources unreachable in
  #    this contour (e.g. "GAD REDHAT" behind a 403).  Best-effort: any failure
  #    here is non-fatal — NVD-only is still a usable, activatable DB.
  if [ "${CVE_BIN_TOOL_FEED_ENRICH:-1}" = "1" ]; then
    mkdir -p "$UPDATE_SCAN_DIR"
    # Build ONE combined --disable-data-source arg for the enrichment step:
    # NVD always off (feed import handles NVD) + contour-specific skips +
    # caller-specified CVE_BIN_TOOL_DISABLE_SOURCES.  Using a single CSV flag
    # is required because StringToListAction (store) only keeps the last flag.
    # shellcheck disable=SC2086
    _enrich_disable_arg="$(_disable_sources_to_args "NVD ${CVE_BIN_TOOL_ENRICH_DISABLE:-} $CVE_DISABLE_SOURCES")"
    {
      echo "[feed] enrichment (pre-NVD) proxy=${CVE_BIN_TOOL_ENRICH_PROXY:-none}"
      set +e
      # ALL_PROXY (SOCKS) is unset here: cve-bin-tool's Python client can't use
      # SOCKS, and a leftover socks ALL_PROXY makes its startup version-check
      # stall.  --disable-version-check skips that PyPI call entirely.  All HTTP
      # goes through the xray HTTP bridge (CVE_BIN_TOOL_ENRICH_PROXY).
      # shellcheck disable=SC2086
      ALL_PROXY="" all_proxy="" NO_PROXY="${NO_PROXY:-}" \
      HOME="$candidate_home" XDG_CACHE_HOME="$candidate_home/.cache" \
        HTTP_PROXY="${CVE_BIN_TOOL_ENRICH_PROXY:-${HTTP_PROXY:-}}" \
        HTTPS_PROXY="${CVE_BIN_TOOL_ENRICH_PROXY:-${HTTPS_PROXY:-}}" \
        cve-bin-tool --update now --disable-version-check \
          $_enrich_disable_arg "$UPDATE_SCAN_DIR"
      echo "[feed] enrichment exit=$?"
      set -e
    } >>"$attempt_log" 2>&1
  fi

  # 2) NVD feed import.  Its stdout must reach the CONTAINER stdout (not just the
  # log) so the dashboard can fill the barrel from "X MiB / Y MiB" progress;
  # tee duplicates it to the attempt log.  dash has no PIPESTATUS, so the
  # importer's own exit code is stashed in a file.
  # shellcheck disable=SC2086
  (
    set +e
    python "$feed_import" --db-root "$candidate_root" \
      ${CVE_BIN_TOOL_FEED_START_YEAR:+--start-year $CVE_BIN_TOOL_FEED_START_YEAR} \
      ${CVE_BIN_TOOL_FEED_END_YEAR:+--end-year $CVE_BIN_TOOL_FEED_END_YEAR} \
      ${CVE_BIN_TOOL_FEED_BASE:+--feed-base $CVE_BIN_TOOL_FEED_BASE}
    echo $? > "$feed_rc_file"
  ) 2>&1 | tee -a "$attempt_log"
  feed_rc="$(cat "$feed_rc_file" 2>/dev/null || echo 1)"
  if [ "$feed_rc" -ne 0 ]; then
    echo "[feed] NVD feed import failed rc=$feed_rc" | tee -a "$attempt_log"
    return "$feed_rc"
  fi

  # 3) Audit (doesn't drive the barrel).
  python -m resilient_updates.cli --config "$CONFIG_PATH" audit cve-bin-tool-db --db-root "$candidate_root" >>"$attempt_log" 2>&1
}

case "$MODE" in
  update)
    write_status "failed" "update started"
    updated=0
    candidate_count=0
    last_attempt_log=""
    set --
    for nvd_mode in $CVE_UPDATE_MODES; do
      if [ "$nvd_mode" = "feed" ]; then
        candidate_root="$STAGING_ROOT/candidates/feed-default/.cache/cve-bin-tool"
        candidate_count=$((candidate_count + 1))
        set -- "$@" --candidate-root "$candidate_root"
        if feed_import_attempt; then
          updated=1
          break
        fi
        last_attempt_log="$ATTEMPTS_DIR/feed-default.log"
        continue
      fi
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
          if attempt_update "$nvd_mode" "$api_label" "$api_key" "$BASE_DISABLE_ARGS"; then
            updated=1
            break
          fi
          last_attempt_log="$ATTEMPTS_DIR/${nvd_mode}-${api_label}.log"
          if [ "$nvd_mode" = "json-mirror" ] \
             && [ -n "$RETRY_DISABLE_ARGS" ] \
             && [ -f "$last_attempt_log" ] \
             && grep -q "KeyError: 'type'" "$last_attempt_log"; then
            mkdir -p artifacts/debug/cve-bin-tool
            cp "$last_attempt_log" "artifacts/debug/cve-bin-tool/json-mirror-keyerror-type.log" 2>/dev/null || true
            retry_label="${api_label}-retry-disabled-sources"
            retry_root="$STAGING_ROOT/candidates/${nvd_mode}-${retry_label}/.cache/cve-bin-tool"
            candidate_count=$((candidate_count + 1))
            set -- "$@" --candidate-root "$retry_root"
            if attempt_update "$nvd_mode" "$retry_label" "$api_key" "$BASE_PLUS_RETRY_DISABLE_ARGS"; then
              updated=1
              break
            fi
          fi
        done
        if [ "$updated" -eq 1 ]; then
          break
        fi
        if [ -z "$NVD_API_KEY_PRIMARY" ] && [ -z "$NVD_API_KEY_SECONDARY" ]; then
          candidate_root="$STAGING_ROOT/candidates/${nvd_mode}-no-key/.cache/cve-bin-tool"
          candidate_count=$((candidate_count + 1))
          set -- "$@" --candidate-root "$candidate_root"
          if attempt_update "$nvd_mode" "no-key" "" "$BASE_DISABLE_ARGS"; then
            updated=1
            break
          fi
          last_attempt_log="$ATTEMPTS_DIR/${nvd_mode}-no-key.log"
          if [ "$nvd_mode" = "json-mirror" ] \
             && [ -n "$RETRY_DISABLE_ARGS" ] \
             && [ -f "$last_attempt_log" ] \
             && grep -q "KeyError: 'type'" "$last_attempt_log"; then
            mkdir -p artifacts/debug/cve-bin-tool
            cp "$last_attempt_log" "artifacts/debug/cve-bin-tool/json-mirror-keyerror-type.log" 2>/dev/null || true
            retry_label="no-key-retry-disabled-sources"
            retry_root="$STAGING_ROOT/candidates/${nvd_mode}-${retry_label}/.cache/cve-bin-tool"
            candidate_count=$((candidate_count + 1))
            set -- "$@" --candidate-root "$retry_root"
            if attempt_update "$nvd_mode" "$retry_label" "" "$BASE_PLUS_RETRY_DISABLE_ARGS"; then
              updated=1
              break
            fi
          fi
        fi
      else
        candidate_root="$STAGING_ROOT/candidates/${nvd_mode}-default/.cache/cve-bin-tool"
        candidate_count=$((candidate_count + 1))
        set -- "$@" --candidate-root "$candidate_root"
        if attempt_update "$nvd_mode" "default" "" "$BASE_DISABLE_ARGS"; then
          updated=1
          break
        fi
        last_attempt_log="$ATTEMPTS_DIR/${nvd_mode}-default.log"
        if [ "$nvd_mode" = "json-mirror" ] \
           && [ -n "$RETRY_DISABLE_ARGS" ] \
           && [ -f "$last_attempt_log" ] \
           && grep -q "KeyError: 'type'" "$last_attempt_log"; then
          mkdir -p artifacts/debug/cve-bin-tool
          cp "$last_attempt_log" "artifacts/debug/cve-bin-tool/json-mirror-keyerror-type.log" 2>/dev/null || true
          retry_label="default-retry-disabled-sources"
          retry_root="$STAGING_ROOT/candidates/${nvd_mode}-${retry_label}/.cache/cve-bin-tool"
          candidate_count=$((candidate_count + 1))
          set -- "$@" --candidate-root "$retry_root"
          if attempt_update "$nvd_mode" "$retry_label" "" "$BASE_PLUS_RETRY_DISABLE_ARGS"; then
            updated=1
            break
          fi
        fi
        if [ "$nvd_mode" = "json-nvd" ] \
           && [ -f "$last_attempt_log" ] \
           && grep -qi "SHAMismatch" "$last_attempt_log"; then
          mkdir -p artifacts/debug/cve-bin-tool
          cp "$last_attempt_log" "artifacts/debug/cve-bin-tool/json-nvd-sha-mismatch.log" 2>/dev/null || true
          sleep 5
          retry_label="default-retry-sha"
          retry_root="$STAGING_ROOT/candidates/${nvd_mode}-${retry_label}/.cache/cve-bin-tool"
          candidate_count=$((candidate_count + 1))
          set -- "$@" --candidate-root "$retry_root"
          if attempt_update "$nvd_mode" "$retry_label" "" "$BASE_DISABLE_ARGS"; then
            updated=1
            break
          fi
        fi
      fi
    done

    if [ "$updated" -eq 0 ]; then
      mirror_home="$STAGING_ROOT/candidates/internal-mirror-default"
      mirror_root="$mirror_home/.cache/cve-bin-tool"
      candidate_count=$((candidate_count + 1))
      set -- "$@" --candidate-root "$mirror_root"
      if import_from_internal_mirror "$mirror_home"; then
        python -m resilient_updates.cli --config "$CONFIG_PATH" audit cve-bin-tool-db --db-root "$mirror_root" \
          >"$ATTEMPTS_DIR/internal-mirror-default.log" 2>&1 || true
        updated=1
      fi
    fi

    if [ "$updated" -eq 0 ]; then
      bundle_home="$STAGING_ROOT/candidates/bundle-import-default"
      bundle_root="$bundle_home/.cache/cve-bin-tool"
      candidate_count=$((candidate_count + 1))
      set -- "$@" --candidate-root "$bundle_root"
      if import_bundle_if_present "$bundle_home"; then
        python -m resilient_updates.cli --config "$CONFIG_PATH" audit cve-bin-tool-db --db-root "$bundle_root" \
          >"$ATTEMPTS_DIR/bundle-import-default.log" 2>&1 || true
        updated=1
      fi
    fi

    [ "$candidate_count" -gt 0 ] || exit 1
    set +e
    python -m resilient_updates.cli --config "$CONFIG_PATH" activate cve-bin-tool-db "$@" --active-root "$DB_ROOT" --previous-root "$STAGING_ROOT/previous" --temp-root "$STAGING_ROOT/tmp" --provenance-path "artifacts/provenance/cve-bin-tool-db.json"
    activate_code=$?
    set -e
    activation_status="$(python - <<'PY'
from __future__ import annotations
import json
from pathlib import Path

payload = {}
path = Path("artifacts/provenance/cve-bin-tool-db.json")
if path.exists():
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        payload = {}
print(str(payload.get("activation_status") or "failed"))
PY
)"
    if [ "$activate_code" -eq 5 ]; then
      echo "cve-bin-tool updater fell back to last-known-good database" >&2
      write_status "lkg" "last-known-good database used"
      exit 0
    fi
    if [ "$activate_code" -eq 0 ]; then
      write_status "$activation_status" "candidate database activated"
    else
      write_status "failed" "activation failed with code $activate_code"
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

    # Purge the previous run's report: cve-bin-tool refuses to overwrite an
    # existing report.json and dumps output.cve-bin-tool.<ts>.json into the
    # workspace root instead (stale report + root clutter). We run as root in
    # the container, so this also removes root-owned files the host cannot.
    rm -f "$REPORT_DIR/report.json" "$REPORT_DIR/timeout.flag" 2>/dev/null || true
    rm -f /workspace/output.cve-bin-tool.*.json 2>/dev/null || true

    # ── SBOM fast-path ────────────────────────────────────────────────────────
    # If Syft already generated a SBOM (cyclonedx / spdx / syft-json), feed it
    # directly to cve-bin-tool instead of scanning the binary tree.
    # This replaces 365 regex-per-binary checkers with a simple DB lookup:
    # seconds instead of 10+ minutes for large Go / JVM targets.
    #
    # AUTO-DETECT: if CVE_BIN_TOOL_SBOM_PATH wasn't set explicitly but Syft
    # already produced a syft.json in the standard location, use it.  This
    # turns the slow binary scan into a SBOM lookup whenever the pipeline
    # ran syft-sbom first (i.e. the default `run-scan.sh` flow).  Opt out
    # by exporting CVE_BIN_TOOL_AUTO_SBOM=0.
    if [ -z "$SBOM_PATH" ] && [ "${CVE_BIN_TOOL_AUTO_SBOM:-1}" = "1" ]; then
      # syft.json (native Syft format) is NOT accepted by cve-bin-tool's --sbom flag.
      # Only cyclonedx and spdx are valid; try cyclonedx first (richer component data).
      for candidate in \
        /workspace/artifacts/sbom/cyclonedx.json \
        /workspace/artifacts/sbom/spdx.json; do
        if [ -s "$candidate" ]; then
          SBOM_PATH="$candidate"
          case "$candidate" in
            *cyclonedx.json) SBOM_FORMAT="cyclonedx" ;;
            *spdx.json)      SBOM_FORMAT="spdx" ;;
          esac
          echo "[cve-bin-tool] auto-SBOM: found $candidate (format=$SBOM_FORMAT)"
          break
        fi
      done
    fi
    #
    # Explicit override is still respected:
    #   CVE_BIN_TOOL_SBOM_PATH=/workspace/artifacts/sbom/cyclonedx.json
    #   CVE_BIN_TOOL_SBOM_FORMAT=cyclonedx   (or spdx / syft)

    # ── Go runtime injection into SBOM ────────────────────────────────────────
    # syft's CycloneDX SBOM catalogs Go *module* dependencies but omits the
    # Go *runtime* (golang:go X.Y.Z) because syft reports packages, not the
    # toolchain that compiled them.  cve-bin-tool's Go checker matches NVD
    # entries for the runtime itself (e.g. CVE-2024-3566 affects go < 1.24).
    #
    # Fix: when a SBOM is available and the scan target contains Go binaries,
    # extract the embedded Go version(s) from go:buildinfo and inject each as
    # a separate CycloneDX component before feeding the SBOM to cve-bin-tool.
    #
    # We collect MULTIPLE versions because a single tarball can ship binaries
    # compiled with different Go toolchains (vendored helpers, plugins, the
    # main daemon) — see CYBERSEC-11531 reference (Prometheus 3.11 contained
    # both go1.23.0 and go1.26.1).  The legacy "first match wins" injection
    # only ever surfaced one runtime CVE per scan, so a clean reproduction
    # would consistently undercount findings.
    #
    # Opt-out: CVE_BIN_TOOL_INJECT_GO_RUNTIME=0
    if [ -n "$SBOM_PATH" ] && [ -f "$SBOM_PATH" ] && [ "${CVE_BIN_TOOL_INJECT_GO_RUNTIME:-1}" = "1" ]; then
      GO_VERSIONS_FILE="/tmp/cbt-go-versions.txt"
      : > "$GO_VERSIONS_FILE"
      if [ -d "$TARGET" ]; then
        # Detect ELF files by magic bytes rather than the execute bit:
        # on Windows + WSL2 bind-mounts the exec bit is not preserved, so
        # `find -perm /111` lies.  The size>+1M fallback catches large
        # monoliths but skips small helper binaries (e.g. promtool ~ 80 MB
        # is fine, but tiny sidecars and node_exporter helpers might fall
        # through).  Walk *every* regular file up to depth 6 and probe the
        # first 4 bytes for the ELF magic 0x7F 'E' 'L' 'F'.
        #
        # Python is preferred over `xxd`/`hexdump` because the cve-bin-tool
        # image ships python:3.12-slim but neither hexdump utility.
        ELF_LIST="/tmp/cbt-elf-list.txt"
        TARGET_SCAN_DIR="$TARGET" python3 - <<'PYEOF' >"$ELF_LIST"
import os, sys
root = os.environ['TARGET_SCAN_DIR']
for dirpath, _dirs, files in os.walk(root, followlinks=False):
    # mirror -maxdepth 6 from the find invocation
    depth = dirpath[len(root):].count(os.sep)
    if depth > 6:
        continue
    for name in files:
        path = os.path.join(dirpath, name)
        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
        except OSError:
            continue
        if magic == b'\x7fELF':
            print(path)
PYEOF
        # Pull every embedded "go1.X.Y" string out of every ELF binary and
        # deduplicate.  grep -oa = print bytes that match without binary
        # warning, -m1 = stop after first match per file (one runtime per
        # binary is the rule), sort -u = collapse duplicates across binaries.
        while IFS= read -r _bin; do
          [ -n "$_bin" ] || continue
          grep -oam1 'go1\.[0-9][0-9]*\.[0-9][0-9]*' "$_bin" 2>/dev/null
        done < "$ELF_LIST" | sed 's/^go//' | sort -u > "$GO_VERSIONS_FILE.tmp"
        mv "$GO_VERSIONS_FILE.tmp" "$GO_VERSIONS_FILE"
        elf_count=$(wc -l < "$ELF_LIST" 2>/dev/null || echo 0)
        ver_count=$(wc -l < "$GO_VERSIONS_FILE" 2>/dev/null || echo 0)
        echo "[cve-bin-tool] ELF files probed: $elf_count, unique Go runtime versions: $ver_count"
        if [ "$ver_count" -gt 0 ]; then
          while IFS= read -r _v; do
            [ -n "$_v" ] && echo "[cve-bin-tool]   - go$_v"
          done < "$GO_VERSIONS_FILE"
        fi
      fi
      # ── Always-on SBOM patch: filter UNKNOWN-versioned components + inject Go runtime ──
      # cve-bin-tool 3.4 raises UnknownVersion('version string = UNKNOWN')
      # on parse_version when a SBOM component carries `version: "UNKNOWN"`
      # — it aborts the entire SBOM scan partway through.  Filter such
      # components before passing the SBOM in.  We run the patcher
      # unconditionally (even with no Go versions to inject) so the same
      # sanitised file is always the one consumed by cve-bin-tool.
      PATCHED_SBOM="/tmp/cbt-sbom-patched.json"
      set +e
      SBOM_PATH_IN="$SBOM_PATH" VERSIONS_FILE="${GO_VERSIONS_FILE:-/dev/null}" PATCHED_OUT="$PATCHED_SBOM" \
      python3 - <<'PYEOF'
import json
import os
import shutil
import sys

sbom_in = os.environ['SBOM_PATH_IN']
versions_file = os.environ['VERSIONS_FILE']
patched = os.environ['PATCHED_OUT']

_BAD_VERSIONS = {'', 'unknown', 'none', 'null'}


def _is_bad_version(value):
    if value is None:
        return True
    return str(value).strip().lower() in _BAD_VERSIONS


try:
    versions = []
    if versions_file != '/dev/null':
        try:
            with open(versions_file) as fh:
                versions = sorted({line.strip() for line in fh if line.strip()})
        except OSError:
            versions = []

    with open(sbom_in) as fh:
        sbom = json.load(fh)

    comps_in = sbom.get('components') or []
    comps_filtered = []
    dropped = 0
    for comp in comps_in:
        if isinstance(comp, dict) and _is_bad_version(comp.get('version')):
            dropped += 1
            continue
        comps_filtered.append(comp)

    added = 0
    for v in versions:
        if not any(
            isinstance(c, dict) and c.get('name') == 'go' and c.get('version') == v
            for c in comps_filtered
        ):
            comps_filtered.append({
                'type': 'library',
                'name': 'go',
                'version': v,
                'purl': 'pkg:golang/go@' + v,
                'description': 'Go toolchain runtime (injected from go:buildinfo)',
            })
            added += 1

    sbom['components'] = comps_filtered
    with open(patched, 'w') as fh:
        json.dump(sbom, fh)

    print(
        '[cve-bin-tool] SBOM patched: dropped {} unknown-version components, '
        'added {} golang:go entries ({} unique Go versions, {} components total)'.format(
            dropped, added, len(versions), len(comps_filtered)
        )
    )
except Exception as exc:  # noqa: BLE001
    print('[cve-bin-tool] WARN: SBOM patching failed: {}'.format(exc), file=sys.stderr)
    shutil.copy(sbom_in, patched)
PYEOF
      inject_rc=$?
      set -e
      if [ "$inject_rc" -eq 0 ] && [ -s "$PATCHED_SBOM" ]; then
        SBOM_PATH="$PATCHED_SBOM"
      else
        echo "[cve-bin-tool] WARN: SBOM patching failed (rc=$inject_rc) — using original SBOM" >&2
      fi
    fi

    if [ -n "$SBOM_PATH" ] && [ -f "$SBOM_PATH" ]; then
      echo "[cve-bin-tool] SBOM fast-path: format=$SBOM_FORMAT file=$SBOM_PATH"
      echo "[cve-bin-tool] scan timeout=${SCAN_TIMEOUT}s (SBOM lookup — much faster than binary scan)"
      set +e
      # --sbom-file = path to the SBOM (NOT the positional [directory] argument)
      # --sbom      = format: cyclonedx | spdx | swid
      timeout "$SCAN_TIMEOUT" cve-bin-tool --offline \
        --sbom "$SBOM_FORMAT" --sbom-file "$SBOM_PATH" \
        --format json --output-file "$REPORT_DIR/report.json"
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
      # Use `grep -a` (treat binary as text) — works without binutils/strings,
      # available in every Docker base image.
      go_count=0
      native_so_count=0
      # -perm /111 works on Linux FS; on Windows NTFS bind-mounts all files
      # appear as rw------- (no execute bit).  Fallback: also include files
      # larger than 1 MB, which covers all realistic Go/ELF binary sizes.
      executables=$(find "$EFFECTIVE_TARGET" -maxdepth 6 -type f \
        \( -perm /111 -o -size +1M \) 2>/dev/null | head -50)
      for bin in $executables; do
        # Go detection: every Go binary contains a build-info string like "go1.21.0"
        # grep -a = treat binary as text; -q = quiet; -m1 = stop at first match
        if grep -qam1 'go1\.[0-9][0-9]*\.' "$bin" 2>/dev/null; then
          go_count=$((go_count + 1))
        fi
      done
      # Native .so files indicate non-Go (C/C++) dynamic libraries
      native_so_count=$(find "$EFFECTIVE_TARGET" -maxdepth 6 -name "*.so" -o -name "*.so.*" 2>/dev/null | wc -l)

      echo "[cve-bin-tool] auto-detect: go_binaries=$go_count native_so=$native_so_count"
      if [ "$go_count" -gt 0 ] && [ "$native_so_count" -eq 0 ]; then
        # Pure Go target — restrict regular checkers to language-relevant ones.
        #
        # -r filters REGULAR checkers (the byte-level regex pack).  Language
        # checkers (go/python/java/…) always run; they parse embedded module
        # manifests rather than do regex scans, so they're cheap and we
        # cannot disable them from CLI.
        #
        # Pruned from the previous list: php, python, perl.  Their regular
        # checkers ship the most expensive backtracking patterns and trigger
        # 10-30 min hangs on big Go binaries (Prometheus, Grafana etc.).
        # `go` and `rust` cover the relevant signal for Go-only artifacts.
        CHECKERS="go,rust"
        echo "[cve-bin-tool] → pure Go target: regular checkers limited to {go,rust}"
        echo "[cve-bin-tool]   language checkers (12) still run for go/rust/python/... module info"
        echo "[cve-bin-tool]   (set CVE_BIN_TOOL_CHECKERS=all to run all 365 regular checkers)"
      elif [ "$go_count" -gt 0 ] && [ "$native_so_count" -gt 0 ]; then
        echo "[cve-bin-tool] → mixed Go+native: running all regular checkers"
      else
        echo "[cve-bin-tool] → native/unknown: running all regular checkers"
      fi
    fi

    CHECKER_FLAGS=""
    if [ -n "$CHECKERS" ] && [ "$CHECKERS" != "all" ]; then
      # cve-bin-tool 3.4 uses -r / --runs to restrict which checkers run
      CHECKER_FLAGS="-r $CHECKERS"
      echo "[cve-bin-tool] checkers: $CHECKERS"
    fi

    # ── Exclude oversize binaries to keep wall-clock predictable ──────────────
    # Anything larger than CVE_BIN_TOOL_MAX_FILE_MB (default 256 MB) is skipped
    # via -e EXCLUDE.  Large Go monoliths with bundled assets blow up regex
    # backtracking budgets — we'd rather miss one outlier than wedge the run.
    # Set CVE_BIN_TOOL_MAX_FILE_MB=0 to disable the filter entirely.
    MAX_FILE_MB="${CVE_BIN_TOOL_MAX_FILE_MB:-256}"
    EXCLUDE_FLAGS=""
    if [ "$MAX_FILE_MB" -gt 0 ]; then
      oversize_list=$(find "$EFFECTIVE_TARGET" -type f -size +"${MAX_FILE_MB}"M 2>/dev/null | tr '\n' ',' | sed 's/,$//')
      if [ -n "$oversize_list" ]; then
        EXCLUDE_FLAGS="-e $oversize_list"
        oversize_count=$(echo "$oversize_list" | tr ',' '\n' | wc -l)
        echo "[cve-bin-tool] excluding $oversize_count file(s) larger than ${MAX_FILE_MB} MB"
        printf 'excluded_files_larger_than_mb=%s\n%s\n' "$MAX_FILE_MB" "$oversize_list" \
          > "$REPORT_DIR/excluded.flag"
      fi
    fi

    # ── Parallelism ──────────────────────────────────────────────────────────
    # NOTE: cve-bin-tool 3.4 does NOT expose a CLI flag for binary-scan worker
    # count.  Its `-n` flag is reserved for `--nvd <mode>` (api/api2/json/
    # json-mirror/json-nvd) — passing a number to `-n` aborts the run.
    # Internally cve-bin-tool builds a multiprocessing.Pool sized to the host
    # CPU count, so binary scan is already parallel by default.
    #
    # `CVE_BIN_TOOL_PARALLEL` is kept as a reserved env knob: when a future
    # cve-bin-tool release ships a real `--workers N` flag we can wire it
    # here without touching the call-sites again.
    PARALLEL_FLAGS=""
    if [ -n "${CVE_BIN_TOOL_PARALLEL:-}" ]; then
      echo "[cve-bin-tool] CVE_BIN_TOOL_PARALLEL=$CVE_BIN_TOOL_PARALLEL — no-op for v3.4 (binary scan uses CPU-count multiprocessing.Pool internally)"
    fi

    echo "[cve-bin-tool] scan timeout=${SCAN_TIMEOUT}s target=$EFFECTIVE_TARGET"
    set +e
    # shellcheck disable=SC2086
    timeout "$SCAN_TIMEOUT" cve-bin-tool --offline $PARALLEL_FLAGS $CHECKER_FLAGS $EXCLUDE_FLAGS --format json --output-file "$REPORT_DIR/report.json" "$EFFECTIVE_TARGET"
    scan_rc=$?
    set -e
    if [ "$scan_rc" -eq 124 ]; then
      echo "[cve-bin-tool] WARN: scan timed out after ${SCAN_TIMEOUT}s -- writing empty report" >&2
      printf 'timed_out_after=%s\n' "$SCAN_TIMEOUT" > "$REPORT_DIR/timeout.flag"
      [ -f "$REPORT_DIR/report.json" ] || printf '[]' > "$REPORT_DIR/report.json"
      exit 0
    fi
    # cve-bin-tool exit codes:
    #   0 = success, no CVEs found
    #   1 = success, CVEs found  ← keep compose runs green
    #   2+ = actual tool/runtime error
    if [ "$scan_rc" -le 1 ]; then
      if [ ! -s "$REPORT_DIR/report.json" ]; then
        latest=$(ls -t /workspace/output.cve-bin-tool.*.json 2>/dev/null | head -1)
        if [ -n "$latest" ]; then
          mv "$latest" "$REPORT_DIR/report.json"
          echo "[cve-bin-tool] moved orphan output → $REPORT_DIR/report.json"
        else
          printf '[]' > "$REPORT_DIR/report.json"
        fi
      fi
      echo "[cve-bin-tool] binary scan done (exit $scan_rc)"
      exit 0
    fi
    if [ "$scan_rc" -ne 0 ]; then
      echo "[cve-bin-tool] scan exited with code $scan_rc" >&2
      exit "$scan_rc"
    fi
    ;;
  export)
    export_path="${BUNDLE_PATH:-artifacts/mirror/cve-bin-tool-export.json}"
    mkdir -p "$(dirname "$export_path")"
    cve-bin-tool --export "$export_path"
    ;;
  import)
    import_path="${BUNDLE_PATH:-artifacts/mirror/cve-bin-tool-export.json}"
    cve-bin-tool --import "$import_path"
    ;;
  *)
    echo "Unsupported mode: $MODE" >&2
    exit 2
    ;;
esac
