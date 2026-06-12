#!/usr/bin/env bash
set -euo pipefail

RUN_NETWORK_TESTS="${RUN_NETWORK_TESTS:-0}"
UPDATE_TIMEOUT_SECONDS="${CVE_BIN_TOOL_UPDATE_TIMEOUT_SECONDS:-180}"

compose_cmd=(docker compose)
if [[ -n "${COMPOSE_FILE:-}" ]]; then
  normalized="${COMPOSE_FILE//;/:}"
  IFS=':' read -r -a files <<< "$normalized"
  for file in "${files[@]}"; do
    [[ -n "$file" ]] || continue
    compose_cmd+=(-f "$file")
  done
fi

echo "[diag] cve-bin-tool version and supported flags"
"${compose_cmd[@]}" run --rm --entrypoint sh cve-bin-tool-updater -lc '
set -euo pipefail
cve-bin-tool --version
cve-bin-tool --help | grep -E -- "--nvd|--disable-data-source|--update"
'

if [[ "$RUN_NETWORK_TESTS" != "1" ]]; then
  echo "[diag] RUN_NETWORK_TESTS!=1, skipping online update attempts"
  exit 0
fi

run_attempt() {
  label="$1"
  shift
  echo ""
  echo "[diag] attempt: $label"
  set +e
  "${compose_cmd[@]}" run --rm --entrypoint sh cve-bin-tool-updater -lc "
set -eu
timeout $UPDATE_TIMEOUT_SECONDS cve-bin-tool $*
"
  rc=$?
  set -e
  echo "[diag] exit code: $rc"
}

run_attempt "api2" "--nvd api2 -u now"
run_attempt "json-mirror" "--nvd json-mirror -u now"
run_attempt "json-mirror-no-osv" "--nvd json-mirror -u now --disable-data-source OSV"
run_attempt "json-nvd" "--nvd json-nvd -u now"
