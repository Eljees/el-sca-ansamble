#!/usr/bin/env bash
set -euo pipefail

RENDERED_PATH="${RENDERED_PATH:-/tmp/el-sca-compose.rendered.yml}"
PROFILE="${PROFILE:-scan}"

is_abs_path() {
  local value="$1"
  case "$value" in
    /*) return 0 ;;
    [A-Za-z]:[\\/]* ) return 0 ;;
    *) return 1 ;;
  esac
}

compose_cmd=(docker compose)
if [[ -n "${COMPOSE_FILE:-}" ]]; then
  normalized="${COMPOSE_FILE//;/:}"
  IFS=':' read -r -a files <<< "$normalized"
  for file in "${files[@]}"; do
    [[ -n "$file" ]] || continue
    compose_cmd+=(-f "$file")
  done
fi

: "${SCAN_TARGET_HOST:?Set SCAN_TARGET_HOST (absolute path to artifact/directory)}"
: "${REPORT_OUTPUT:?Set REPORT_OUTPUT (container path for final report)}"

if [[ -z "${EXTRACT_INPUT_HOST:-}" ]]; then
  export EXTRACT_INPUT_HOST="$SCAN_TARGET_HOST"
fi

if ! is_abs_path "$SCAN_TARGET_HOST"; then
  echo "SCAN_TARGET_HOST must be absolute: $SCAN_TARGET_HOST" >&2
  exit 2
fi
if ! is_abs_path "$EXTRACT_INPUT_HOST"; then
  echo "EXTRACT_INPUT_HOST must be absolute: $EXTRACT_INPUT_HOST" >&2
  exit 2
fi

if [[ ! -e "$SCAN_TARGET_HOST" ]]; then
  echo "SCAN_TARGET_HOST does not exist: $SCAN_TARGET_HOST" >&2
  exit 2
fi
if [[ ! -e "$EXTRACT_INPUT_HOST" ]]; then
  echo "EXTRACT_INPUT_HOST does not exist: $EXTRACT_INPUT_HOST" >&2
  exit 2
fi

case "$REPORT_OUTPUT" in
  /workspace/*) ;;
  *) mkdir -p "$(dirname "$REPORT_OUTPUT")" ;;
esac

"${compose_cmd[@]}" --profile "$PROFILE" config > "$RENDERED_PATH"

if grep -nE '\$\{(SCAN_TARGET_HOST|EXTRACT_INPUT_HOST|REPORT_OUTPUT)([:?+-][^}]*)?\}' "$RENDERED_PATH"; then
  echo "Unresolved compose variables found in rendered config" >&2
  exit 2
fi

if grep -nE '\.(tar\.gz|tgz|zip|apk|exe|msi)\}' "$RENDERED_PATH"; then
  echo "Bad trailing brace in rendered compose source path" >&2
  exit 2
fi

echo "preflight ok: rendered compose -> $RENDERED_PATH"
