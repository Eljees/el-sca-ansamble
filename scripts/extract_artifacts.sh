#!/usr/bin/env sh
set -eu

INPUT="${1:-${EXTRACT_INPUT_HOST:-${SCAN_TARGET_HOST:-}}}"
OUTPUT="${2:-${EXTRACT_OUTPUT:-/workspace/artifacts/extracted/current}}"
MAX_DEPTH="${EXTRACT_MAX_DEPTH:-4}"
MAX_FILES="${EXTRACT_MAX_FILES:-20000}"
MAX_BYTES="${EXTRACT_MAX_BYTES:-10737418240}"

if [ -z "$INPUT" ]; then
  echo "EXTRACT_INPUT_HOST or first argument is required" >&2
  exit 2
fi

EXTRACT_INPUT_HOST="$INPUT" \
EXTRACT_OUTPUT="$OUTPUT" \
EXTRACT_MAX_DEPTH="$MAX_DEPTH" \
EXTRACT_MAX_FILES="$MAX_FILES" \
EXTRACT_MAX_BYTES="$MAX_BYTES" \
docker compose --profile extract run --rm artifact-extractor
