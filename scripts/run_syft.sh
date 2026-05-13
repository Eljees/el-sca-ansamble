#!/usr/bin/env sh
set -eu

TARGET="${1:-${SYFT_TARGET:-alpine:latest}}"
FROM="${2:-${SYFT_FROM:-registry}}"
OUTPUT_DIR="${3:-artifacts/sbom}"

mkdir -p "$OUTPUT_DIR"

if ! command -v syft >/dev/null 2>&1; then
  echo "syft is not installed in this environment" >&2
  exit 3
fi

syft "$TARGET" --from "$FROM" -o syft-json="$OUTPUT_DIR/syft.json" -o cyclonedx-json="$OUTPUT_DIR/cyclonedx.json" -o spdx-json="$OUTPUT_DIR/spdx.json"
