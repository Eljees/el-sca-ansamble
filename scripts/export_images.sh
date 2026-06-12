#!/usr/bin/env bash
# export_images.sh — build/pull ALL stack images once and save them to a tar,
# so a target host can run the complex with ZERO downloads (docker load).
#
# Usage:  ./scripts/export_images.sh [--push REGISTRY_PREFIX]
# Output: artifacts/image-bundle/images.tar  (+ images.txt list)
#
# Run on a machine WITH network.  Requires docker + docker compose v2.
set -euo pipefail
# Compose evaluates ${SCAN_TARGET_HOST:?} across the whole file before profiles.
export SCAN_TARGET_HOST="${SCAN_TARGET_HOST:-/tmp/el-sca-noscan}"

PROFILES=(--profile scan --profile update --profile report --profile db-bundle)
OUT="${IMAGE_BUNDLE_DIR:-artifacts/image-bundle}"
mkdir -p "$OUT"

echo "==> [1/4] building local images (needs pypi + base images)"
docker compose "${PROFILES[@]}" build

echo "==> [2/4] pulling public/base images"
docker compose "${PROFILES[@]}" pull --ignore-buildable 2>/dev/null || \
  docker compose "${PROFILES[@]}" pull || true

echo "==> [3/4] collecting image list"
mapfile -t IMGS < <(docker compose "${PROFILES[@]}" config --images | sort -u)
printf '%s\n' "${IMGS[@]}" | tee "$OUT/images.txt"

echo "==> [4/4] saving ${#IMGS[@]} images to $OUT/images.tar"
docker save "${IMGS[@]}" -o "$OUT/images.tar"
ls -lh "$OUT/images.tar"
echo "done. Ship '$OUT/images.tar' to the target and run scripts/import_images.sh."
