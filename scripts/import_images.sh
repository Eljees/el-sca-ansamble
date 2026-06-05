#!/usr/bin/env bash
# import_images.sh — load the stack image bundle on a target host (offline).
#
# Usage:  ./scripts/import_images.sh [path/to/images.tar]
# Default: ./incoming/images.tar, then artifacts/image-bundle/images.tar
set -euo pipefail
TAR="${1:-}"
if [ -z "$TAR" ]; then
  for cand in incoming/images.tar artifacts/image-bundle/images.tar; do
    [ -f "$cand" ] && { TAR="$cand"; break; }
  done
fi
[ -n "$TAR" ] && [ -f "$TAR" ] || { echo "image bundle not found (pass path as arg)" >&2; exit 2; }

echo "==> loading images from $TAR"
docker load -i "$TAR"
echo "done. All stack images are present locally — compose runs fully offline."
echo "    Tip: enable strict offline by adding to .env:"
echo "      COMPOSE_FILE=docker-compose.yml:docker-compose.offline.yml"
