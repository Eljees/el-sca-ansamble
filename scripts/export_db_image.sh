#!/usr/bin/env bash
# export_db_image.sh — snapshot the CURRENT vulnerability DBs into a data image.
#
# 1. Runs the compose `db-exporter` service: tars every scanner DB volume into
#    ./artifacts/db-image/<volume>.tar.gz (compose resolves the real volume
#    names, so no project-prefix guessing).
# 2. Builds Dockerfile.db-data from that folder, tagging :<DB_TAG> and :latest.
# 3. With --push, pushes both tags to the registry.
#
# Usage:
#   ./scripts/export_db_image.sh [--image REF] [--tag TAG] [--push]
#
# Defaults (override with env or flags):
#   DB_IMAGE  registry.gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble/db-data
#   DB_TAG    UTC date (YYYYMMDD)
#
# Requires: docker, docker compose v2.  Run from the repo root.
set -euo pipefail

# Compose interpolates the WHOLE file (including the ${SCAN_TARGET_HOST:?} guard
# on the scanner services) before selecting a profile, so provide a harmless
# value to satisfy it — the db-bundle services never read SCAN_TARGET_HOST.
export SCAN_TARGET_HOST="${SCAN_TARGET_HOST:-/tmp/el-sca-db-bundle-noscan}"

IMAGE="${DB_IMAGE:-registry.gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble/db-data}"
TAG="${DB_TAG:-$(date -u +%Y%m%d)}"
PUSH=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --tag)   TAG="$2";   shift 2 ;;
    --push)  PUSH=1;     shift ;;
    -h|--help)
      sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

echo "==> [1/3] exporting DB volumes via compose db-exporter"
docker compose --profile db-bundle run --rm db-exporter

echo "==> [2/3] building data image ${IMAGE}:${TAG} (+ :latest)"
docker build -f Dockerfile.db-data \
  -t "${IMAGE}:${TAG}" -t "${IMAGE}:latest" \
  artifacts/db-image

if [ "$PUSH" -eq 1 ]; then
  echo "==> [3/3] pushing ${IMAGE}:${TAG} and :latest"
  docker push "${IMAGE}:${TAG}"
  docker push "${IMAGE}:latest"
else
  echo "==> [3/3] skipped push (add --push to upload)"
fi

echo "done: ${IMAGE}:${TAG}"
