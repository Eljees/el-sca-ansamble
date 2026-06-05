#!/usr/bin/env bash
# import_db_image.sh — restore vulnerability DBs from a data image on a fresh host.
#
# 1. Pulls the data image (built by export_db_image.sh).
# 2. Unpacks its /db-bundle/*.tar.gz into ./incoming.
# 3. Runs the compose `db-importer` service to load each archive into the
#    matching scanner volume (compose resolves the real volume names).
# 4. Activates the Grype snapshot so the first scan works offline.
#
# Usage:
#   ./scripts/import_db_image.sh [--image REF]
#
# Default (override with env or flag):
#   DB_IMAGE  registry.gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble/db-data:latest
#
# Requires: docker, docker compose v2.  Run from the repo root.
set -euo pipefail

# Compose interpolates the WHOLE file (including the ${SCAN_TARGET_HOST:?} guard
# on the scanner services) before selecting a profile, so provide a harmless
# value to satisfy it — the db-bundle services never read SCAN_TARGET_HOST.
export SCAN_TARGET_HOST="${SCAN_TARGET_HOST:-/tmp/el-sca-db-bundle-noscan}"

IMAGE="${DB_IMAGE:-registry.gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble/db-data:latest}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

mkdir -p incoming

echo "==> [1/4] pulling ${IMAGE}"
docker pull "$IMAGE"

echo "==> [2/4] extracting bundle into ./incoming"
docker run --rm -v "$PWD/incoming:/out" "$IMAGE" sh -c 'cp -v /db-bundle/*.tar.gz /out/'

echo "==> [3/4] restoring DB volumes via compose db-importer"
docker compose --profile db-bundle run --rm db-importer

echo "==> [4/4] activating Grype snapshot"
docker compose --profile airgap run --rm grype-db-importer || \
  echo "WARN: grype-db-importer returned non-zero (snapshot may already be active)"

echo "done. DB volumes populated — the stack can scan with bundled databases."
