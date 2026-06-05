#!/usr/bin/env bash
# deploy_light.sh — deploy a LIGHT bundle on a Linux target (Ubuntu): load
# images, restore Grype/Trivy DBs, set strict offline + skip cve-bin-tool.
#
# Usage:  ./scripts/deploy_light.sh [BUNDLE_DIR]
#   BUNDLE_DIR holds el-sca-images-light.tar and the db-image *.tar.gz files
#   (default: current directory).
#
# Requires Docker + docker compose v2.  Needs NO network.  Run from the repo root.
set -euo pipefail

BUNDLE_DIR="${1:-.}"

echo "==> [1/4] configuring .env (strict offline + skip cve-bin-tool)"
[ -f .env ] || cp .env.example .env
grep -qE '^[[:space:]]*COMPOSE_FILE=' .env || \
  echo 'COMPOSE_FILE=docker-compose.yml:docker-compose.offline.yml' >> .env
grep -qE '^[[:space:]]*EL_SCA_SKIP_CVEBT=' .env || \
  echo 'EL_SCA_SKIP_CVEBT=1' >> .env

echo "==> [2/4] loading images from $BUNDLE_DIR/el-sca-images-light.tar"
docker load -i "$BUNDLE_DIR/el-sca-images-light.tar"

echo "==> [3/4] restoring Grype + Trivy DB volumes"
mkdir -p incoming
cp "$BUNDLE_DIR"/*.tar.gz incoming/ 2>/dev/null || true
export SCAN_TARGET_HOST="/tmp/x"          # satisfies the ${SCAN_TARGET_HOST:?} guard
docker compose --profile db-bundle run --rm db-importer

echo "==> [4/4] activating Grype snapshot"
docker compose --profile airgap run --rm grype-db-importer

echo
echo "done — fully offline, no downloads on scan."
echo "Install GUI deps once:  python3 -m pip install fastapi 'uvicorn[standard]' python-multipart"
echo "Start the GUI:          python3 -m resilient_updates.cli dashboard --repo-root . --port 8088"
