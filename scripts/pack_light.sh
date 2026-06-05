#!/usr/bin/env bash
# pack_light.sh — build the LIGHT bundle straight into bundle/ (Linux twin of
# scripts/windows/pack-light.ps1), so it ships INSIDE the repo via Git LFS.
#
# Writes bundle/el-sca-images-light.tar + bundle/grype-db.tar.gz +
# bundle/trivy-cache.tar.gz.  Then:
#   git lfs install
#   git add -A && git commit -m "ship bundle" && git push <remote> master
# A clone brings everything; deploy with scripts/deploy_light.sh.
# Run on a machine WITH network + Docker.
set -euo pipefail

OUT="${1:-bundle}"
mkdir -p "$OUT"
export SCAN_TARGET_HOST="/tmp/x"     # satisfies the ${SCAN_TARGET_HOST:?} guard
export COMPOSE_PROJECT_NAME="el-sca-ansamble"   # stable image prefix for the bundle
PROFILES=(--profile scan --profile report --profile db-bundle)

echo "==> [1/5] building local images (no cve-bin-tool)"
docker compose --profile scan --profile report build artifact-extractor report-collector stack-info db-admin

echo "==> [2/5] pulling public images"
docker compose "${PROFILES[@]}" pull --ignore-buildable || true

echo "==> [3/5] saving stack images (excluding cve-bin-tool) -> $OUT"
mapfile -t imgs < <(docker compose "${PROFILES[@]}" config --images | sort -u | grep -v 'cve-bin-tool')
printf '    %s\n' "${imgs[@]}"
docker save "${imgs[@]}" -o "$OUT/el-sca-images-light.tar"

echo "==> [4/5] exporting Grype + Trivy DBs"
docker compose --profile db-bundle run --rm db-exporter

echo "==> [5/5] collecting DBs into $OUT"
cp artifacts/db-image/grype-db.tar.gz artifacts/db-image/trivy-cache.tar.gz "$OUT"/

echo
echo "done.  bundle ready in $OUT/  (images + Grype/Trivy DBs)"
echo "Next:  git lfs install; git add -A; git commit -m 'ship bundle'; git push <remote> master"
