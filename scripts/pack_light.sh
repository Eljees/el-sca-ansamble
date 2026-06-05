#!/usr/bin/env bash
# pack_light.sh — build & save a LIGHT bundle (Trivy + Grype + Syft, no
# cve-bin-tool) from a Linux host.  Linux twin of scripts/windows/pack-light.ps1.
#
# Usage:  ./scripts/pack_light.sh [OUT_DIR]   (default: current directory)
# Output: OUT_DIR/el-sca-images-light.tar + artifacts/db-image/*.tar.gz
#
# Run on a machine WITH network + Docker.  Pair with deploy_light.sh on the target.
set -euo pipefail

OUT="${1:-.}"
export SCAN_TARGET_HOST="/tmp/x"     # satisfies the ${SCAN_TARGET_HOST:?} guard
PROFILES=(--profile scan --profile report --profile db-bundle)

echo "==> [1/4] building local images (no cve-bin-tool)"
docker compose --profile scan --profile report build artifact-extractor report-collector stack-info db-admin

echo "==> [2/4] pulling public images"
docker compose "${PROFILES[@]}" pull --ignore-buildable || true

echo "==> [3/4] saving stack images (excluding cve-bin-tool)"
mapfile -t imgs < <(docker compose "${PROFILES[@]}" config --images | sort -u | grep -v 'cve-bin-tool')
printf '    %s\n' "${imgs[@]}"
docker save "${imgs[@]}" -o "$OUT/el-sca-images-light.tar"

echo "==> [4/4] exporting Grype + Trivy DBs"
docker compose --profile db-bundle run --rm db-exporter
rm -f artifacts/db-image/cve-bin-tool-cache.tar.gz artifacts/db-image/internal-mirror-data.tar.gz

echo
echo "done.  Ship: $OUT/el-sca-images-light.tar + artifacts/db-image/grype-db.tar.gz, trivy-cache.tar.gz"
