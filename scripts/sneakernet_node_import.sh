exec > /tmp/import.log 2>&1
set -x
cd /home/SCA/el-sca-ansamble || exit 9
git pull origin master 2>&1 | tail -3
ls -la /tmp/cvebt_db.tgz || exit 10
touch /tmp/epss_scores-current.csv   # ensure mountable even if not shipped
# Mount the freshly pulled resilient_updates OVER the image copy so the audit
# uses the current code (PURL2CPE-by-file fix) without rebuilding the image.
sudo docker compose --profile update run --rm -u 0 \
  -v /tmp/cvebt_db.tgz:/incoming.tgz:ro \
  -v /tmp/epss_scores-current.csv:/incoming_epss.csv:ro \
  -v /home/SCA/el-sca-ansamble/resilient_updates:/opt/app/resilient_updates:ro \
  --entrypoint sh cve-bin-tool-updater -c '
    set -ex
    CAND=/var/lib/resilient-db/cve-bin-tool/candidates/windows-sneakernet/.cache/cve-bin-tool
    rm -rf /var/lib/resilient-db/cve-bin-tool/candidates/windows-sneakernet
    mkdir -p "$CAND" /var/lib/resilient-db/cve-bin-tool/previous /var/lib/resilient-db/cve-bin-tool/tmp
    tar xzf /incoming.tgz -C "$CAND"
    if [ -s /incoming_epss.csv ]; then
      mkdir -p "$CAND/epss"
      cp /incoming_epss.csv "$CAND/epss/epss_scores-current.csv"
      echo "EPSS csv placed from host"
    fi
    chown -R appuser:appuser /var/lib/resilient-db/cve-bin-tool/candidates/windows-sneakernet || true
    ls -la "$CAND"
    python -m resilient_updates.cli --config configs/feed_sources.yaml audit cve-bin-tool-db --db-root "$CAND"
    python -m resilient_updates.cli --config configs/feed_sources.yaml activate cve-bin-tool-db \
      --candidate-root "$CAND" \
      --active-root /home/appuser/.cache/cve-bin-tool \
      --previous-root /var/lib/resilient-db/cve-bin-tool/previous \
      --temp-root /var/lib/resilient-db/cve-bin-tool/tmp \
      --provenance-path artifacts/provenance/cve-bin-tool-db.json
  '
rc=$?
echo "ACTIVATE_RC=$rc"
# Snapshot the activated DB to the stack-local S3 (SeaweedFS) so it survives
# volume loss: scripts/s3_storage.sh db-push packs the active roots and uploads.
if [ "$rc" -eq 0 ]; then
  sudo bash scripts/s3_storage.sh init 2>&1 | tail -2
  sudo bash scripts/s3_storage.sh db-push 2>&1 | tail -5
  echo "S3_PUSH_RC=$?"
fi
exit $rc
