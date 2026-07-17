exec > /tmp/import.log 2>&1
set -x
cd /home/SCA/el-sca-ansamble || exit 9
git pull origin master 2>&1 | tail -3
ls -la /tmp/cvebt_db.tgz || exit 10
sudo docker compose --profile update run --rm -u 0 \
  -v /tmp/cvebt_db.tgz:/incoming.tgz:ro \
  --entrypoint sh cve-bin-tool-updater -c '
    set -ex
    CAND=/var/lib/resilient-db/cve-bin-tool/candidates/windows-sneakernet/.cache/cve-bin-tool
    rm -rf /var/lib/resilient-db/cve-bin-tool/candidates/windows-sneakernet
    mkdir -p "$CAND" /var/lib/resilient-db/cve-bin-tool/previous /var/lib/resilient-db/cve-bin-tool/tmp
    tar xzf /incoming.tgz -C "$CAND"
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
exit $rc
