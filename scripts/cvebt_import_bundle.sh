#!/usr/bin/env bash
set -euo pipefail

bundle_path="${1:-${CVE_BIN_TOOL_BUNDLE_ARCHIVE:-}}"
if [[ -z "$bundle_path" ]]; then
  echo "usage: $0 <path-to-cvebt-db-*.tar.zst>" >&2
  exit 2
fi
if [[ ! -f "$bundle_path" ]]; then
  echo "bundle archive not found: $bundle_path" >&2
  exit 2
fi

manifest_path="${CVE_BIN_TOOL_BUNDLE_MANIFEST:-${bundle_path%.tar.zst}.manifest.json}"
sha_path="${CVE_BIN_TOOL_BUNDLE_SHA256:-${bundle_path%.tar.zst}.sha256}"
if [[ ! -f "$manifest_path" ]]; then
  echo "bundle manifest not found: $manifest_path" >&2
  exit 2
fi
if [[ ! -f "$sha_path" ]]; then
  echo "bundle sha file not found: $sha_path" >&2
  exit 2
fi

compose_cmd=(docker compose)
if [[ -n "${COMPOSE_FILE:-}" ]]; then
  normalized="${COMPOSE_FILE//;/:}"
  IFS=':' read -r -a files <<< "$normalized"
  for file in "${files[@]}"; do
    [[ -n "$file" ]] || continue
    compose_cmd+=(-f "$file")
  done
fi

bundle_rel="$bundle_path"
manifest_rel="$manifest_path"
sha_rel="$sha_path"
case "$bundle_rel" in
  /workspace/*) ;;
  *) bundle_rel="/workspace/${bundle_rel#./}" ;;
esac
case "$manifest_rel" in
  /workspace/*) ;;
  *) manifest_rel="/workspace/${manifest_rel#./}" ;;
esac
case "$sha_rel" in
  /workspace/*) ;;
  *) sha_rel="/workspace/${sha_rel#./}" ;;
esac

"${compose_cmd[@]}" run --rm \
  -e IMPORT_BUNDLE_PATH="$bundle_rel" \
  -e IMPORT_MANIFEST_PATH="$manifest_rel" \
  -e IMPORT_SHA_PATH="$sha_rel" \
  --entrypoint sh cve-bin-tool-updater -lc '
set -euo pipefail
candidate_home="/var/lib/resilient-db/cve-bin-tool/candidates/bundle-import-manual"
candidate_root="$candidate_home/.cache/cve-bin-tool"
db_root="${CVE_BIN_TOOL_DB_ROOT:-/home/appuser/.cache/cve-bin-tool}"
config_path="${CONFIG_PATH:-configs/feed_sources.yaml}"

rm -rf "$candidate_home"
mkdir -p "$candidate_root"

expected="$(tr -d " \t\r\n" < "$IMPORT_SHA_PATH")"
actual="$(sha256sum "$IMPORT_BUNDLE_PATH" | awk "{print \$1}")"
if [ "$expected" != "$actual" ]; then
  echo "bundle sha mismatch: expected=$expected actual=$actual" >&2
  exit 3
fi

tar --zstd -C "$candidate_root" -xf "$IMPORT_BUNDLE_PATH"
test -f "$candidate_root/cve.db" || { echo "cve.db missing after import" >&2; exit 4; }

python -m resilient_updates.cli --config "$config_path" activate cve-bin-tool-db \
  --candidate-root "$candidate_root" \
  --active-root "$db_root" \
  --previous-root "/var/lib/resilient-db/cve-bin-tool/previous" \
  --temp-root "/var/lib/resilient-db/cve-bin-tool/tmp" \
  --provenance-path "artifacts/provenance/cve-bin-tool-db.json"
'

echo "bundle imported and activated: $bundle_path"
