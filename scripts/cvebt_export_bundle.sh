#!/usr/bin/env bash
set -euo pipefail

bundle_root="${BUNDLE_OUTPUT_DIR:-artifacts/cve-bin-tool-bundles}"
timestamp="$(date -u +%Y%m%d-%H%M%S)"
bundle_name="cvebt-db-${timestamp}"

compose_cmd=(docker compose)
if [[ -n "${COMPOSE_FILE:-}" ]]; then
  normalized="${COMPOSE_FILE//;/:}"
  IFS=':' read -r -a files <<< "$normalized"
  for file in "${files[@]}"; do
    [[ -n "$file" ]] || continue
    compose_cmd+=(-f "$file")
  done
fi

mkdir -p "$bundle_root"

"${compose_cmd[@]}" run --rm \
  -e BUNDLE_ROOT="/workspace/${bundle_root}" \
  -e BUNDLE_NAME="$bundle_name" \
  --entrypoint sh cve-bin-tool-updater -lc '
set -euo pipefail
db_root="${CVE_BIN_TOOL_DB_ROOT:-/root/.cache/cve-bin-tool}"
bundle_dir="$BUNDLE_ROOT"
base="$BUNDLE_NAME"
archive_path="$bundle_dir/$base.tar.zst"
manifest_path="$bundle_dir/$base.manifest.json"
sha_path="$bundle_dir/$base.sha256"

[ -f "$db_root/cve.db" ] || { echo "cve.db not found under $db_root" >&2; exit 2; }
mkdir -p "$bundle_dir"

tar --zstd -C "$db_root" -cf "$archive_path" .
sha256sum "$archive_path" | awk "{print \$1}" > "$sha_path"

python - "$db_root" "$archive_path" "$manifest_path" "$sha_path" <<'"'"'PY'"'"'
from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

db_root = Path(sys.argv[1])
archive_path = Path(sys.argv[2])
manifest_path = Path(sys.argv[3])
sha_path = Path(sys.argv[4])

tool_version = ""
try:
    out = subprocess.check_output(["cve-bin-tool", "--version"], text=True).strip()
    tool_version = out.split()[-1]
except Exception:
    tool_version = "unknown"

audit_payload: dict[str, object] = {}
try:
    raw = subprocess.check_output(
        [
            "python",
            "-m",
            "resilient_updates.cli",
            "--config",
            "configs/feed_sources.yaml",
            "audit",
            "cve-bin-tool-db",
            "--db-root",
            str(db_root),
        ],
        text=True,
    )
    audit_payload = json.loads(raw)
except Exception:
    audit_payload = {}

source_status = {}
for source, payload in (audit_payload.get("source_status") or {}).items():
    if not isinstance(payload, dict):
        continue
    source_status[source] = payload.get("status") or "unknown"

manifest = {
    "tool": "cve-bin-tool",
    "tool_version": tool_version,
    "created_at": datetime.now(timezone.utc).isoformat(),
    "db_root": str(db_root),
    "sources": source_status,
    "overall_status": audit_payload.get("overall_status") or "unknown",
    "sha256": sha_path.read_text(encoding="utf-8").strip(),
    "archive": archive_path.name,
}
manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
PY
'

echo "bundle exported: ${bundle_root}/${bundle_name}.tar.zst"
echo "manifest: ${bundle_root}/${bundle_name}.manifest.json"
echo "sha256: ${bundle_root}/${bundle_name}.sha256"
