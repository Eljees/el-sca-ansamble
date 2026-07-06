#!/usr/bin/env bash
# s3_storage.sh — publish/pull DB snapshots and scan results through the
# stack-local S3-compatible storage (SeaweedFS MVP).
#
# Usage:
#   ./scripts/s3_storage.sh init
#   ./scripts/s3_storage.sh db-push
#   ./scripts/s3_storage.sh db-pull [latest|previous]
#   ./scripts/s3_storage.sh cve-source-push <nvd|osv|gad|redhat|epss|purl2cpe|rsd> <path>
#   ./scripts/s3_storage.sh results-push [_SCA_reports/<run-id>|artifacts/runs/<run-id>]
#   ./scripts/s3_storage.sh ls [prefix]
set -euo pipefail

cd "$(dirname "$0")/.."

export SCAN_TARGET_HOST="${SCAN_TARGET_HOST:-/tmp/el-sca-s3-noscan}"
export EXTRACT_INPUT_HOST="${EXTRACT_INPUT_HOST:-/tmp/el-sca-s3-noextract}"
# Git Bash / Docker Desktop can derive a hash-like compose project name from
# translated Windows paths. Pin the repo's normal project name unless the
# operator deliberately overrides it, so repeated storage commands reuse the
# same SeaweedFS container and the same DB volumes.
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-el-sca-ansamble}"

S3_ALIAS="${EL_SCA_S3_ALIAS:-elsca}"
S3_BUCKET="${EL_SCA_S3_BUCKET:-el-sca}"
STAGING_ROOT="artifacts/s3-staging"

compose_cmd=(docker compose)
if [[ -n "${COMPOSE_FILE:-}" ]]; then
  normalized="${COMPOSE_FILE//;/:}"
  IFS=':' read -r -a files <<< "$normalized"
  compose_cmd=(docker compose)
  for file in "${files[@]}"; do
    [[ -n "$file" ]] || continue
    compose_cmd+=(-f "$file")
  done
fi

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
}

storage_up() {
  local cid
  cid="$("${compose_cmd[@]}" --profile storage ps -q seaweedfs 2>/dev/null || true)"
  if [[ -n "$cid" ]]; then
    local running
    running="$(docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null || true)"
    if [[ "$running" == "true" ]]; then
      return 0
    fi
  fi
  "${compose_cmd[@]}" --profile storage up -d seaweedfs
}

mc_exec() {
  local script="$1"
  storage_up
  "${compose_cmd[@]}" --profile storage --profile storage-tools run --rm --no-deps s3-client "
set -eu
ready=0
for i in \$(seq 1 30); do
  mc alias set \"\$EL_SCA_S3_ALIAS\" \"\$EL_SCA_S3_ENDPOINT\" \"\$EL_SCA_S3_ACCESS_KEY\" \"\$EL_SCA_S3_SECRET_KEY\" --api S3v4 >/dev/null
  if mc ls \"\$EL_SCA_S3_ALIAS\" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ \"\$ready\" != \"1\" ]; then
  echo \"S3 endpoint is not ready: \$EL_SCA_S3_ENDPOINT\" >&2
  exit 3
fi
mc mb -p \"\$EL_SCA_S3_ALIAS/\$EL_SCA_S3_BUCKET\" >/dev/null 2>&1 || true
$script
"
}

rotate_prefix() {
  local prefix="$1"
  mc_exec "
mc rm --recursive --force \"\$EL_SCA_S3_ALIAS/\$EL_SCA_S3_BUCKET/$prefix/previous\" >/dev/null 2>&1 || true
mc cp --recursive \"\$EL_SCA_S3_ALIAS/\$EL_SCA_S3_BUCKET/$prefix/latest/\" \"\$EL_SCA_S3_ALIAS/\$EL_SCA_S3_BUCKET/$prefix/previous/\" >/dev/null 2>&1 || true
"
}

init_storage() {
  mc_exec "
mc ls \"\$EL_SCA_S3_ALIAS/\$EL_SCA_S3_BUCKET\" >/dev/null
printf 'S3 storage ready: %s/%s\n' \"\$EL_SCA_S3_ALIAS\" \"\$EL_SCA_S3_BUCKET\"
"
}

write_db_manifest() {
  local dir="$1"
  local manifest="$dir/manifest.json"
  python - "$dir" "$manifest" <<'PY'
from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

root = Path(sys.argv[1])
manifest = Path(sys.argv[2])
files = []
for item in sorted(root.glob("*.tar.gz")):
    digest = hashlib.sha256()
    with item.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    files.append(
        {
            "name": item.name,
            "size": item.stat().st_size,
            "sha256": digest.hexdigest(),
        }
    )
payload = {
    "schema": "el-sca.s3-db-bundle.v1",
    "created_at": datetime.now(UTC).isoformat(),
    "retention": "latest+previous",
    "files": files,
}
manifest.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
PY
}

stage_db_component() {
  local component="$1"
  shift
  local out="$STAGING_ROOT/db/$component"
  rm -rf "$out"
  mkdir -p "$out"
  for archive in "$@"; do
    cp "artifacts/db-image/$archive" "$out/"
  done
  write_db_manifest "$out"
}

db_push() {
  echo "==> exporting current DB volumes"
  "${compose_cmd[@]}" --profile db-bundle run --rm db-exporter

  rm -rf "$STAGING_ROOT/db"
  mkdir -p "$STAGING_ROOT/db"
  stage_db_component trivy trivy-cache.tar.gz
  stage_db_component grype grype-db.tar.gz grype-cache.tar.gz
  stage_db_component cve-bin-tool cve-bin-tool-cache.tar.gz internal-mirror-data.tar.gz
  stage_db_component all trivy-cache.tar.gz grype-db.tar.gz grype-cache.tar.gz cve-bin-tool-cache.tar.gz internal-mirror-data.tar.gz

  for component in trivy grype cve-bin-tool all; do
    echo "==> publishing db/$component/latest (previous kept when present)"
    rotate_prefix "db/$component"
    mc_exec "
mc mirror --overwrite --remove \"/workspace/$STAGING_ROOT/db/$component\" \"\$EL_SCA_S3_ALIAS/\$EL_SCA_S3_BUCKET/db/$component/latest\"
"
  done
}

db_pull() {
  local slot="${1:-latest}"
  case "$slot" in
    latest|previous) ;;
    *) echo "slot must be latest or previous" >&2; exit 2 ;;
  esac

  mkdir -p incoming
  rm -f incoming/trivy-cache.tar.gz incoming/grype-db.tar.gz incoming/grype-cache.tar.gz \
        incoming/cve-bin-tool-cache.tar.gz incoming/internal-mirror-data.tar.gz incoming/manifest.json

  echo "==> pulling db/all/$slot into ./incoming"
  mc_exec "
mc mirror --overwrite \"\$EL_SCA_S3_ALIAS/\$EL_SCA_S3_BUCKET/db/all/$slot\" /workspace/incoming
"

  echo "==> restoring DB volumes"
  "${compose_cmd[@]}" --profile db-bundle run --rm db-importer
  echo "==> activating Grype snapshot"
  "${compose_cmd[@]}" --profile airgap run --rm grype-db-importer || \
    echo "WARN: grype-db-importer returned non-zero (snapshot may already be active)"
}

cve_source_push() {
  local source="${1:-}"
  local input="${2:-}"
  case "$source" in
    nvd|osv|gad|redhat|epss|purl2cpe|rsd) ;;
    *) echo "source must be one of: nvd osv gad redhat epss purl2cpe rsd" >&2; exit 2 ;;
  esac
  [[ -n "$input" && -e "$input" ]] || { echo "path not found: $input" >&2; exit 2; }

  local stage="$STAGING_ROOT/cve-bin-tool/$source"
  rm -rf "$stage"
  mkdir -p "$stage"
  if [[ -d "$input" ]]; then
    cp -a "$input/." "$stage/"
  else
    cp "$input" "$stage/"
  fi

  rotate_prefix "db/cve-bin-tool/sources/$source"
  mc_exec "
mc mirror --overwrite --remove \"/workspace/$stage\" \"\$EL_SCA_S3_ALIAS/\$EL_SCA_S3_BUCKET/db/cve-bin-tool/sources/$source/latest\"
"
}

newest_run_dir() {
  {
    for root in _SCA_reports artifacts/runs; do
      [[ -d "$root" ]] || continue
      find "$root" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null || true
    done
  } | sort -nr | awk 'NR==1 {print $2}'
}

results_push() {
  local run_dir="${1:-}"
  if [[ -z "$run_dir" ]]; then
    run_dir="$(newest_run_dir || true)"
  fi
  [[ -n "$run_dir" && -d "$run_dir" ]] || {
    echo "No run directory found. Pass _SCA_reports/<run-id> or artifacts/runs/<run-id> explicitly." >&2
    exit 2
  }

  local run_id
  run_id="$(basename "$run_dir")"

  echo "==> publishing scan run: $run_id"
  rotate_prefix "scans"
  mc_exec "
mc mirror --overwrite --remove \"/workspace/$run_dir\" \"\$EL_SCA_S3_ALIAS/\$EL_SCA_S3_BUCKET/scans/$run_id\"
mc mirror --overwrite --remove \"/workspace/$run_dir\" \"\$EL_SCA_S3_ALIAS/\$EL_SCA_S3_BUCKET/scans/latest\"
"
  echo "scan results published under s3://$S3_BUCKET/scans/$run_id and scans/latest"
}

list_prefix() {
  local prefix="${1:-}"
  mc_exec "
mc ls --recursive \"\$EL_SCA_S3_ALIAS/\$EL_SCA_S3_BUCKET/$prefix\"
"
}

cmd="${1:-}"
case "$cmd" in
  init) shift; init_storage "$@" ;;
  db-push) shift; db_push "$@" ;;
  db-pull) shift; db_pull "$@" ;;
  cve-source-push) shift; cve_source_push "$@" ;;
  results-push) shift; results_push "$@" ;;
  ls) shift; list_prefix "$@" ;;
  -h|--help|help|"") usage ;;
  *) echo "unknown command: $cmd" >&2; usage >&2; exit 2 ;;
esac
