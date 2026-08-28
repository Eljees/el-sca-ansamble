#!/usr/bin/env bash
# Register an artifact that is ALREADY on this server into the dashboard
# catalog WITHOUT an HTTP upload, then optionally trigger a scan.
#
# Why: multi-GB files should not go through the browser/uvicorn upload path
# (no resume, timeouts, double disk).  Deliver the file first (rsync / WinSCP /
# scp — see docs/big-artifacts.md), then run this ON the server:
#
#   scripts/register_local_artifact.sh -f /home/SCA/_incoming/CYBERSEC-13529/big.gz \
#       -c CYBERSEC-13529 -s
#
# Options:
#   -f PATH   file to register (required)
#   -c ID     CYBERSEC-XXXXX case id (optional)
#   -n NAME   display name (optional; default = file stem)
#   -s        trigger a scan via the dashboard API after registering
#   -u URL    dashboard base URL (default http://127.0.0.1:8088, or $EL_SCA_URL)
#
# The file is HARDLINKED into artifacts/uploads/<artifact-id>/ (same
# filesystem -> zero extra bytes; automatic fallback to copy across
# filesystems).  Metadata matches ArtifactCatalog.create_upload exactly, so
# the card behaves like any uploaded artifact (Scan / Reports / rename / purge).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FILE="" CASE_ID="" NAME="" DO_SCAN=0
BASE_URL="${EL_SCA_URL:-http://127.0.0.1:8088}"

while getopts "f:c:n:su:h" opt; do
  case "$opt" in
    f) FILE=$OPTARG ;;
    c) CASE_ID=$OPTARG ;;
    n) NAME=$OPTARG ;;
    s) DO_SCAN=1 ;;
    u) BASE_URL=$OPTARG ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "usage: $0 -f FILE [-c CYBERSEC-XXXXX] [-n NAME] [-s] [-u URL]" >&2; exit 2 ;;
  esac
done

[ -n "$FILE" ] || { echo "ERROR: -f FILE is required" >&2; exit 2; }
[ -f "$FILE" ] || { echo "ERROR: no such file: $FILE" >&2; exit 1; }

cd "$REPO_ROOT"
AID=$(python3 - "$FILE" "$CASE_ID" "$NAME" <<'PY'
import os, shutil, sys, uuid
from pathlib import Path

sys.path.insert(0, os.getcwd())
from datetime import datetime

try:
    from datetime import UTC
except ImportError:  # py3.10
    from datetime import timezone as _tz

    UTC = _tz.utc

from resilient_updates.artifact_catalog import (
    _now_utc,
    _safe_filename,
    _write_json,
    detect_case_id,
    normalize_case_id,
)
from resilient_updates.manifest import hash_input_archive

src = Path(sys.argv[1]).resolve()
case_id = normalize_case_id(sys.argv[2]) or detect_case_id(src.name, str(src))
name = (sys.argv[3] or src.stem).strip()

uploads = Path("artifacts/uploads").resolve()
aid = f"artifact-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
adir = uploads / aid
adir.mkdir(parents=True, exist_ok=False)
safe = _safe_filename(src.name)
dest = adir / safe
try:
    os.link(src, dest)  # same fs: zero extra bytes
    how = "hardlink"
except OSError:
    shutil.copy2(src, dest)  # cross-device fallback
    how = "copy"

hashes = hash_input_archive(dest)  # single pass sha1+sha256
payload = {
    "id": aid,
    "kind": "uploaded",
    "original_filename": src.name,
    "stored_filename": safe,
    "stored_path": str(dest.resolve()),
    "display_name": name,
    "case_id": case_id,
    "sha1": hashes.get("sha1", ""),
    "sha256": hashes.get("sha256", ""),
    "size": dest.stat().st_size,
    "uploaded_at_utc": _now_utc(),
    "deleted_at": "",
    "runs": [],
}
_write_json(adir / "artifact.json", payload)
print(
    f"registered {aid} ({how}, {payload['size']} bytes, sha256={payload['sha256'][:16]}…,"
    f" case={case_id or '-'})",
    file=sys.stderr,
)
print(aid)
PY
)

echo "artifact_id: $AID"
if [ "$DO_SCAN" = 1 ]; then
  echo "triggering scan via $BASE_URL …"
  curl -fsS --max-time 60 -X POST "$BASE_URL/api/artifacts/$AID/scan"
  echo
fi
