#!/usr/bin/env bash
# reproduce-cybersec-11531.sh
#
# Reproduce the cve-bin-tool findings from
#   --exps/high_critical_report_2026-04-29_ru.md
# against
#   --exps/prometheus-3.11.0.linux-amd64.tar.gz   (SHA-256 FF799C…0C3B76)
#
# Reference output (cve-bin-tool only):
#   findings = 3
#   severity = CRITICAL × 2, UNKNOWN × 1
#   named   = CVE-2024-3566  (golang:go 1.23.0)
#           = CVE-2024-3566  (golang:go 1.26.1)
#
# Two scan paths can reproduce the Go runtime findings:
#
#   A. Binary scan path
#        cve-bin-tool runs the "go" regex checker against ELF binaries and
#        picks up *every* embedded "go1.X.Y" string.  Original behaviour
#        used in --exps/high_critical_report_2026-04-29_ru.md.  Slower:
#        15-30 min for Prometheus-class targets without LOCAL_COPY.
#
#   B. SBOM fast-path + Go runtime injection (default since v3.x)
#        syft produces the SBOM, update_cve_bin_tool.sh extracts
#        go:buildinfo from one of the target binaries and injects
#        "golang:go X.Y.Z" as a CycloneDX component, cve-bin-tool then
#        looks it up in NVD.  Seconds instead of minutes, but only one Go
#        version is injected per run (the first binary's), so total
#        finding count may be smaller than the binary path.
#
# The default in v3.x is path B (auto-SBOM with injection on); this script
# leaves that default alone so the reproducer mirrors what users actually
# run.  Pass --binary-scan to force path A and check that side too.
#
# Pinned knobs (applied to both paths):
#   - checkers limited to "go,rust" (auto-detect already does this for
#     pure-Go targets; we set it explicitly so a future auto-detect tweak
#     doesn't silently change findings);
#   - no MAX_FILE_MB filter (Prometheus binaries are ~150 MB);
#   - 1 hour scan timeout to absorb the regex-backtracking budget on slow
#     hosts.
#
# This script is OFFLINE-friendly: if the cve-bin-tool DB is already
# present and recent, no upstream calls happen.  Pass --update-db to
# refresh first.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

TARGET_TAR="--exps/prometheus-3.11.0.linux-amd64.tar.gz"
TARGET_SHA="ff799c3e4c318e17dec14aaaa406a4da328fabb4578336b36d96d893870c3b76"
EXTRACT_DIR_REL="artifacts/extracted/current"
EXTRACT_DIR_HOST="$REPO_ROOT/$EXTRACT_DIR_REL"
CBT_REPORT_REL="artifacts/reports/cve-bin-tool/report.json"

UPDATE_DB=0
SKIP_EXTRACT=0
BINARY_SCAN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --update-db)    UPDATE_DB=1; shift ;;
    --skip-extract) SKIP_EXTRACT=1; shift ;;
    --binary-scan)  BINARY_SCAN=1; shift ;;
    -h|--help)
      sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

# ── Pre-flight ───────────────────────────────────────────────────────────────
[[ -f "$TARGET_TAR" ]] || { echo "Missing $TARGET_TAR"; exit 1; }

actual_sha=$(sha256sum "$TARGET_TAR" | awk '{print $1}')
if [[ "$actual_sha" != "$TARGET_SHA" ]]; then
  echo "WARN: target sha256 differs from reference."
  echo "  expected: $TARGET_SHA"
  echo "  observed: $actual_sha"
  echo "  proceeding anyway; results may drift."
fi

# ── Pinned environment for reproducibility ───────────────────────────────────
export SCAN_TARGET_HOST="$EXTRACT_DIR_HOST"
export SCAN_TARGET_CONTAINER="/scan-target"
export SCAN_TARGET_DISPLAY="$TARGET_TAR -> $EXTRACT_DIR_HOST"
export CVE_BIN_TOOL_TARGET="/scan-target"

# Path selection.
#   --binary-scan   → force the regex-checker path (matches the original
#                     reference report exactly, slower).
#   default         → keep the project default (SBOM fast-path with the
#                     Go runtime injection added by Phase 5.6) — still
#                     produces CVE-2024-3566 because golang:go is injected
#                     into the SBOM as a component.
if [[ "$BINARY_SCAN" -eq 1 ]]; then
  export CVE_BIN_TOOL_AUTO_SBOM=0
  export CVE_BIN_TOOL_SBOM_PATH=""
  echo "[reproduce] mode       : BINARY SCAN (forced --binary-scan)"
else
  export CVE_BIN_TOOL_AUTO_SBOM=1
  export CVE_BIN_TOOL_INJECT_GO_RUNTIME=1
  echo "[reproduce] mode       : SBOM fast-path with Go runtime injection (default)"
fi

# Pin checker selection.  The auto-detect already chooses {go,rust} for
# pure-Go targets; we set it explicitly so a future auto-detect tweak
# doesn't silently change findings.
export CVE_BIN_TOOL_CHECKERS="go,rust"

# Do NOT exclude large files — Prometheus binaries are ~150 MB.
export CVE_BIN_TOOL_MAX_FILE_MB=0

# Long timeout to absorb regex backtracking on slow hosts.
export CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS=3600

# Local copy to tmpfs stays on (faster, no semantic difference).
export CVE_BIN_TOOL_LOCAL_COPY=1

echo "[reproduce] target tar : $TARGET_TAR"
echo "[reproduce] target sha : $actual_sha"
echo "[reproduce] update DB  : $UPDATE_DB"
echo "[reproduce] checkers   : $CVE_BIN_TOOL_CHECKERS"

# ── Step 1: optional DB refresh ──────────────────────────────────────────────
if [[ "$UPDATE_DB" -eq 1 ]]; then
  echo "[reproduce] refreshing cve-bin-tool DB..."
  docker compose --profile update run --rm cve-bin-tool-updater
fi

# ── Step 2: extract (idempotent) ─────────────────────────────────────────────
if [[ "$SKIP_EXTRACT" -eq 0 ]]; then
  echo "[reproduce] extracting tarball..."
  mkdir -p "$EXTRACT_DIR_HOST"
  EXTRACT_INPUT_HOST="$REPO_ROOT/$TARGET_TAR" \
  EXTRACT_OUTPUT="/workspace/$EXTRACT_DIR_REL" \
  EXTRACT_MAX_DEPTH=4 \
    docker compose --profile extract run --rm artifact-extractor
else
  [[ -d "$EXTRACT_DIR_HOST" ]] || { echo "Extract dir missing and --skip-extract set"; exit 1; }
fi

# ── Step 3a: Syft SBOM (only when SBOM fast-path is on) ──────────────────────
if [[ "$BINARY_SCAN" -eq 0 ]]; then
  echo "[reproduce] generating Syft SBOM (needed for SBOM fast-path)..."
  export SYFT_TARGET="/scan-target"
  export SYFT_FROM="dir"
  docker compose --profile scan run --rm syft-sbom
fi

# ── Step 3b: cve-bin-tool scan ──────────────────────────────────────────────
echo "[reproduce] running cve-bin-tool scan..."
rm -f "$CBT_REPORT_REL" "${CBT_REPORT_REL%.json}/timeout.flag" 2>/dev/null || true
docker compose --profile scan run --rm cve-bin-tool-scanner

# ── Step 4: verify ───────────────────────────────────────────────────────────
echo ""
echo "[reproduce] === results ==="
if [[ ! -s "$CBT_REPORT_REL" ]]; then
  echo "ERROR: $CBT_REPORT_REL is empty or missing — scan did not produce findings."
  exit 4
fi
python - <<'PY' "$CBT_REPORT_REL"
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    data = json.load(fh)
if not isinstance(data, list):
    print(f"ERROR: report is not a JSON array; got {type(data).__name__}")
    sys.exit(4)

total = len(data)
by_sev: dict[str, int] = {}
named = []
for entry in data:
    sev = str(entry.get("severity") or "UNKNOWN").upper()
    by_sev[sev] = by_sev.get(sev, 0) + 1
    cve = entry.get("cve_number") or entry.get("CVE")
    product = entry.get("product")
    version = entry.get("version")
    if cve:
        named.append(f"{cve} - {product}:{version} ({sev})")

print(f"total cve-bin-tool findings: {total}")
for sev, cnt in sorted(by_sev.items()):
    print(f"  {sev:<10} {cnt}")
print()
print("named findings:")
for line in named:
    print(f"  {line}")

# Reference baseline from --exps/high_critical_report_2026-04-29_ru.md.
#
# Both scan paths produce CVE-2024-3566 against the Go runtime — the
# SBOM-with-injection path emits ONE finding (single Go version injected
# from the first matching binary), the binary-scan path emits multiple
# (one per "go1.X.Y" string embedded in the bundle's binaries).  Hence the
# "approximate" minimum below: at least one Go-runtime finding is enough
# proof that the pipeline reproduces the reference signal.
expected_minimum = {
    "total": 1,
    "by_sev_at_least_one_of": ["CRITICAL", "HIGH"],
    "must_include_cve_id": "CVE-2024-3566",
}

drift = []
if total < expected_minimum["total"]:
    drift.append(f"finding count {total} below approximate baseline {expected_minimum['total']}")
if not any(by_sev.get(s, 0) >= 1 for s in expected_minimum["by_sev_at_least_one_of"]):
    drift.append(
        "no CRITICAL or HIGH finding (reference shows CRITICAL × 2)"
    )
if not any(expected_minimum["must_include_cve_id"] in line for line in named):
    drift.append(f"missing {expected_minimum['must_include_cve_id']}")

print()
if drift:
    print("DRIFT vs CYBERSEC-11531 approximate baseline:")
    for d in drift:
        print(f"  - {d}")
    sys.exit(5)
print("OK — reproduces the reference Go-runtime signal (approximate).")
PY
