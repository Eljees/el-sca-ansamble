#!/usr/bin/env bash
# run-scan.sh — Linux/macOS entry point for el-sca-ansamble (FULL pipeline).
# Mirrors scripts/windows/run-scan.ps1 in behaviour and flags.
#
# Sibling-name disambiguation (see scripts/README.md):
#   run-scan.sh    dash       = full pipeline via docker compose + reports  (this file)
#   run_scan.sh    underscore = native per-tool wrapper, no docker
#
# Usage:
#   ./scripts/run-scan.sh -t /path/to/target [options]
#
# Options:
#   -t, --target PATH       Path to file or directory to scan (required)
#   -p, --profile NAME      Docker Compose profile (default: scan)
#       --tool TOOL         Run only one tool: all|syft|grype|trivy|cve-bin-tool (default: all)
#       --format FORMAT     Target format: auto|apk|win (default: auto)
#   -u, --update-db         Pull fresh CVE databases before scanning
#   -e, --extract           Unpack archive before scanning (auto-detected for archives)
#       --extract-max-depth N  Max recursion depth for extraction (default: 4)
#   -c, --clean             Remove previous artifacts before this run
#       --sbom-scan         Feed Syft SBOM to cve-bin-tool instead of binary scan (experimental)
#       --timeout N         cve-bin-tool scan timeout in seconds (default: 1800)
#
# Requires: docker, docker compose, bash >= 4
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
TARGET=""
PROFILE="scan"
TOOL="all"
FORMAT="auto"
UPDATE_DB=0
EXTRACT=0
EXTRACT_MAX_DEPTH=4
CLEAN=0
SBOM_SCAN=0
CBT_TIMEOUT=1800
CBT_CHECKERS=""

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target)           TARGET="$2"; shift 2 ;;
    -p|--profile)          PROFILE="$2"; shift 2 ;;
    --tool)                TOOL="$2"; shift 2 ;;
    --format)              FORMAT="$2"; shift 2 ;;
    -u|--update-db)        UPDATE_DB=1; shift ;;
    -e|--extract)          EXTRACT=1; shift ;;
    --extract-max-depth)   EXTRACT_MAX_DEPTH="$2"; shift 2 ;;
    -c|--clean)            CLEAN=1; shift ;;
    --sbom-scan)           SBOM_SCAN=1; shift ;;
    --timeout)             CBT_TIMEOUT="$2"; shift 2 ;;
    --checkers)            CBT_CHECKERS="$2"; shift 2 ;;
    -h|--help)
      sed -n '/^# Usage:/,/^[^#]/p' "$0" | grep "^#" | sed 's/^# \?//'
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "ERROR: -t/--target is required" >&2
  exit 2
fi
if [[ ! -e "$TARGET" ]]; then
  echo "ERROR: Target does not exist: $TARGET" >&2
  exit 2
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
die() { echo "ERROR: $*" >&2; exit 1; }

compose_checked() {
  docker compose "$@"
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    die "docker compose failed (exit $rc): $*"
  fi
}

db_status() {
  local tool="$1" path="$2"
  docker compose run --rm db-admin db-status "$tool" --path "$path" --warning-age 24h || true
}

import_local_env() {
  local envfile=".env.local"
  [[ -f "$envfile" ]] || return 0
  while IFS= read -r line; do
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
    export "${line?}"
  done < "$envfile"
}

# ── Pre-flight ────────────────────────────────────────────────────────────────
docker --version > /dev/null
docker compose version > /dev/null
import_local_env

TARGET_RESOLVED="$(realpath "$TARGET")"
TARGET_DIR="$(dirname "$TARGET_RESOLVED")"
RAW_NAME="$(basename "$TARGET_RESOLVED")"

# Strip known archive extensions (compound first)
BASE_NAME="$RAW_NAME"
for ext in .tar.gz .tar.bz2 .tar.xz .tar.zst .tar .tgz .zip .gz .bz2 .xz .zst .jar .war .ear .apk .ipa; do
  case "${BASE_NAME,,}" in
    *"$ext") BASE_NAME="${BASE_NAME%"${BASE_NAME: -${#ext}}"}"; break ;;
  esac
done

DATE="$(date +%Y-%m-%d)"
REPORT_MD="${TARGET_DIR}/${BASE_NAME}_report_${DATE}.md"
REPORT_HTML="${TARGET_DIR}/${BASE_NAME}_report_${DATE}.html"
ARTIFACTS_DIR="$(pwd)/artifacts"

echo ""
printf '\e[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n'
printf '\e[36m SCA Pipeline\e[0m\n'
printf '\e[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n'
printf ' Target  : %s\n' "$TARGET_RESOLVED"
printf ' MD out  : %s\n' "$REPORT_MD"
printf ' HTML out: %s\n' "$REPORT_HTML"
printf '\e[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n'
echo ""

# ── Clean ────────────────────────────────────────────────────────────────────
if [[ $CLEAN -eq 1 ]]; then
  echo "[clean] Removing previous artifacts..."
  find "$ARTIFACTS_DIR" -type f ! -name ".gitkeep" -delete
  # Remove empty subdirectories (deepest first)
  find "$ARTIFACTS_DIR" -mindepth 1 -type d -empty -delete 2>/dev/null || true
  # Remove orphan cve-bin-tool output files in workspace root
  find "$(pwd)" -maxdepth 1 -name "output.cve-bin-tool.*.json" -delete 2>/dev/null || true
  echo "[clean] Done."
  echo ""
fi

# Always remove stale SBOM files so Syft writes fresh ones
for f in syft.json cyclonedx.json spdx.json; do
  rm -f "$ARTIFACTS_DIR/sbom/$f"
done

# ── Render Trivy flags (standard pipeline only) ───────────────────────────────
TRIVY_FLAGS=""
if [[ "$FORMAT" == "auto" ]]; then
  TRIVY_FLAGS="$(python -m resilient_updates.cli render-flags trivy 2>/dev/null || true)"
fi

# ── Environment for containers ────────────────────────────────────────────────
export SCAN_TARGET_HOST="$TARGET_RESOLVED"
export SCAN_TARGET_CONTAINER="/scan-target"
export SCAN_TARGET_DISPLAY="$TARGET_RESOLVED"
export SYFT_TARGET="/scan-target"
export SYFT_FROM="dir"
export TRIVY_TARGET="/scan-target"
export CVE_BIN_TOOL_TARGET="/scan-target"
export CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS="$CBT_TIMEOUT"
export CVE_BIN_TOOL_CHECKERS="$CBT_CHECKERS"
export REPORT_OUTPUT="/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md"

if [[ $SBOM_SCAN -eq 1 ]]; then
  export CVE_BIN_TOOL_SBOM_PATH="/workspace/artifacts/sbom/syft.json"
  export CVE_BIN_TOOL_SBOM_FORMAT="syft"
  echo " SbomScan: ENABLED (cve-bin-tool will read syft.json)"
else
  export CVE_BIN_TOOL_SBOM_PATH=""
  export CVE_BIN_TOOL_SBOM_FORMAT=""
fi

# ── Auto-detect format ────────────────────────────────────────────────────────
if [[ "$FORMAT" == "auto" ]]; then
  ext="${TARGET_RESOLVED##*.}"
  ext="${ext,,}"
  case "$ext" in
    apk) FORMAT="apk" ;;
    msi|exe) FORMAT="win" ;;
    zip)
      # Peek inside ZIP for .apk or .exe/.msi
      if command -v unzip &>/dev/null; then
        inner=$(unzip -l "$TARGET_RESOLVED" 2>/dev/null | awk '{print $NF}' || true)
        if echo "$inner" | grep -qi '\.apk$'; then FORMAT="apk"
        elif echo "$inner" | grep -qiE '\.(msi|exe)$'; then FORMAT="win"
        fi
      fi ;;
  esac
  [[ "$FORMAT" != "auto" ]] && echo " Format  : $FORMAT (auto-detected)"
fi

# ── Auto-enable extract for archives (except APK which handles its own) ───────
if [[ "$FORMAT" != "apk" && $EXTRACT -eq 0 ]]; then
  case "${TARGET_RESOLVED,,}" in
    *.tar|*.tar.gz|*.tgz|*.tar.bz2|*.tar.xz|*.tar.zst|*.zip|*.rpm|*.deb)
      EXTRACT=1
      echo " Extract : enabled automatically for archive target"
      ;;
  esac
fi

# ── Extract ───────────────────────────────────────────────────────────────────
if [[ $EXTRACT -eq 1 ]]; then
  EXTRACT_REL="artifacts/extracted/current"
  EXTRACT_HOST="$(pwd)/$EXTRACT_REL"
  mkdir -p "$EXTRACT_HOST"
  export EXTRACT_INPUT_HOST="$SCAN_TARGET_HOST"
  export EXTRACT_OUTPUT="/workspace/$EXTRACT_REL"
  export EXTRACT_MAX_DEPTH="$EXTRACT_MAX_DEPTH"
  compose_checked --profile extract run --rm artifact-extractor
  export SCAN_TARGET_HOST="$(realpath "$EXTRACT_HOST")"
  export SCAN_TARGET_DISPLAY="$TARGET_RESOLVED -> $SCAN_TARGET_HOST"
  export SYFT_TARGET="/scan-target"
  export SYFT_FROM="dir"
fi

# ── Specialized format pipelines ─────────────────────────────────────────────
if [[ "$FORMAT" == "apk" ]]; then
  echo "[apk] Running APK analyzer..."
  compose_checked --profile apk run --rm apk-analyzer

  echo "[apk] Running grype on generated SBOM..."
  export SYFT_TARGET="/workspace/artifacts/sbom/syft.json"
  export SYFT_FROM="sbom"
  [[ $UPDATE_DB -eq 1 ]] && compose_checked --profile update run --rm grype-updater && compose_checked --profile update run --rm grype-db-importer
  db_status grype /var/lib/resilient-db/grype/active
  compose_checked --profile "$PROFILE" run --rm grype-scanner

  NATIVE_DIR="$ARTIFACTS_DIR/extracted/apk-native"
  if [[ -d "$NATIVE_DIR" ]] && [[ -n "$(find "$NATIVE_DIR" -name '*.so' 2>/dev/null)" ]]; then
    echo "[apk] Running cve-bin-tool on native .so files..."
    export CVE_BIN_TOOL_TARGET="/workspace/artifacts/extracted/apk-native"
    export SCAN_TARGET_HOST="$(realpath "$NATIVE_DIR")"
    db_status cve-bin-tool /root/.cache/cve-bin-tool
    compose_checked --profile "$PROFILE" run --rm cve-bin-tool-scanner
  fi

elif [[ "$FORMAT" == "win" ]]; then
  echo "[win] Running Windows installer analyzer..."
  compose_checked --profile win run --rm win-analyzer

  echo "[win] Running grype on generated SBOM..."
  export SYFT_TARGET="/workspace/artifacts/sbom/syft.json"
  export SYFT_FROM="sbom"
  if [[ $UPDATE_DB -eq 1 ]]; then
    compose_checked --profile update run --rm grype-updater
    compose_checked --profile update run --rm grype-db-importer
    compose_checked --profile update run --rm cve-bin-tool-updater
  fi
  db_status grype /var/lib/resilient-db/grype/active
  db_status cve-bin-tool /root/.cache/cve-bin-tool
  compose_checked --profile "$PROFILE" run --rm grype-scanner

  WIN_EXTRACT_DIR="$ARTIFACTS_DIR/extracted/win-installer"
  if [[ -d "$WIN_EXTRACT_DIR" ]]; then
    echo "[win] Running cve-bin-tool on extracted installer contents..."
    export CVE_BIN_TOOL_TARGET="/workspace/artifacts/extracted/win-installer"
    export SCAN_TARGET_HOST="$(realpath "$WIN_EXTRACT_DIR")"
    compose_checked --profile "$PROFILE" run --rm cve-bin-tool-scanner
  fi

else
  # ── Standard pipeline ───────────────────────────────────────────────────────
  case "$TOOL" in
    all)
      if [[ $UPDATE_DB -eq 1 ]]; then
        compose_checked --profile update run --rm -e "TRIVY_RENDERED_FLAGS=$TRIVY_FLAGS" trivy-updater
        compose_checked --profile update run --rm grype-updater
        compose_checked --profile update run --rm grype-db-importer
        compose_checked --profile update run --rm cve-bin-tool-updater
      fi
      db_status trivy /var/lib/resilient-db/trivy
      db_status grype /var/lib/resilient-db/grype/active
      db_status cve-bin-tool /root/.cache/cve-bin-tool
      compose_checked --profile "$PROFILE" run --rm syft-sbom
      compose_checked --profile "$PROFILE" run --rm -e "TRIVY_RENDERED_FLAGS=$TRIVY_FLAGS" trivy-scanner
      compose_checked --profile "$PROFILE" run --rm grype-scanner
      compose_checked --profile "$PROFILE" run --rm cve-bin-tool-scanner
      ;;
    syft)
      compose_checked --profile "$PROFILE" run --rm syft-sbom ;;
    grype)
      [[ $UPDATE_DB -eq 1 ]] && compose_checked --profile update run --rm grype-updater && compose_checked --profile update run --rm grype-db-importer
      db_status grype /var/lib/resilient-db/grype/active
      compose_checked --profile "$PROFILE" run --rm syft-sbom
      compose_checked --profile "$PROFILE" run --rm grype-scanner
      ;;
    trivy)
      [[ $UPDATE_DB -eq 1 ]] && compose_checked --profile update run --rm -e "TRIVY_RENDERED_FLAGS=$TRIVY_FLAGS" trivy-updater
      db_status trivy /var/lib/resilient-db/trivy
      compose_checked --profile "$PROFILE" run --rm -e "TRIVY_RENDERED_FLAGS=$TRIVY_FLAGS" trivy-scanner
      ;;
    cve-bin-tool)
      [[ $UPDATE_DB -eq 1 ]] && compose_checked --profile update run --rm cve-bin-tool-updater
      db_status cve-bin-tool /root/.cache/cve-bin-tool
      compose_checked --profile "$PROFILE" run --rm cve-bin-tool-scanner
      ;;
  esac
fi

# ── Collect reports ───────────────────────────────────────────────────────────
compose_checked --profile report run --rm report-collector

python -m resilient_updates.cli collect-report \
  --reports-dir artifacts \
  --target      "$SCAN_TARGET_HOST" \
  --display-target "$SCAN_TARGET_DISPLAY" \
  --output      "$REPORT_MD"

python scripts/report_html.py \
  --artifacts-dir artifacts \
  --target        "$SCAN_TARGET_DISPLAY" \
  --output        "$REPORT_HTML" || echo "[warn] HTML report generation failed — skipping"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
printf '\e[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n'
printf '\e[32m Reports ready:\e[0m\n'
printf '   MD  : %s\n' "$REPORT_MD"
printf '   HTML: %s\n' "$REPORT_HTML"
printf '\e[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n'
echo ""
