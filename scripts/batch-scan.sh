#!/usr/bin/env bash
# scripts/batch-scan.sh — Linux/macOS mirror of scripts/windows/batch-scan.ps1.
#
# Run scripts/run-scan.sh against a list of {case, target} pairs sequentially,
# tolerate per-target failures, then print a SUMMARY table.  Use this for any
# multi-artifact run instead of pasting an ad-hoc loop into the terminal.
#
# Usage:
#   scripts/batch-scan.sh --jobs-json batches/daily.json
#   scripts/batch-scan.sh --jobs-csv  batches/daily.csv
#   scripts/batch-scan.sh --case CYBERSEC-12103 --target /path/a.tar.gz \
#                        --case CYBERSEC-12104 --target /path/b.zip
#
# Job-source precedence: explicit --case/--target pairs > --jobs-json > --jobs-csv.
#
# Flags:
#   --update-db-once    Pass -u to the FIRST run-scan.sh only.
#   --update-db-every   Pass -u to every run-scan.sh.
#   --skip-case-rewrite Don't overwrite "# CYBERSEC-…" header in the produced MD.
#   --no-clean          Don't pass -c (skip clean step in run-scan.sh).
#   --skip-high-critical-digest
#                       Don't run scripts/make-high-critical-report.sh after each
#                       successful scan.  By default the digest is produced
#                       next to the run-scan markdown.
#   -h | --help         Print this help.
#
# Job formats:
#   JSON: array of {"case": "...", "target": "..."} objects.
#   CSV:  first line `Case,Target`, then rows; lines whose Case starts with `#` are skipped.
#
# Exit codes:
#   0  all jobs OK
#   2  at least one job failed
#   3  bad usage / no jobs

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RUN_SCAN="$REPO_ROOT/scripts/run-scan.sh"
if [[ ! -x "$RUN_SCAN" ]]; then
  echo "ERROR: $RUN_SCAN is not executable. chmod +x scripts/run-scan.sh" >&2
  exit 3
fi

# ── Parse args ──────────────────────────────────────────────────────────────
JOBS_JSON=""
JOBS_CSV=""
UPDATE_DB_ONCE=0
UPDATE_DB_EVERY=0
SKIP_REWRITE=0
DO_CLEAN=1
SKIP_HC_DIGEST=0
INLINE_CASES=()
INLINE_TARGETS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --jobs-json)       JOBS_JSON="$2"; shift 2 ;;
    --jobs-csv)        JOBS_CSV="$2";  shift 2 ;;
    --case)            INLINE_CASES+=("$2"); shift 2 ;;
    --target)          INLINE_TARGETS+=("$2"); shift 2 ;;
    --update-db-once)  UPDATE_DB_ONCE=1; shift ;;
    --update-db-every) UPDATE_DB_EVERY=1; shift ;;
    --skip-case-rewrite) SKIP_REWRITE=1; shift ;;
    --no-clean)        DO_CLEAN=0; shift ;;
    --skip-high-critical-digest) SKIP_HC_DIGEST=1; shift ;;
    -h|--help)
      sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 3 ;;
  esac
done

if [[ $UPDATE_DB_ONCE -eq 1 && $UPDATE_DB_EVERY -eq 1 ]]; then
  echo "ERROR: pick one of --update-db-once / --update-db-every" >&2
  exit 3
fi
if [[ ${#INLINE_CASES[@]} -ne ${#INLINE_TARGETS[@]} ]]; then
  echo "ERROR: --case count != --target count" >&2
  exit 3
fi

# ── Load jobs ───────────────────────────────────────────────────────────────
# Each entry as "CASE|TARGET" (so we can store in a bash array without
# losing whitespace).  Precedence: inline → json → csv.
JOBS=()

if [[ ${#INLINE_CASES[@]} -gt 0 ]]; then
  for i in "${!INLINE_CASES[@]}"; do
    JOBS+=("${INLINE_CASES[$i]}|${INLINE_TARGETS[$i]}")
  done
fi

if [[ -z "${JOBS[*]:-}" && -n "$JOBS_JSON" ]]; then
  [[ -f "$JOBS_JSON" ]] || { echo "ERROR: $JOBS_JSON not found" >&2; exit 3; }
  # shellcheck disable=SC2207
  while IFS= read -r line; do
    JOBS+=("$line")
  done < <(python3 -c '
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
for item in data:
    case = (item.get("case") or item.get("Case") or "").strip()
    target = (item.get("target") or item.get("Target") or "").strip()
    if target:
        print(f"{case}|{target}")
' "$JOBS_JSON")
fi

if [[ -z "${JOBS[*]:-}" && -n "$JOBS_CSV" ]]; then
  [[ -f "$JOBS_CSV" ]] || { echo "ERROR: $JOBS_CSV not found" >&2; exit 3; }
  while IFS= read -r line; do
    JOBS+=("$line")
  done < <(python3 -c '
import csv, sys
with open(sys.argv[1]) as f:
    rd = csv.DictReader(f)
    for row in rd:
        case = (row.get("Case") or row.get("case") or "").strip()
        if not case or case.startswith("#"):
            continue
        target = (row.get("Target") or row.get("target") or "").strip()
        if target:
            print(f"{case}|{target}")
' "$JOBS_CSV")
fi

if [[ ${#JOBS[@]} -eq 0 ]]; then
  echo "ERROR: no jobs to run.  Pass --case/--target, --jobs-json, or --jobs-csv." >&2
  exit 3
fi

# ── Run loop ────────────────────────────────────────────────────────────────
TODAY="$(date +%Y-%m-%d)"
FIRST_JOB=1
declare -a RESULT_STATUS RESULT_CASE RESULT_REPORT RESULT_SYFT RESULT_GRYPE RESULT_CBT RESULT_SEV

idx=0
for entry in "${JOBS[@]}"; do
  CASE_ID="${entry%%|*}"
  TARGET="${entry#*|}"
  LABEL="${CASE_ID:-(auto-case)}"
  BASENAME="$(basename "$TARGET")"

  echo
  echo "========== $LABEL  ($BASENAME) =========="

  if [[ ! -e "$TARGET" ]]; then
    echo "   ! цель не найдена: $TARGET" >&2
    RESULT_STATUS[$idx]="missing-target"
    RESULT_CASE[$idx]="$CASE_ID"
    RESULT_REPORT[$idx]=""
    RESULT_SYFT[$idx]=""; RESULT_GRYPE[$idx]=""; RESULT_CBT[$idx]=""; RESULT_SEV[$idx]=""
    idx=$((idx + 1))
    continue
  fi

  ARGS=(-t "$TARGET")
  [[ $DO_CLEAN -eq 1 ]] && ARGS+=(-c)
  if [[ $UPDATE_DB_EVERY -eq 1 ]] || { [[ $UPDATE_DB_ONCE -eq 1 ]] && [[ $FIRST_JOB -eq 1 ]]; }; then
    ARGS+=(-u)
  fi
  FIRST_JOB=0
  # Pass --case-id explicitly so the final Markdown header is correct on
  # the first try — no need for the postfix grep+sed dance below.  The
  # rewrite logic is preserved as a safety net for older runs.
  [[ -n "$CASE_ID" ]] && ARGS+=(--case-id "$CASE_ID")

  set +e
  "$RUN_SCAN" "${ARGS[@]}"
  rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    echo "   ! run-scan.sh exit $rc" >&2
    RESULT_STATUS[$idx]="failed"
    RESULT_CASE[$idx]="$CASE_ID"
    RESULT_REPORT[$idx]=""
    RESULT_SYFT[$idx]=""; RESULT_GRYPE[$idx]=""; RESULT_CBT[$idx]=""; RESULT_SEV[$idx]=""
    idx=$((idx + 1))
    continue
  fi

  # Locate today's report next to the target.
  TARGET_DIR="$(dirname "$TARGET")"
  TARGET_BASE="$(basename "$TARGET")"
  # Strip known archive suffixes for report basename derivation.
  REPORT_BASE="$TARGET_BASE"
  for ext in .tar.gz .tar.bz2 .tar.xz .tar.zst .tar .tgz .zip .gz .bz2 .xz .zst .jar .war .ear .apk .ipa; do
    if [[ "${REPORT_BASE,,}" == *"$ext" ]]; then
      REPORT_BASE="${REPORT_BASE%${REPORT_BASE: -${#ext}}}"
      break
    fi
  done
  REPORT="$TARGET_DIR/${REPORT_BASE}_report_${TODAY}.md"
  if [[ ! -f "$REPORT" ]]; then
    echo "   ! сегодняшнего отчёта нет в $TARGET_DIR" >&2
    RESULT_STATUS[$idx]="no-report"
    RESULT_CASE[$idx]="$CASE_ID"
    RESULT_REPORT[$idx]=""
    RESULT_SYFT[$idx]=""; RESULT_GRYPE[$idx]=""; RESULT_CBT[$idx]=""; RESULT_SEV[$idx]=""
    idx=$((idx + 1))
    continue
  fi

  # Rewrite the # CYBERSEC-… header line if explicit case differs.
  if [[ $SKIP_REWRITE -eq 0 && -n "$CASE_ID" ]]; then
    head_line="$(head -n 1 "$REPORT" || true)"
    if ! grep -qE "^# ${CASE_ID}:" "$REPORT"; then
      python3 -c '
import re, sys, pathlib
p = pathlib.Path(sys.argv[1])
case = sys.argv[2]
text = p.read_text(encoding="utf-8")
text = re.sub(r"^# CYBERSEC-\S+:", f"# {case}:", text, count=1, flags=re.MULTILINE)
p.write_text(text, encoding="utf-8")
' "$REPORT" "$CASE_ID"
      echo "   shapka -> $CASE_ID"
    fi
  fi

  # Pull headline numbers.
  SYFT=$(grep -m1 -oE 'Syft components:\s*`[0-9]+`' "$REPORT" | grep -oE '[0-9]+' | head -1)
  GRYPE=$(grep -m1 -oE 'Grype findings:\s*`[0-9]+`' "$REPORT" | grep -oE '[0-9]+' | head -1)
  CBT=$(grep -m1 -oE 'cve-bin-tool findings:\s*`[0-9]+`' "$REPORT" | grep -oE '[0-9]+' | head -1)
  SEV=$(grep -m1 -oE "Severity counts:\s*\`[^\`]*\`" "$REPORT" | sed -E 's/^.*\`(.*)\`/\1/')

  RESULT_STATUS[$idx]="ok"
  RESULT_CASE[$idx]="$CASE_ID"
  RESULT_REPORT[$idx]="$REPORT"
  RESULT_SYFT[$idx]="${SYFT:-}"
  RESULT_GRYPE[$idx]="${GRYPE:-}"
  RESULT_CBT[$idx]="${CBT:-}"
  RESULT_SEV[$idx]="${SEV:-}"

  # Compact high/critical digest in CYBERSEC-11531 reference format.  Skip
  # with --skip-high-critical-digest.
  if [[ $SKIP_HC_DIGEST -eq 0 ]]; then
    HC_SCRIPT="$REPO_ROOT/scripts/make-high-critical-report.sh"
    if [[ -x "$HC_SCRIPT" ]]; then
      HC_ARGS=(--target "$TARGET")
      if [[ $UPDATE_DB_EVERY -eq 1 ]] || { [[ $UPDATE_DB_ONCE -eq 1 ]] && [[ $idx -eq 0 ]]; }; then
        HC_ARGS+=(--online-db)
      fi
      "$HC_SCRIPT" "${HC_ARGS[@]}" || \
        echo "   ! make-high-critical-report.sh упал (job продолжается)" >&2
    fi
  fi

  idx=$((idx + 1))
done

# ── SUMMARY ─────────────────────────────────────────────────────────────────
echo
echo "=========== SUMMARY ==========="
BAD=0
for i in "${!RESULT_STATUS[@]}"; do
  STATUS="${RESULT_STATUS[$i]}"
  [[ "$STATUS" != "ok" ]] && BAD=$((BAD + 1))
  printf '%-25s %-14s syft=%-4s grype=%-4s cbt=%-4s sev=%s\n' \
    "${RESULT_CASE[$i]:-(auto)}" \
    "$STATUS" \
    "${RESULT_SYFT[$i]:-}" \
    "${RESULT_GRYPE[$i]:-}" \
    "${RESULT_CBT[$i]:-}" \
    "${RESULT_SEV[$i]:-}"
done

exit $(( BAD > 0 ? 2 : 0 ))
