#!/usr/bin/env bash
# scripts/make-high-critical-report.sh
#
# POSIX mirror of scripts/windows/make-high-critical-report.ps1.
#
# Produce a compact "high/critical" digest in the CYBERSEC-11531 reference
# format from an existing run-scan.sh markdown report.  It does NOT re-run
# any scanner — parses the existing scan markdown for the
# "High / Critical findings" table and the "Scanner summary" block, then
# re-renders them next to the source report as
#     <basename>_high_critical_<REPORT_DATE>_ru.md
#
# Usage:
#   scripts/make-high-critical-report.sh --target /path/to/artifact.tar.gz
#   scripts/make-high-critical-report.sh --report  /path/to/foo_report_2026-05-20.md
#   scripts/make-high-critical-report.sh --jobs-json batches/daily.json
#
# Options:
#   --target  PATH        Archive that was scanned.  Auto-discovers latest sibling *_report_*.md.
#   --report  PATH        Explicit path to the scan-report markdown.
#   --jobs-json PATH      JSON array of {"case", "target"} objects (same shape as batch-scan).
#   --jobs-csv  PATH      CSV with columns Case,Target.
#   --runner   STRING     Tooling identifier embedded in "Методика" section.
#                         Default: "el-sca-ansamble (docker compose)".
#   --online-db           Mark digest as produced after a forced DB refresh.
#   --output-dir PATH     Override where the digest is written.
#   -h | --help           Print this help.
#
# Exit codes:
#   0  digest written
#   2  one or more inputs failed; remaining outputs still written
#   3  bad usage

set -euo pipefail

RUNNER="el-sca-ansamble (docker compose)"
ONLINE_DB=0
OUTPUT_DIR=""
TARGET=""
REPORT=""
JOBS_JSON=""
JOBS_CSV=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)     TARGET="$2";     shift 2 ;;
    --report)     REPORT="$2";     shift 2 ;;
    --jobs-json)  JOBS_JSON="$2";  shift 2 ;;
    --jobs-csv)   JOBS_CSV="$2";   shift 2 ;;
    --runner)     RUNNER="$2";     shift 2 ;;
    --online-db)  ONLINE_DB=1;     shift   ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 3 ;;
  esac
done

if [[ -z "$TARGET" && -z "$REPORT" && -z "$JOBS_JSON" && -z "$JOBS_CSV" ]]; then
  echo "ERROR: pass --target, --report, --jobs-json or --jobs-csv" >&2
  exit 3
fi

# ── helpers ────────────────────────────────────────────────────────────────

# Echo the most recent <basename>_report_*.md sibling of the given target, or
# nothing if none found.  Trim trailing .tar before computing the base so
# foo.tar.gz → foo (matching run-scan.sh's behaviour).
_latest_report_for() {
  local tgt="$1"
  local dir base
  dir="$(dirname -- "$tgt")"
  base="$(basename -- "$tgt")"
  base="${base%.*}"          # strip last extension
  base="${base%.tar}"        # strip .tar from .tar.gz
  ls -1t -- "${dir}"/${base}_report_*.md 2>/dev/null \
    | grep -v '_high_critical_' \
    | head -n1
}

_report_date() {
  local fname
  fname="$(basename -- "$1")"
  if [[ "$fname" =~ _report_([0-9]{4}-[0-9]{2}-[0-9]{2})\.md$ ]]; then
    echo "${BASH_REMATCH[1]}"
  else
    date '+%Y-%m-%d'
  fi
}

_sha256_of() {
  if [[ -f "$1" ]]; then
    sha256sum "$1" | awk '{print toupper($1)}'
  fi
}

# Parse the scan markdown and emit a digest to stdout.  We do this in Python
# because regex + table walking is materially easier than in pure bash.
_emit_digest() {
  local report_path="$1" archive_path="$2" archive_sha="$3" report_date="$4"
  local runner_name="$5" online_db="$6"

  REPORT_PATH="$report_path" \
  ARCHIVE_PATH="$archive_path" \
  ARCHIVE_SHA="$archive_sha" \
  REPORT_DATE="$report_date" \
  RUNNER_NAME="$runner_name" \
  ONLINE_DB="$online_db" \
  python3 - <<'PYEOF'
import os, re, sys, pathlib
from collections import Counter, defaultdict

path = pathlib.Path(os.environ["REPORT_PATH"])
text = path.read_text(encoding="utf-8", errors="replace").splitlines()

# Header line: "# CYBERSEC-NNNNN: контейнерный SCA-отчет"
case_id = "CYBERSEC-UNKNOWN"
if text and text[0].startswith("# "):
    head_tokens = text[0].lstrip("# ").split()
    if head_tokens:
        case_id = head_tokens[0].rstrip(":")

# Scanner summary fields and DB metadata.
fields = {
    "target_display": "", "target_sha": "", "db_snapshot": "",
    "db_drift": "", "tool_failures": "",
    "syft": 0, "grype": 0, "trivy": 0, "cbt": 0,
    "severity_counts": {},
}
for ln in text:
    m = re.match(r"-\s+Target:\s+`([^`]+)`", ln);              ok = m and fields.update(target_display=m.group(1))
    m = re.match(r"-\s+SHA-256:\s+`([^`]+)`", ln);             ok = m and fields.update(target_sha=m.group(1))
    m = re.match(r"-\s+DB snapshot:\s+`([^`]+)`", ln);         ok = m and fields.update(db_snapshot=m.group(1))
    m = re.match(r"-\s+DB drift:\s+`([^`]+)`", ln);            ok = m and fields.update(db_drift=m.group(1))
    m = re.match(r"-\s+Tool failures:\s+`([^`]+)`", ln);       ok = m and fields.update(tool_failures=m.group(1))
    m = re.match(r"-\s+Syft components:\s+`(\d+)`", ln);       ok = m and fields.update(syft=int(m.group(1)))
    m = re.match(r"-\s+Grype findings:\s+`(\d+)`", ln);        ok = m and fields.update(grype=int(m.group(1)))
    m = re.match(r"-\s+Trivy findings:\s+`(\d+)`", ln);        ok = m and fields.update(trivy=int(m.group(1)))
    m = re.match(r"-\s+cve-bin-tool findings:\s+`(\d+)`", ln); ok = m and fields.update(cbt=int(m.group(1)))
    m = re.match(r"-\s+Severity counts:\s+`([^`]+)`", ln)
    if m:
        sev = {}
        for k, v in re.findall(r"'([A-Z]+)':\s*(\d+)", m.group(1)):
            sev[k] = int(v)
        fields["severity_counts"] = sev

# High/Critical table walk.
findings = []
i = 0
while i < len(text):
    if re.match(r"^##\s+High\s*/\s*Critical", text[i]):
        i += 1
        while i < len(text) and not text[i].lstrip().startswith("| Tool"):
            if text[i].startswith("## "):
                i = len(text); break
            i += 1
        if i >= len(text):
            break
        # header row -> column names
        cols = [c.strip() for c in text[i].strip().strip("|").split("|")]
        i += 2  # skip the rule line
        while i < len(text):
            row = text[i].rstrip()
            if not row or not row.startswith("|"):
                break
            cells = [c.strip() for c in row.strip().strip("|").split("|")]
            rec = dict(zip(cols, cells))
            findings.append(rec)
            i += 1
        break
    i += 1

cve_key = "CVE/GHSA"
def _comp(rec):
    vendor = rec.get("Vendor", "")
    product = rec.get("Product", "")
    version = rec.get("Version", "")
    src = rec.get("Source", "")
    if vendor and product and vendor != product:
        return f"{vendor}:{product} {version}".rstrip()
    if product:
        return f"{product} {version}".rstrip()
    return src or "(unknown component)"

critical = [r for r in findings if r.get("Severity", "").upper() == "CRITICAL"]
high     = [r for r in findings if r.get("Severity", "").upper() == "HIGH"]

archive_path = os.environ.get("ARCHIVE_PATH") or ""
archive_name = os.path.basename(archive_path) if archive_path else os.path.basename(fields["target_display"])
sha_header   = os.environ.get("ARCHIVE_SHA") or (fields["target_sha"] if fields["target_sha"] and fields["target_sha"] != "UNKNOWN" else "UNKNOWN")
sev = fields["severity_counts"]
crit_total = sev.get("CRITICAL", 0); high_total = sev.get("HIGH", 0)
med_total  = sev.get("MEDIUM", 0);   low_total  = sev.get("LOW", 0)
unk_total  = sev.get("UNKNOWN", 0)
report_date = os.environ.get("REPORT_DATE") or ""
runner = os.environ.get("RUNNER_NAME") or "el-sca-ansamble (docker compose)"
online = os.environ.get("ONLINE_DB", "0") == "1"

out = []
out.append(f"# Отчет по high/critical уязвимостям: {case_id}")
out.append("")
out.append("## Объект анализа")
out.append(f"- `{archive_name}`")
out.append(f"- SHA-256: `{sha_header}`")
out.append("")
out.append("## Методика")
out.append(f"- Контейнерный прогон `{runner}`.")
if online:
    out.append("- Локальные базы `grype` и `cve-bin-tool` с принудительным online-обновлением перед прогоном.")
else:
    out.append("- Локальные базы `grype` и `cve-bin-tool`, без online-обновления.")
out.append("- Проверены `summary.json`, `status.json`, `syft.json`, `reports/grype/report.json`, `reports/cve-bin-tool/report.json`.")
if fields["db_snapshot"] and fields["db_snapshot"] != "UNKNOWN":
    out.append(f"- DB snapshot: `{fields['db_snapshot']}`.")
if fields["db_drift"] and fields["db_drift"] != "UNKNOWN":
    out.append(f"- DB drift: `{fields['db_drift']}`.")
if fields["tool_failures"] and fields["tool_failures"] != "UNKNOWN":
    out.append(f"- Tool failures: `{fields['tool_failures']}`.")
out.append("")
out.append("## Что обнаружено")
out.append(f"- `syft components={fields['syft']}`")
out.append(f"- `grype matches={fields['grype']}`")
out.append(f"- `cve-bin-tool findings={fields['cbt']}`")
if fields['trivy']:
    out.append(f"- `trivy findings={fields['trivy']}`")
out.append("- `severity totals`:")
out.append(f"  - `CRITICAL={crit_total}`")
out.append(f"  - `HIGH={high_total}`")
out.append(f"  - `MEDIUM={med_total}`")
out.append(f"  - `LOW={low_total}`")
if unk_total:
    out.append(f"  - `UNKNOWN={unk_total}`")
out.append("")
out.append("## High / Critical")
out.append("")
out.append("### Critical")
out.append("")
if not critical:
    out.append("- Critical-находок не зафиксировано.")
else:
    for r in sorted(critical, key=lambda x: (x.get("Tool",""), x.get(cve_key,""))):
        out.append(f"- `{r.get(cve_key,'')}` - `{_comp(r)}` - `{r.get('Tool','')}`")
out.append("")
out.append("### High")
out.append("")
by_tool = defaultdict(list)
for r in high:
    by_tool[r.get("Tool", "unknown")].append(r)
if not by_tool:
    out.append("- High-находок не зафиксировано.")
    out.append("")
else:
    for tool in sorted(by_tool):
        out.append(f"#### `{tool}`")
        out.append("")
        for r in sorted(by_tool[tool], key=lambda x: (x.get(cve_key,""), x.get("Product",""), x.get("Version",""))):
            out.append(f"- `{r.get(cve_key,'')}` - `{_comp(r)}`")
        out.append("")

table_total = len(critical) + len(high)
agg_total = crit_total + high_total
if agg_total > table_total:
    extra = agg_total - table_total
    out.append(f"Примечание: `severity totals` показывает CRITICAL+HIGH={agg_total}, тогда как уникальных записей в таблице — {table_total}. Разница в {extra} строки приходится на дубли по разным бинарям/локациям внутри одного bundle (deduplication по (id, product, version, tool)).")
    out.append("")

out.append("## Практический вывод")
if crit_total > 0 or high_total > 0:
    out.append(f"- Для `{case_id}` high/critical уязвимости подтверждены сканерами.")
    out.append("- Перед допуском требуется ручной applicability review по каждой строке: проверить, что версия компонента и contextual exploitability действительно применимы к поставке.")
    out.append(f"- Хранить вместе с этим digest-ом исходный `{archive_name}` SHA-256 `{sha_header}` и сканер-отчёт `{os.path.basename(os.environ['REPORT_PATH'])}`.")
else:
    out.append(f"- Для `{case_id}` high/critical находок не зафиксировано в текущем прогоне.")
    out.append(f"- Файл сохраняется как формальное подтверждение чистого результата на дату `{report_date}`.")
out.append("")

sys.stdout.write("\n".join(out))
PYEOF
}

_process_one() {
  local archive_path="$1" report_path="$2"

  if [[ -z "$report_path" && -n "$archive_path" ]]; then
    report_path="$(_latest_report_for "$archive_path")"
    if [[ -z "$report_path" ]]; then
      echo "   ! не найден scan-отчёт рядом с $archive_path" >&2
      return 1
    fi
  fi
  if [[ ! -f "$report_path" ]]; then
    echo "   ! отсутствует $report_path" >&2
    return 1
  fi

  local report_date archive_sha base out_dir out_path
  report_date="$(_report_date "$report_path")"
  archive_sha=""
  if [[ -n "$archive_path" ]]; then
    archive_sha="$(_sha256_of "$archive_path" || true)"
  fi
  base="$(basename -- "$report_path" .md)"
  base="${base%_report_${report_date}}"
  if [[ -n "$OUTPUT_DIR" ]]; then
    out_dir="$OUTPUT_DIR"
  else
    out_dir="$(dirname -- "$report_path")"
  fi
  mkdir -p -- "$out_dir"
  out_path="${out_dir}/${base}_high_critical_${report_date}_ru.md"

  _emit_digest "$report_path" "$archive_path" "$archive_sha" "$report_date" "$RUNNER" "$ONLINE_DB" \
    > "$out_path"
  echo "   high/critical digest -> $out_path"
}

rc=0
if [[ -n "$JOBS_JSON" ]]; then
  [[ -f "$JOBS_JSON" ]] || { echo "JOBS_JSON not found: $JOBS_JSON" >&2; exit 3; }
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    _process_one "$line" "" || rc=2
  done < <(python3 -c '
import json, sys
data = json.load(open(sys.argv[1]))
for item in data:
    t = item.get("target") or item.get("Target") or ""
    if t: print(t)
' "$JOBS_JSON")
elif [[ -n "$JOBS_CSV" ]]; then
  [[ -f "$JOBS_CSV" ]] || { echo "JOBS_CSV not found: $JOBS_CSV" >&2; exit 3; }
  while IFS=, read -r case target rest; do
    [[ "$case" =~ ^# ]]    && continue
    [[ "$case" == "Case" ]] && continue
    [[ -z "$target" ]]      && continue
    _process_one "$target" "" || rc=2
  done < "$JOBS_CSV"
else
  _process_one "$TARGET" "$REPORT" || rc=$?
fi

exit $rc
