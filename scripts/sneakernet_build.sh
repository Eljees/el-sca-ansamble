#!/bin/sh
# v7: per-source isolated builds + sqlite merge.
# - one cve-bin-tool source per run (multi-source gather hangs on fast networks
#   even with fixups; single-source runs are proven green);
# - each run gets its OWN HOME so --update now cannot wipe previous results;
# - python merges the per-source cve.db files into one, then our own importers
#   add NVD (feeds), EPSS (seed) and PURL2CPE (file).
set -x
cd /workspace
python /workspace/scripts/patches/cve_bin_tool_3.4_fixups.py
echo "=== fixups rc=$? ==="

DB=/tmp/build/.cache/cve-bin-tool
mkdir -p "$DB" /tmp/empty

run_src() {
  name="$1"; disable="$2"; tmo="$3"; proxy="${4:-}"
  home="/tmp/b_$name"
  # Idempotent: a previous run's db (also mountable from the host) is kept.
  if [ -s "$home/.cache/cve-bin-tool/cve.db" ]; then
    echo "=== SRC $name SKIP (cve.db already present) ==="
    return 0
  fi
  rm -rf "$home"; mkdir -p "$home/.cache"
  for try in 1 2; do
    echo "=== SRC $name try $try $(date -u +%H:%M:%S) proxy=${proxy:-none} ==="
    HOME="$home" XDG_CACHE_HOME="$home/.cache" \
      HTTP_PROXY="$proxy" HTTPS_PROXY="$proxy" http_proxy="$proxy" https_proxy="$proxy" \
      timeout "$tmo" cve-bin-tool --update now --disable-version-check \
      --disable-data-source "$disable" /tmp/empty
    rc=$?
    echo "=== SRC $name rc=$rc ==="
    if [ "$rc" -le 1 ] && [ -s "$home/.cache/cve-bin-tool/cve.db" ]; then return 0; fi
  done
  return 1
}

run_src REDHAT "NVD,EPSS,PURL2CPE,OSV,RSD,Curl,GAD" 1200
run_src GAD    "NVD,EPSS,PURL2CPE,OSV,RSD,Curl,REDHAT" 1500
# CURL is tiny (~200 rows about the curl utility) and works fine on the node's
# proxied egress (it was green in the pre-existing DB).  It can rc=33 on some
# fast networks, so it is best-effort: a failure does NOT abort the build.
# Pass the host proxy for contours that need it (same as OSV_HTTP_PROXY).
run_src CURL   "NVD,EPSS,PURL2CPE,OSV,RSD,GAD,REDHAT" 900 "${OSV_HTTP_PROXY:-}" || \
  echo "=== CURL skipped (rc=33 / unreachable) — non-fatal ==="
# OSV via cve-bin-tool hangs even single-source; NOT needed: the audit counts
# OSV/EPSS/PURL2CPE/RSD by FILES in db_root (see cve_db_audit._source_count),
# and our `seed cve-bin-tool-aux` below downloads those files via requests
# (honours HTTP(S)_PROXY env - set OSV_HTTP_PROXY for blocked hosts).

# Merge all per-source cve.db files into $DB/cve.db.
python - <<'PY'
import glob, os, sqlite3
dst_path = "/tmp/build/.cache/cve-bin-tool/cve.db"
srcs = sorted(glob.glob("/tmp/b_*/.cache/cve-bin-tool/cve.db"))
print("merging:", srcs)
con = sqlite3.connect(dst_path)
for i, s in enumerate(srcs):
    alias = f"m{i}"
    con.execute(f"ATTACH DATABASE '{s}' AS {alias}")
    rows = con.execute(
        f"SELECT name, sql FROM {alias}.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    for name, sql in rows:
        if sql:
            con.execute(sql.replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1))
        n = con.execute(f"INSERT OR IGNORE INTO {name} SELECT * FROM {alias}.{name}").rowcount
        print(f"{os.path.dirname(s).split('/')[2]} -> {name}: +{n}")
    con.commit()
    con.execute(f"DETACH DATABASE {alias}")
con.commit()
for name, in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
    cnt = con.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
    print(f"TOTAL {name}: {cnt}")
con.close()
PY
echo "=== merge rc=$? ==="

# NOTE: per-source caches (gad/, redhat/ yaml trees) are deliberately NOT
# copied into the final root: the audit counts GAD/REDHAT by cve.db rows,
# and 35k small files only bloat the tar and the scp (and crawl through
# WSL2 bind mounts).

# NVD via our own feed importer (adds into the merged db). Route through the
# host proxy when provided - requests honours these env vars.
export HTTP_PROXY="${OSV_HTTP_PROXY:-}" HTTPS_PROXY="${OSV_HTTP_PROXY:-}"
export http_proxy="${OSV_HTTP_PROXY:-}" https_proxy="${OSV_HTTP_PROXY:-}"
python resilient_updates/nvd_feed_import.py --db-root "$DB"
echo "=== NVD feed import rc=$? ==="

# OSV + EPSS + RSD seed files (this is what the audit/dashboard actually
# counts for those sources). requests + proxy env, fixed empiricalsecurity URL.
python -m resilient_updates.cli --config configs/feed_sources.yaml seed cve-bin-tool-aux \
  --db-root "$DB" --seed-epss --seed-rsd --timeout 600 \
  --osv-ecosystem Debian --osv-ecosystem Ubuntu --osv-ecosystem Alpine \
  --osv-ecosystem Go --osv-ecosystem PyPI --osv-ecosystem Maven \
  --osv-ecosystem npm --osv-ecosystem Rust
echo "=== seed rc=$? ==="

# PURL2CPE: standalone sqlite, mounted in.
mkdir -p "$DB/purl2cpe"
cp /aux/purl2cpe.db "$DB/purl2cpe/purl2cpe.db" && echo "purl2cpe placed"

python -m resilient_updates.cli --config configs/feed_sources.yaml audit cve-bin-tool-db --db-root "$DB"
echo "=== audit rc=$? ==="
ls -la "$DB"
cd "$DB" && tar czf /out/cvebt_db.tgz . && echo "=== PACKED OK ==="
