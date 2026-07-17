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
  name="$1"; disable="$2"; tmo="$3"
  home="/tmp/b_$name"
  rm -rf "$home"; mkdir -p "$home/.cache"
  for try in 1 2; do
    echo "=== SRC $name try $try $(date -u +%H:%M:%S) ==="
    HOME="$home" XDG_CACHE_HOME="$home/.cache" \
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
run_src CURL   "NVD,EPSS,PURL2CPE,OSV,RSD,GAD,REDHAT" 900
run_src OSV    "NVD,EPSS,PURL2CPE,RSD,Curl,GAD,REDHAT" 3600

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

# Copy aux dirs (source caches) from per-source homes into the final root so
# the node's cve-bin-tool sees fresh caches too.
for h in /tmp/b_*/.cache/cve-bin-tool; do
  for d in "$h"/*/; do
    [ -d "$d" ] && cp -rn "$d" "$DB/" 2>/dev/null
  done
done

# NVD via our own feed importer (adds into the merged db).
python resilient_updates/nvd_feed_import.py --db-root "$DB"
echo "=== NVD feed import rc=$? ==="

# EPSS seed (fixed empiricalsecurity URL).
python -m resilient_updates.cli --config configs/feed_sources.yaml seed cve-bin-tool-aux \
  --db-root "$DB" --seed-epss --timeout 300
echo "=== EPSS seed rc=$? ==="

# PURL2CPE: standalone sqlite, mounted in.
mkdir -p "$DB/purl2cpe"
cp /aux/purl2cpe.db "$DB/purl2cpe/purl2cpe.db" && echo "purl2cpe placed"

python -m resilient_updates.cli --config configs/feed_sources.yaml audit cve-bin-tool-db --db-root "$DB"
echo "=== audit rc=$? ==="
ls -la "$DB"
cd "$DB" && tar czf /out/cvebt_db.tgz . && echo "=== PACKED OK ==="
