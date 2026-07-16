#!/usr/bin/env python3
"""Apply targeted fixes to cve-bin-tool 3.4's broken enrichment sources.

Run at image-build time (Dockerfile.cve-bin-tool) right after
`pip install cve-bin-tool==3.4`.  3.4 is the latest PyPI release, so there is
no version to bump to; these are upstream bugs that fire on *every* machine and
every code path (proven on 10.2.108.47), which is why OSV/EPSS/PURL2CPE were
disabled via CVE_BIN_TOOL_ENRICH_DISABLE.

Wrapper-first project rule: we do NOT fork cve-bin-tool.  This patcher only
repairs the specific breakages in-place and reuses cve-bin-tool's own
download/parse/store — so the data stays upstream's, not ours.

Each fix is idempotent and *verified*: if the exact target text is missing
(e.g. a future version moved the code), the build FAILS loudly instead of
silently shipping an unpatched image.

Fixes
-----
1. cvedb.py ordering -- the ROOT CAUSE (upstream PR bundle: docs/upstream/).

   ``CVEDB.refresh_cache_and_update_db()`` gathers every data source first
   (``run_coroutine(self.refresh())`` -> ``get_data()`` ->
   ``source.get_cve_data()``) and only then runs ``populate_db()``, whose
   first statement ``populate_metrics()`` inserts the static metric rows
   (1,'EPSS') / (2,'CVSS-2') / (3,'CVSS-3').  But ``Epss_Source`` resolves
   its metric id *while fetching*: ``EPSS_id_finder`` does
   ``SELECT metrics_id FROM metrics WHERE metrics_name = "EPSS"`` and then
   ``fetchall()[0][0]`` -> ``IndexError``, because the ``metrics`` table is
   still empty (or missing entirely on a fresh cache).

   Fix: create the schema and the static metric rows BEFORE the gather.
   ``init_database()`` and ``populate_metrics()`` are both idempotent
   (CREATE TABLE IF NOT EXISTS / INSERT OR REPLACE) and depend on no source
   output, so hoisting them is safe.

2. epss_source.py -- kept in addition to fix 1:

   a. ``get_cve_data`` calls ``await self.update_epss()`` but the method
      signature is ``update_epss(self, cursor)`` -- a hard ``TypeError`` on
      every run.  Fix 1 does NOT cure this; without a cursor EPSS still dies.
   b. The same patch defensively creates/seeds the (1,'EPSS') metric row from
      the source's own sqlite connection.  With fix 1 in place this is a
      no-op belt-and-suspenders (protects a partially initialized cache or
      standalone use of the source).

Both bugs are swallowed by ``except Exception`` in ``get_cve_data`` and
surface only as "Unable to fetch EPSS, skipping EPSS." at count 0.

Version note: pinned to cve-bin-tool==3.4 (latest stable on PyPI as of
2026-07).  Upstream main / 3.4.1rc0 rewrites epss_source.py -- update_epss()
drops the cursor parameter and the metrics-table lookup entirely -- which
masks the crash but keeps the populate-metrics-after-gather ordering that
fix 1 corrects (fix 1's target text is unchanged there and still correct).
On any version bump: DROP fix 2 (its patched call would pass a stray cursor)
and re-audit fix 1.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _cvebt_dir() -> Path:
    import cve_bin_tool

    return Path(cve_bin_tool.__file__).parent


def _replace_once(path: Path, old: str, new: str, *, marker: str) -> str:
    text = path.read_text(encoding="utf-8")
    if marker in text:
        return "already-patched"
    if old not in text:
        raise SystemExit(
            f"PATCH FAILED: expected text not found in {path.name}; "
            f"cve-bin-tool internals changed -- review scripts/patches/ before building.\n"
            f"--- expected ---\n{old}"
        )
    if text.count(old) != 1:
        raise SystemExit(
            f"PATCH FAILED: {path.name}: expected exactly 1 match, found {text.count(old)}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")
    return "patched"


def fix_cvedb_metrics_ordering() -> str:
    """Populate static metric definitions BEFORE the source gather (root cause)."""
    path = _cvebt_dir() / "cvedb.py"

    # Part 1: hoist schema init + metric definitions above the source gather.
    old_gather = (
        '        self.LOGGER.debug("Updating CVE data. This will take a few minutes.")\n'
        "        # refresh the nvd cache\n"
        "        run_coroutine(self.refresh())\n"
        "\n"
        "        # if the database isn't open, open it\n"
        "        self.init_database()\n"
        "        self.populate_db()\n"
    )
    new_gather = (
        '        self.LOGGER.debug("Updating CVE data. This will take a few minutes.")\n'
        "        # PATCH(el-sca): populate metric definitions before the source gather.\n"
        "        # Root cause of the 3.4 EPSS crash: get_data() runs every source's\n"
        "        # get_cve_data() -- and Epss_Source resolves its metrics_id from the\n"
        "        # metrics table while fetching -- BEFORE populate_db() ->\n"
        "        # populate_metrics() has inserted the (1,'EPSS') row, so the lookup\n"
        "        # hits an empty table and raises IndexError.  Schema and static\n"
        "        # metric rows depend on no source output and both calls are\n"
        "        # idempotent (CREATE TABLE IF NOT EXISTS / INSERT OR REPLACE), so\n"
        "        # do them first.  The cachedir may not exist yet on a fresh install\n"
        "        # (upstream created it inside refresh()), hence the mkdir guard.\n"
        "        if not self.cachedir.is_dir():\n"
        "            self.cachedir.mkdir(parents=True)\n"
        "        # if the database isn't open, open it\n"
        "        self.init_database()\n"
        "        self.populate_metrics()\n"
        "        # refresh the nvd cache\n"
        "        run_coroutine(self.refresh())\n"
        "\n"
        "        self.populate_db()\n"
    )
    part1 = _replace_once(
        path,
        old_gather,
        new_gather,
        marker="PATCH(el-sca): populate metric definitions before the source gather",
    )

    # Part 2: drop the now-too-late call inside populate_db().
    old_late = (
        "        self.populate_metrics()\n"
        "        # EPSS uses metrics table to get the EPSS metric id.\n"
        "        # It can't be run before creation of metrics table.\n"
        "\n"
    )
    new_late = (
        "        # PATCH(el-sca): populate_metrics() call moved up into\n"
        "        # refresh_cache_and_update_db(), BEFORE the source gather -- the\n"
        "        # EPSS source needs the metrics rows while it is fetching, which\n"
        "        # happens before populate_db() ever runs.\n"
        "\n"
    )
    part2 = _replace_once(
        path,
        old_late,
        new_late,
        marker="PATCH(el-sca): populate_metrics() call moved up",
    )

    parts = (part1, part2)
    if all(p == "already-patched" for p in parts):
        return "already-patched"
    return "patched"


def fix_epss() -> str:
    path = _cvebt_dir() / "data_sources" / "epss_source.py"
    old = (
        "        try:\n"
        "            await self.update_epss()\n"
        "        except Exception as e:\n"
        '            self.LOGGER.debug(f"Error while fetching EPSS data: {e}")\n'
        '            self.LOGGER.error("Unable to fetch EPSS, skipping EPSS.")\n'
    )
    new = (
        "        # PATCH(el-sca): EPSS is broken two ways in 3.4 -- update_epss()\n"
        "        # is called without its required cursor, and sources are fetched\n"
        "        # before populate_metrics() inserts the EPSS row. Provide a cursor\n"
        "        # onto the cve.db and ensure the (1,'EPSS') metric row exists,\n"
        "        # using cve-bin-tool's own constant, so store_epss_data writes\n"
        "        # under the same id.\n"
        "        try:\n"
        "            import sqlite3 as _sqlite3\n"
        "            import os as _os\n"
        '            _db = _os.path.join(self.cachedir, "cve.db")\n'
        "            _conn = _sqlite3.connect(_db)\n"
        "            try:\n"
        "                _cur = _conn.cursor()\n"
        '                _cur.execute("CREATE TABLE IF NOT EXISTS metrics '
        '(metrics_id INTEGER, metrics_name TEXT, PRIMARY KEY(metrics_id))")\n'
        '                _cur.execute("INSERT OR IGNORE INTO metrics '
        "(metrics_id, metrics_name) VALUES (1, 'EPSS')\")\n"
        "                _conn.commit()\n"
        "                await self.update_epss(_cur)\n"
        "            finally:\n"
        "                _conn.close()\n"
        "        except Exception as e:\n"
        '            self.LOGGER.debug(f"Error while fetching EPSS data: {e}")\n'
        '            self.LOGGER.error("Unable to fetch EPSS, skipping EPSS.")\n'
    )
    return _replace_once(path, old, new, marker="PATCH(el-sca): EPSS is broken two ways")


def main() -> int:
    results = {
        "cvedb_metrics_ordering": fix_cvedb_metrics_ordering(),
        "epss": fix_epss(),
    }
    print("[cve-bin-tool 3.4 fixups]", results)
    if all(v == "already-patched" for v in results.values()) and os.environ.get(
        "CVEBT_PATCH_STRICT"
    ):
        print("WARNING: every fix already applied -- unexpected on a clean install", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
