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
EPSS (epss_source.py) has two bugs that both keep the source at count 0:

  1. ``get_cve_data`` calls ``await self.update_epss()`` but the method is
     ``update_epss(self, cursor)`` -- a hard ``TypeError`` every run.
  2. Ordering: ``cvedb.get_data`` fetches all sources (``get_cve_data``) *before*
     ``cvedb.populate_metrics`` inserts the ``(1,"EPSS")`` row, so
     ``EPSS_id_finder`` selects from an empty ``metrics`` table and IndexErrors.

Both are swallowed and surface only as "Unable to fetch EPSS, skipping".

Fix: give ``get_cve_data`` a cursor onto the cve.db AND ensure the EPSS metric
row exists first -- using cve-bin-tool's OWN constant (``populate_metrics``
hardcodes ``(1, "EPSS")``), so nothing is guessed and the later
``store_epss_data`` writes under the same id.  Reuses cve-bin-tool's own
download/parse/store.  Worst case (no cve.db) degrades to the prior skip.
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
        "                _conn.commit()  # PATCH(el-sca): persist ingested rows (close() alone rolls back)\n"
        "            finally:\n"
        "                _conn.close()\n"
        "        except Exception as e:\n"
        '            self.LOGGER.debug(f"Error while fetching EPSS data: {e}")\n'
        '            self.LOGGER.error("Unable to fetch EPSS, skipping EPSS.")\n'
    )
    return _replace_once(path, old, new, marker="PATCH(el-sca): EPSS is broken two ways")


def main() -> int:
    results = {"epss": fix_epss()}
    print("[cve-bin-tool 3.4 fixups]", results)
    if all(v == "already-patched" for v in results.values()) and os.environ.get(
        "CVEBT_PATCH_STRICT"
    ):
        print("WARNING: every fix already applied -- unexpected on a clean install", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
