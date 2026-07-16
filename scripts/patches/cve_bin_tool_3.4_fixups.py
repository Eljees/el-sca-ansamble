#!/usr/bin/env python3
"""Apply targeted fixes to cve-bin-tool 3.4's broken EPSS enrichment source.

Run at image-build time (Dockerfile.cve-bin-tool) right after
`pip install cve-bin-tool==3.4`.  3.4 is the latest PyPI release, so there is
no version to bump to; these are upstream bugs that fire on *every* machine
and every code path (proven on 10.2.108.47), which is why OSV/EPSS/PURL2CPE
were disabled via CVE_BIN_TOOL_ENRICH_DISABLE.

Wrapper-first project rule: we do NOT fork cve-bin-tool.  This patcher only
repairs the specific breakages in-place and reuses cve-bin-tool's own
download/parse/store -- so the data stays upstream's, not ours.

Each fix is idempotent and *verified*: if the exact target text is missing
(e.g. a future version moved the code), the build FAILS loudly instead of
silently shipping an unpatched image.  After patching, the offline
end-to-end check scripts/patches/verify_cve_bin_tool_epss_fix.py gates the
image build.

The bug (two layers, both proven offline: tests/test_cve_bin_tool_epss_fixups.py)
----------------------------------------------------------------------------------
1. TypeError -- ``get_cve_data()`` calls ``await self.update_epss()`` but the
   3.4 signature is ``update_epss(self, cursor)``; the broad ``except`` hides
   the crash ("Unable to fetch EPSS, skipping EPSS."), so EPSS silently never
   loads.
2. Ordering (root cause) -- even with a cursor, ``EPSS_id_finder()`` SELECTs
   from the ``metrics`` table during the source gather
   (``refresh_cache_and_update_db()`` -> ``refresh()`` -> ``get_data()``,
   cvedb.py:401), which runs BEFORE ``populate_db()`` ->
   ``populate_metrics()`` (cvedb.py:470) inserts the (1,'EPSS') row.  Fresh
   cache -> ``sqlite3.OperationalError: no such table: metrics``; created but
   still-empty table -> ``IndexError`` from ``fetchall()[0][0]``.

The fix (backport of upstream's own solution, not a local invention)
---------------------------------------------------------------------
Upstream (repo moved intel/ -> ossf/cve-bin-tool) already fixed this on
``main`` -- the "metric ids as constants" change (~PR #4473), merged in 2025
-- but never shipped a release with it: the latest tag is still v3.4 and the
latest PyPI stable is 3.4 (3.4.1rc0 of 2025-06-13 contains the fix but is an
RC).  Earlier revisions of this patcher fixed the same two layers with a
local reorder (hoisting populate_metrics() before the gather) plus a
cursor-shim; that worked, but diverged from upstream.  This revision
backports upstream's actual fix so our 3.4 behaves exactly like main /
3.4.1rc0:

* cvedb.py gains module-level constants (EPSS_METRIC_ID = 1, CVSS_2/3_...)
  and populate_metrics() uses them;
* epss_source.py: update_epss() loses the ``cursor`` parameter,
  ``EPSS_id_finder()`` is deleted, and parse_epss_data() tags rows with
  EPSS_METRIC_ID directly (lazy import to avoid a circular dependency).

After this the download phase never touches the database, so the ordering
bug disappears as a class.  On a version bump to >= 3.4.1 the targets below
will be missing and every fix reports "already-patched"/fails loudly --
at that point simply drop this file from the build.

See docs/upstream/STATUS.md for the upstream situation and the
release-request issue template.
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


def fix_cvedb_metric_constants() -> str:
    """cvedb.py: module-level metric id constants (upstream main backport)."""
    path = _cvebt_dir() / "cvedb.py"

    old_anchor = 'OLD_CACHE_DIR = Path("~") / ".cache" / "cvedb"\n'
    new_anchor = (
        'OLD_CACHE_DIR = Path("~") / ".cache" / "cvedb"\n'
        "\n"
        "# PATCH(el-sca): metric ids as module-level constants -- backport of the\n"
        "# upstream fix (ossf/cve-bin-tool main, merged 2025, unreleased).  Must\n"
        "# match the rows populate_metrics() inserts into the metrics table.\n"
        "EPSS_METRIC_ID = 1\n"
        "CVSS_2_METRIC_ID = 2\n"
        "CVSS_3_METRIC_ID = 3\n"
    )
    part1 = _replace_once(
        path,
        old_anchor,
        new_anchor,
        marker="PATCH(el-sca): metric ids as module-level constants",
    )

    old_data = (
        "        data = [\n"
        '            (1, "EPSS"),\n'
        '            (2, "CVSS-2"),\n'
        '            (3, "CVSS-3"),\n'
        "        ]\n"
    )
    new_data = (
        "        data = [\n"
        '            (EPSS_METRIC_ID, "EPSS"),\n'
        '            (CVSS_2_METRIC_ID, "CVSS-2"),\n'
        '            (CVSS_3_METRIC_ID, "CVSS-3"),\n'
        "        ]\n"
    )
    part2 = _replace_once(
        path, old_data, new_data, marker='(EPSS_METRIC_ID, "EPSS"),'
    )

    if part1 == part2 == "already-patched":
        return "already-patched"
    return "patched"


def fix_epss_source() -> str:
    """epss_source.py: no cursor, no DB reads mid-fetch (upstream main backport)."""
    path = _cvebt_dir() / "data_sources" / "epss_source.py"

    # (a) __init__: drop the now-unused epss_metric_id attribute.
    old_init = (
        '        self.file_name = os.path.join(self.epss_path, "epss_scores-current.csv")\n'
        "        self.epss_metric_id = None\n"
    )
    new_init = (
        '        self.file_name = os.path.join(self.epss_path, "epss_scores-current.csv")\n'
        "        # PATCH(el-sca): epss_metric_id attribute removed -- rows are tagged\n"
        "        # with cvedb.EPSS_METRIC_ID (upstream main backport).\n"
    )
    a = _replace_once(
        path, old_init, new_init, marker="PATCH(el-sca): epss_metric_id attribute removed"
    )

    # (b) update_epss: drop the cursor parameter -- the 3.4 call site invokes
    # update_epss() with no arguments, so every EPSS update died with a
    # swallowed TypeError.
    old_sig = "    async def update_epss(self, cursor):\n"
    new_sig = (
        "    # PATCH(el-sca): cursor parameter removed (upstream main backport).\n"
        "    async def update_epss(self):\n"
    )
    b = _replace_once(
        path, old_sig, new_sig, marker="PATCH(el-sca): cursor parameter removed"
    )

    # (c) no DB lookup during the fetch phase.
    old_fetch = (
        '        self.LOGGER.debug("Fetching EPSS data...")\n'
        "\n"
        "        self.EPSS_id_finder(cursor)\n"
        "        await self.download_epss_data()\n"
    )
    new_fetch = (
        '        self.LOGGER.debug("Fetching EPSS data...")\n'
        "\n"
        "        # PATCH(el-sca): EPSS_id_finder(cursor) call removed -- the fetch\n"
        "        # phase must not touch the database (upstream main backport).\n"
        "        await self.download_epss_data()\n"
    )
    c = _replace_once(
        path, old_fetch, new_fetch, marker="PATCH(el-sca): EPSS_id_finder(cursor) call removed"
    )

    # (d) delete the EPSS_id_finder method entirely.
    old_finder = (
        "    def EPSS_id_finder(self, cursor):\n"
        '        """Search for metric id in EPSS table"""\n'
        "        query = \"\"\"\n"
        "        SELECT metrics_id FROM metrics\n"
        '        WHERE metrics_name = "EPSS"\n'
        "        \"\"\"\n"
        "        cursor.execute(query)\n"
        "        self.epss_metric_id = cursor.fetchall()[0][0]\n"
        "\n"
    )
    new_finder = (
        "    # PATCH(el-sca): EPSS_id_finder() deleted (upstream main backport).\n"
        "\n"
    )
    d = _replace_once(
        path, old_finder, new_finder, marker="PATCH(el-sca): EPSS_id_finder() deleted"
    )

    # (e) parse_epss_data(): tag rows with the constant, not a DB-resolved id.
    old_parse = (
        "            cve_id, epss_score, epss_percentile = row[:3]\n"
        "            parsed_data.append(\n"
        "                (cve_id, self.epss_metric_id, epss_score, epss_percentile)\n"
        "            )\n"
    )
    new_parse = (
        "            cve_id, epss_score, epss_percentile = row[:3]\n"
        "\n"
        "            # PATCH(el-sca): rows tagged with the module-level constant\n"
        "            # (upstream main backport); local import avoids a circular\n"
        "            # dependency between cvedb and the data sources.\n"
        "            from cve_bin_tool.cvedb import EPSS_METRIC_ID\n"
        "\n"
        "            parsed_data.append((cve_id, EPSS_METRIC_ID, epss_score, epss_percentile))\n"
    )
    e = _replace_once(
        path, old_parse, new_parse, marker="PATCH(el-sca): rows tagged with the module-level constant"
    )

    results = (a, b, c, d, e)
    if all(r == "already-patched" for r in results):
        return "already-patched"
    return "patched"


def main() -> int:
    results = {
        "cvedb_metric_constants": fix_cvedb_metric_constants(),
        "epss_source": fix_epss_source(),
    }
    print("[cve-bin-tool 3.4 fixups]", results)
    if all(v == "already-patched" for v in results.values()) and os.environ.get(
        "CVEBT_PATCH_STRICT"
    ):
        print(
            "WARNING: every fix already applied -- unexpected on a clean install",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
