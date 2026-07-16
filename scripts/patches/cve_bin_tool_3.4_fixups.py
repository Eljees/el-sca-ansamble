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
EPSS (epss_source.py): ``get_cve_data`` calls ``await self.update_epss()`` but
the method signature is ``update_epss(self, cursor)`` -- a hard ``TypeError`` on
every run, swallowed and reported as "Unable to fetch EPSS".  We open a cursor
onto the already-initialised cve.db (its ``metrics`` table carries the EPSS
metric id) and pass it through.  Worst case (no cve.db yet) degrades to exactly
the prior behaviour: skip EPSS.
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
        "        # PATCH(el-sca): 3.4 calls update_epss() without the required\n"
        "        # cursor -> TypeError. Provide one from the initialised cve.db\n"
        "        # (its metrics table holds the EPSS metric id).\n"
        "        try:\n"
        "            import sqlite3 as _sqlite3\n"
        "            import os as _os\n"
        '            _db = _os.path.join(self.cachedir, "cve.db")\n'
        "            _conn = _sqlite3.connect(_db)\n"
        "            try:\n"
        "                await self.update_epss(_conn.cursor())\n"
        "            finally:\n"
        "                _conn.close()\n"
        "        except Exception as e:\n"
        '            self.LOGGER.debug(f"Error while fetching EPSS data: {e}")\n'
        '            self.LOGGER.error("Unable to fetch EPSS, skipping EPSS.")\n'
    )
    return _replace_once(path, old, new, marker="PATCH(el-sca): 3.4 calls update_epss")


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
