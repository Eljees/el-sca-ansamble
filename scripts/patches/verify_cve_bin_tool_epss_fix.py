#!/usr/bin/env python3
"""Build-time self-check: the patched EPSS pipeline must work, offline.

Runs in Dockerfile.cve-bin-tool right after cve_bin_tool_3.4_fixups.py and
fails the image build on any regression.  Exercises the REAL patched code
end-to-end (fetch phase with no database in existence -> init -> populate ->
store) against a canned EPSS CSV: no network involved.

Full regression suite: tests/test_cve_bin_tool_epss_fixups.py.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import sqlite3
import sys
import tempfile

CANNED_CSV = (
    "#model_version:selfcheck,score_date:2026-01-01\n"
    "cve,epss,percentile\n"
    "CVE-2021-1111,0.97565,0.99923\n"
    "CVE-2022-2222,0.00042,0.05174\n"
)


def main() -> int:
    from cve_bin_tool.cvedb import CVEDB, EPSS_METRIC_ID
    from cve_bin_tool.data_sources.epss_source import Epss_Source

    sig = list(inspect.signature(Epss_Source.update_epss).parameters)
    assert sig == ["self"], f"update_epss must take no cursor, got {sig}"
    assert not hasattr(Epss_Source, "EPSS_id_finder"), "EPSS_id_finder must be gone"
    assert EPSS_METRIC_ID == 1, "EPSS_METRIC_ID must match populate_metrics()"

    with tempfile.TemporaryDirectory() as tmp:
        src = Epss_Source()
        src.epss_path = os.path.join(tmp, "epss")
        src.file_name = os.path.join(src.epss_path, "epss_scores-current.csv")

        async def canned_download():
            os.makedirs(src.epss_path, exist_ok=True)
            with open(src.file_name, "w") as f:
                f.write(CANNED_CSV)

        src.download_epss_data = canned_download

        # Fetch phase FIRST, with no cve.db in existence -- exactly the 3.4
        # ordering that used to crash (get_data before populate_metrics).
        data, name = asyncio.run(src.get_cve_data())
        assert name == "EPSS", name
        assert data, "EPSS fetch must succeed before the DB exists"

        cache = os.path.join(tmp, "cache")
        os.makedirs(cache)
        db = CVEDB(sources=[], cachedir=cache, version_check=False)
        db.init_database()
        db.populate_metrics()
        db.store_epss_data(data)

        con = sqlite3.connect(db.dbpath)
        n = con.execute(
            "SELECT COUNT(*) FROM cve_metrics WHERE metric_id = ?",
            (EPSS_METRIC_ID,),
        ).fetchone()[0]
        (metric_name,) = con.execute(
            "SELECT metrics_name FROM metrics WHERE metrics_id = ?",
            (EPSS_METRIC_ID,),
        ).fetchone()
        con.close()
        assert n == 2, f"expected 2 EPSS rows in cve_metrics, got {n}"
        assert metric_name == "EPSS", metric_name

    print("[verify_cve_bin_tool_epss_fix] OK: patched EPSS pipeline works offline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
