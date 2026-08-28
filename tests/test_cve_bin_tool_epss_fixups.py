"""Regression tests for the cve-bin-tool 3.4 EPSS backport.

Target: site-packages patched by scripts/patches/cve_bin_tool_3.4_fixups.py
(the state shipped in the cve-bin-tool image).  Offline: no network, no
Docker.  Skipped automatically when cve-bin-tool is not installed in the
current environment (it is image-local, not part of the repo requirements).

To run locally:
    python -m venv /tmp/cbt && . /tmp/cbt/bin/activate
    pip install cve-bin-tool==3.4 pytest
    python scripts/patches/cve_bin_tool_3.4_fixups.py
    pytest tests/test_cve_bin_tool_epss_fixups.py -v

Covers both bug layers of vanilla 3.4:
  layer 1: update_epss() called without its required `cursor` -> TypeError,
           swallowed silently, EPSS never loads;
  layer 2: EPSS_id_finder() read the `metrics` table during the source
           gather (cvedb.py:401), before populate_db() -> populate_metrics()
           (cvedb.py:470) seeded it.
"""

import asyncio
import inspect
import os
import sqlite3

import pytest

cvedb_mod = pytest.importorskip(
    "cve_bin_tool.cvedb", reason="cve-bin-tool is image-local (see module docstring)"
)
epss_source = pytest.importorskip("cve_bin_tool.data_sources.epss_source")

CVEDB = cvedb_mod.CVEDB
Epss_Source = epss_source.Epss_Source

EPSS_METRIC_ID = getattr(cvedb_mod, "EPSS_METRIC_ID", None)

# EPSS CSV layout: line 1 = model comment, line 2 = column header (skipped).
SAMPLE_CSV = (
    "#model_version:v2025.03.14,score_date:2026-07-15\n"
    "cve,epss,percentile\n"
    "CVE-2021-1111,0.97565,0.99923\n"
    "CVE-2022-2222,0.00042,0.05174\n"
)


def make_source(tmp_path):
    src = Epss_Source()
    src.epss_path = str(tmp_path / "epss")
    src.file_name = os.path.join(src.epss_path, "epss_scores-current.csv")
    return src


def write_sample(src, body=SAMPLE_CSV):
    os.makedirs(src.epss_path, exist_ok=True)
    with open(src.file_name, "w") as f:
        f.write(body)


def test_fixups_applied_at_all():
    """Guard: these tests are only meaningful against the PATCHED package."""
    assert EPSS_METRIC_ID is not None, (
        "cvedb.EPSS_METRIC_ID missing: run scripts/patches/"
        "cve_bin_tool_3.4_fixups.py against this environment first"
    )


def test_update_epss_needs_no_cursor():
    """Layer 1: the 3.4 call site invokes update_epss() with no arguments."""
    params = list(inspect.signature(Epss_Source.update_epss).parameters)
    assert params == ["self"]


def test_epss_id_finder_removed():
    """Layer 2: nothing may resolve the metric id from the DB mid-fetch."""
    assert not hasattr(Epss_Source, "EPSS_id_finder")


def test_fetch_phase_works_without_any_database(tmp_path, monkeypatch):
    """get_cve_data() must succeed while no cve.db exists at all.

    This is exactly the 3.4 ordering: get_data() (cvedb.py:401) runs before
    init_database()/populate_db()/populate_metrics() (cvedb.py:470).
    """
    src = make_source(tmp_path)

    async def fake_download():
        write_sample(src)

    monkeypatch.setattr(src, "download_epss_data", fake_download)

    data, name = asyncio.run(src.get_cve_data())
    assert name == "EPSS"
    assert data, "EPSS data must be fetched even though the DB does not exist yet"
    assert data[0] == ("CVE-2021-1111", EPSS_METRIC_ID, "0.97565", "0.99923")


def test_parse_uses_metric_id_constant(tmp_path):
    src = make_source(tmp_path)
    write_sample(src)
    parsed = src.parse_epss_data()
    assert {row[1] for row in parsed} == {EPSS_METRIC_ID}
    assert EPSS_METRIC_ID == 1  # must match populate_metrics()


def test_full_fresh_db_flow_end_to_end(tmp_path, monkeypatch):
    """Fetch first (no DB), then init + populate + store: rows land in cve_metrics."""
    src = make_source(tmp_path)

    async def fake_download():
        write_sample(src)

    monkeypatch.setattr(src, "download_epss_data", fake_download)
    data, _ = asyncio.run(src.get_cve_data())

    cachedir = tmp_path / "cache"
    cachedir.mkdir()
    db = CVEDB(sources=[], cachedir=str(cachedir), version_check=False)
    db.init_database()
    db.populate_metrics()
    db.store_epss_data(data)

    con = sqlite3.connect(db.dbpath)
    rows = con.execute(
        "SELECT cve_number, metric_id, metric_score FROM cve_metrics ORDER BY cve_number"
    ).fetchall()
    (metric_name,) = con.execute(
        "SELECT metrics_name FROM metrics WHERE metrics_id = ?", (EPSS_METRIC_ID,)
    ).fetchone()
    con.close()

    assert ("CVE-2021-1111", 1, 0.97565) in rows
    assert ("CVE-2022-2222", 1, 0.00042) in rows
    assert metric_name == "EPSS"


def test_total_download_failure_is_not_fatal(tmp_path, monkeypatch):
    """EPSS staying broken/offline must degrade to (None, 'EPSS'), not crash."""
    src = make_source(tmp_path)

    async def boom():
        raise RuntimeError("no network at all")

    monkeypatch.setattr(src, "download_epss_data", boom)
    data, name = asyncio.run(src.get_cve_data())
    assert (data, name) == (None, "EPSS")
