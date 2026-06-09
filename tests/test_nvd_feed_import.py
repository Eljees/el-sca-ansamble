from __future__ import annotations

import gzip
import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "resilient_updates" / "nvd_feed_import.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("nvd_feed_import", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


# ---------------------------------------------------------------------------
# Helper: build a minimal NVD 2.0 CVE entry dict
# ---------------------------------------------------------------------------


def _cve_entry(
    id: str = "CVE-2099-0001",
    description: str = "test vuln",
    published: str = "2026-01-01T00:00:00.000",
    **extra_cve_fields,
) -> dict:
    cve = {
        "id": id,
        "descriptions": [{"value": description}],
        "published": published,
        **extra_cve_fields,
    }
    return {"cve": cve}


def _make_src():
    """Minimal stub that looks like NVD_Source (only parse_node_api2 needed)."""

    class Logger:
        def __init__(self):
            self.lines: list[str] = []

        def debug(self, msg: str) -> None:
            self.lines.append(msg)

    class Dummy:
        def __init__(self):
            self.LOGGER = Logger()

        def parse_node_api2(self, node):
            return []

    return Dummy()


# ===========================================================================
# feed_names
# ===========================================================================


@pytest.mark.smoke
def test_feed_names_range():
    names = MOD.feed_names(2020, 2022, include_modified=False)
    assert names == ["nvdcve-2.0-2020", "nvdcve-2.0-2021", "nvdcve-2.0-2022"]


def test_feed_names_single_year():
    assert MOD.feed_names(2024, 2024, include_modified=False) == ["nvdcve-2.0-2024"]


def test_feed_names_include_modified():
    names = MOD.feed_names(2024, 2024, include_modified=True)
    assert names[-1] == "nvdcve-2.0-modified"
    assert len(names) == 2


def test_feed_names_no_modified():
    names = MOD.feed_names(2024, 2024, include_modified=False)
    assert "nvdcve-2.0-modified" not in names


# ===========================================================================
# _local_source
# ===========================================================================


def test_local_source_file_url():
    result = MOD._local_source("file:///workspace/nvd/feeds")
    assert result == "/workspace/nvd/feeds"


def test_local_source_posix_abs_path():
    assert MOD._local_source("/data/nvd") == "/data/nvd"


def test_local_source_windows_path():
    # e.g. "C:/data/nvd" — url[1] == ":"
    assert MOD._local_source("C:/data/nvd") == "C:/data/nvd"


def test_local_source_http_returns_none():
    assert MOD._local_source("https://nvd.nist.gov/feeds") is None


def test_local_source_relative_path_returns_none():
    # A bare relative path is treated as a URL component.
    assert MOD._local_source("nvd/local") is None


# ===========================================================================
# log
# ===========================================================================


def test_log_prints_to_stdout(capsys):
    MOD.log("[feed] hello")
    assert "[feed] hello" in capsys.readouterr().out


# ===========================================================================
# _shim_nvd_source_logger
# ===========================================================================


def test_shim_nvd_source_logger_aliases_logger_to_LOGGER():
    class Dummy:
        LOGGER = object()

    src = Dummy()
    assert not hasattr(src, "logger")

    MOD._shim_nvd_source_logger(src)

    assert src.logger is src.LOGGER


def test_shim_nvd_source_logger_keeps_existing_logger():
    sentinel_logger = object()
    sentinel_upper = object()

    class Dummy:
        LOGGER = sentinel_upper
        logger = sentinel_logger

    src = Dummy()
    MOD._shim_nvd_source_logger(src)

    assert src.logger is sentinel_logger


# ===========================================================================
# _format_data_api2_safe — entry-level branches
# ===========================================================================


def test_format_data_api2_safe_handles_metricless_entries_without_crashing():
    src = _make_src()
    entries = [_cve_entry()]

    cve_data, affects_data = MOD._format_data_api2_safe(src, entries)

    assert affects_data == []
    assert cve_data[0]["ID"] == "CVE-2099-0001"
    assert cve_data[0]["score"] == "invalid"


def test_format_data_api2_safe_skips_reject_entries():
    src = _make_src()
    entries = [_cve_entry(description="** REJECT ** Not a real CVE.")]

    cve_data, affects_data = MOD._format_data_api2_safe(src, entries)

    assert cve_data == []
    assert affects_data == []


def test_format_data_api2_safe_uses_lastmodified_over_published():
    src = _make_src()
    entries = [
        _cve_entry(
            lastModified="2026-06-01T12:00:00.000",
        )
    ]

    cve_data, _ = MOD._format_data_api2_safe(src, entries)

    assert cve_data[0]["last_modified"] == "2026-06-01T12:00:00.000"


def test_format_data_api2_safe_falls_back_to_published_when_no_lastmodified():
    src = _make_src()
    entries = [_cve_entry()]  # no lastModified key

    cve_data, _ = MOD._format_data_api2_safe(src, entries)

    assert cve_data[0]["last_modified"] == "2026-01-01T00:00:00.000"


# ===========================================================================
# _format_data_api2_safe — CVSS metrics paths
# ===========================================================================


def _entry_with_cvss31(score: float = 7.5, severity: str = "HIGH", vector: str = "CVSS:3.1/AV:N") -> dict:
    return _cve_entry(
        metrics={
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": score,
                        "baseSeverity": severity,
                        "vectorString": vector,
                    }
                }
            ]
        }
    )


def _entry_with_cvss30(score: float = 6.0, severity: str = "MEDIUM") -> dict:
    return _cve_entry(
        metrics={
            "cvssMetricV30": [
                {
                    "cvssData": {
                        "baseScore": score,
                        "baseSeverity": severity,
                        "vectorString": "CVSS:3.0/AV:N",
                    }
                }
            ]
        }
    )


def _entry_with_cvss2(score: float = 5.0, severity: str = "MEDIUM") -> dict:
    return _cve_entry(
        metrics={
            "cvssMetricV2": [
                {
                    "cvssData": {
                        "baseScore": score,
                        "baseSeverity": severity,
                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                    }
                }
            ]
        }
    )


@pytest.mark.smoke
def test_format_data_api2_safe_cvss31_parsed_correctly():
    src = _make_src()
    cve_data, _ = MOD._format_data_api2_safe(src, [_entry_with_cvss31(7.5, "HIGH")])

    row = cve_data[0]
    assert row["score"] == 7.5
    assert row["severity"] == "HIGH"
    assert row["CVSS_version"] == 3


def test_format_data_api2_safe_cvss30_parsed_correctly():
    src = _make_src()
    cve_data, _ = MOD._format_data_api2_safe(src, [_entry_with_cvss30(6.0, "MEDIUM")])

    row = cve_data[0]
    assert row["score"] == 6.0
    assert row["CVSS_version"] == 3


def test_format_data_api2_safe_cvss2_parsed_correctly():
    src = _make_src()
    cve_data, _ = MOD._format_data_api2_safe(src, [_entry_with_cvss2(5.0, "MEDIUM")])

    row = cve_data[0]
    assert row["score"] == 5.0
    assert row["CVSS_version"] == 2


def test_format_data_api2_safe_no_known_cvss_key_stays_unknown():
    """metrics section with no recognised CVSS key → score/severity stay 'unknown'."""
    src = _make_src()
    entries = [_cve_entry(metrics={"futureMetricV4": []})]

    cve_data, _ = MOD._format_data_api2_safe(src, entries)

    assert cve_data[0]["score"] == "invalid"  # 'unknown' fails float() → 'invalid'
    assert cve_data[0]["severity"] == "unknown"


# ===========================================================================
# _format_data_api2_safe — invalid severity / score sanitisation
# ===========================================================================


def test_format_data_api2_safe_invalid_severity_stripped():
    """Non-alphanumeric characters in severity are stripped via regex."""
    src = _make_src()
    entries = [
        _cve_entry(
            metrics={
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 5.0,
                            "baseSeverity": "HI!GH",  # non-alphanumeric char
                            "vectorString": "",
                        }
                    }
                ]
            }
        )
    ]
    cve_data, _ = MOD._format_data_api2_safe(src, entries)
    assert cve_data[0]["severity"] == "HIGH"


def test_format_data_api2_safe_invalid_score_becomes_invalid_string():
    """A score value of 'unknown' (not a valid float) becomes the string 'invalid'."""
    src = _make_src()
    # entries with no metrics → score defaults to "unknown" string
    cve_data, _ = MOD._format_data_api2_safe(src, [_cve_entry()])
    assert cve_data[0]["score"] == "invalid"


# ===========================================================================
# _format_data_api2_safe — configurations / affects
# ===========================================================================


def test_format_data_api2_safe_configurations_forwarded_to_parse_node():
    """parse_node_api2 is called for each node; its output appears in affects_data."""
    parsed_row = {"vendor": "acme", "product": "widget", "version": "1.0"}

    class Src:
        LOGGER = None

        def parse_node_api2(self, node):
            return [parsed_row]

    entries = [
        _cve_entry(
            configurations=[
                {
                    "nodes": [
                        {"operator": "OR", "negate": False, "cpeMatch": []},
                    ]
                }
            ]
        )
    ]

    cve_data, affects_data = MOD._format_data_api2_safe(Src(), entries)

    assert len(cve_data) == 1
    assert len(affects_data) == 1
    assert affects_data[0]["cve_id"] == "CVE-2099-0001"
    assert affects_data[0]["vendor"] == "acme"


def test_format_data_api2_safe_child_nodes_also_parsed():
    """Children inside a node are processed via parse_node_api2 as well."""
    calls: list[dict] = []

    class Src:
        LOGGER = None

        def parse_node_api2(self, node):
            calls.append(node)
            return []

    entries = [
        _cve_entry(
            configurations=[
                {
                    "nodes": [
                        {
                            "operator": "AND",
                            "children": [{"operator": "OR", "cpeMatch": []}],
                        }
                    ]
                }
            ]
        )
    ]

    MOD._format_data_api2_safe(Src(), entries)

    # One call for the parent node + one for the child = 2 total.
    assert len(calls) == 2


def test_format_data_api2_safe_no_configuration_key():
    """When 'configurations' is absent no parse_node_api2 is called."""
    calls: list[dict] = []

    class Src:
        LOGGER = None

        def parse_node_api2(self, node):
            calls.append(node)
            return []

    MOD._format_data_api2_safe(Src(), [_cve_entry()])

    assert calls == []


# ===========================================================================
# download — local file path (no network, no curl)
# ===========================================================================


def test_download_local_file_url(tmp_path: Path):
    """download() with a file:// URL copies bytes without touching the network."""
    src = tmp_path / "feed.json.gz"
    content = b"fake gzip content"
    src.write_bytes(content)

    dest = tmp_path / "dest.json.gz"
    MOD.download(f"file://{src}", timeout=10, dest=str(dest))

    assert dest.read_bytes() == content


def test_download_posix_path(tmp_path: Path):
    """download() with a bare POSIX path also copies directly."""
    src = tmp_path / "feed.json.gz"
    src.write_bytes(b"data")
    dest = tmp_path / "out.json.gz"

    MOD.download(str(src), timeout=10, dest=str(dest))

    assert dest.read_bytes() == b"data"


# ===========================================================================
# _format_data_api2_safe — legacy "impact" CVSS paths (NVD 1.x feeds)
# ===========================================================================


def test_format_data_api2_safe_legacy_impact_v3():
    """impact.baseMetricV3 path (old NVD 1.x feed format)."""
    src = _make_src()
    entries = [
        _cve_entry(
            impact={
                "baseMetricV3": {
                    "cvssV3": {
                        "baseSeverity": "CRITICAL",
                        "baseScore": 9.8,
                        "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                }
            }
        )
    ]

    cve_data, _ = MOD._format_data_api2_safe(src, entries)

    assert cve_data[0]["severity"] == "CRITICAL"
    assert cve_data[0]["score"] == 9.8
    assert cve_data[0]["CVSS_version"] == 3


def test_format_data_api2_safe_legacy_impact_v3_no_cvssV3_key():
    """impact.baseMetricV3 present but no cvssV3 sub-key → defaults to 0/UNKNOWN."""
    src = _make_src()
    entries = [_cve_entry(impact={"baseMetricV3": {}})]

    cve_data, _ = MOD._format_data_api2_safe(src, entries)

    # No cvssV3 key → score stays 0 → float(0) → 0.0 (not 'invalid')
    assert cve_data[0]["CVSS_version"] == 3
    assert cve_data[0]["score"] == "invalid"  # 'unknown' default → float fails


def test_format_data_api2_safe_configurations_with_real_logger():
    """logger.debug is called inside the configurations loop when logger is set."""
    src = _make_src()
    entries = [
        _cve_entry(
            configurations=[
                {
                    "nodes": [
                        {"operator": "OR", "negate": False, "cpeMatch": []},
                    ]
                }
            ]
        )
    ]

    cve_data, _affects_data = MOD._format_data_api2_safe(src, entries)

    # The LOGGER should have received a debug message about the node.
    debug_lines = src.LOGGER.lines
    assert any("Processing" in line for line in debug_lines), f"No Processing log: {debug_lines}"
    assert len(cve_data) == 1


def test_format_data_api2_safe_legacy_impact_v2():
    """impact.baseMetricV2 path — legacy NVD 1.x format (bugfix regression guard).

    The original code referenced ``impact["baseMetricV4"]`` (a typo) causing
    a KeyError.  After the fix it correctly reads ``impact["baseMetricV2"]``.
    """
    src = _make_src()
    entries = [
        _cve_entry(
            impact={
                "baseMetricV2": {
                    "severity": "HIGH",
                    "cvssV2": {
                        "baseScore": 7.5,
                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                    },
                }
            }
        )
    ]

    # Should NOT raise KeyError now that the typo is fixed.
    cve_data, _ = MOD._format_data_api2_safe(src, entries)

    assert cve_data[0]["CVSS_version"] == 2
    assert cve_data[0]["score"] == 7.5
    assert cve_data[0]["severity"] == "HIGH"


# ===========================================================================
# download — remote paths (mocked)
# ===========================================================================


def test_download_uses_curl_when_available(tmp_path: Path, monkeypatch):
    """download() calls subprocess.run with curl when curl is in PATH."""
    dest = tmp_path / "out.json.gz"

    # Simulate curl writing the file as a side-effect.
    def _fake_run(cmd, **kwargs):
        Path(cmd[cmd.index("-o") + 1]).write_bytes(b"curldata")

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/curl" if name == "curl" else None)
    monkeypatch.setattr("subprocess.run", _fake_run)

    MOD.download("https://nvd.nist.gov/feeds/x.json.gz", timeout=30, dest=str(dest))

    assert dest.read_bytes() == b"curldata"


def test_download_falls_back_to_urllib_when_no_curl(tmp_path: Path, monkeypatch):
    """download() uses urllib when curl is absent."""
    import io as _io

    dest = tmp_path / "out.json.gz"
    response_body = b"urllib-data"

    class _FakeResp(_io.RawIOBase):
        """Minimal file-like that shutil.copyfileobj can drain correctly."""

        def __init__(self):
            self._buf = _io.BytesIO(response_body)

        def read(self, n=-1):
            return self._buf.read(n)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

    monkeypatch.setattr("shutil.which", lambda _name: None)
    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout: _FakeResp())

    MOD.download("https://nvd.nist.gov/feeds/x.json.gz", timeout=30, dest=str(dest))

    assert dest.read_bytes() == response_body


# ===========================================================================
# main() — integration smoke tests with mocked cve_bin_tool
# ===========================================================================


def _write_gzip_feed(path: Path, n_cves: int = 1) -> None:
    """Write a minimal NVD 2.0 gzip feed file to *path*."""
    entries = [
        {
            "cve": {
                "id": f"CVE-2024-{i:04d}",
                "descriptions": [{"value": f"Test vuln {i}"}],
                "published": "2024-01-01T00:00:00.000",
            }
        }
        for i in range(n_cves)
    ]
    feed_data = {"vulnerabilities": entries}
    with gzip.open(str(path), "wb") as f:
        f.write(json.dumps(feed_data).encode())


def _patch_cve_bin_tool(monkeypatch, db_root: Path) -> None:
    """Inject fake cve_bin_tool classes into sys.modules."""
    mock_db_instance = MagicMock()
    mock_db_instance.dbpath = str(db_root / "cve.db")

    mock_cvedb_cls = MagicMock(return_value=mock_db_instance)

    mock_nvd_instance = MagicMock()
    mock_nvd_instance.LOGGER = MagicMock()
    mock_nvd_instance.parse_node_api2.return_value = []
    mock_nvd_cls = MagicMock(return_value=mock_nvd_instance)

    fake_cbt_cvedb = MagicMock()
    fake_cbt_cvedb.CVEDB = mock_cvedb_cls

    fake_cbt_nvd = MagicMock()
    fake_cbt_nvd.NVD_Source = mock_nvd_cls

    monkeypatch.setitem(sys.modules, "cve_bin_tool", MagicMock())
    monkeypatch.setitem(sys.modules, "cve_bin_tool.cvedb", fake_cbt_cvedb)
    monkeypatch.setitem(sys.modules, "cve_bin_tool.data_sources", MagicMock())
    monkeypatch.setitem(sys.modules, "cve_bin_tool.data_sources.nvd_source", fake_cbt_nvd)


def test_main_success_with_local_feed(tmp_path, monkeypatch):
    """main() returns 0 when feeds are read from a local directory and min-cves is met."""
    feed_dir = tmp_path / "feeds"
    feed_dir.mkdir()
    _write_gzip_feed(feed_dir / "nvdcve-2.0-2024.json.gz", n_cves=5)

    db_root = tmp_path / "dbcache"
    db_root.mkdir()
    _patch_cve_bin_tool(monkeypatch, db_root)

    # Use a Windows-style absolute path (no file:// prefix) as feed-base.
    feed_base = str(feed_dir).replace("\\", "/")
    monkeypatch.setattr(
        "sys.argv",
        [
            "nvd_feed_import",
            "--db-root",
            str(db_root),
            "--start-year",
            "2024",
            "--end-year",
            "2024",
            "--no-modified",
            "--feed-base",
            feed_base,
            "--min-cves",
            "1",
        ],
    )

    rc = MOD.main()
    assert rc == 0


def test_main_returns_2_when_min_cves_not_met(tmp_path, monkeypatch):
    """main() returns 2 when fewer CVEs than --min-cves are downloaded."""
    feed_dir = tmp_path / "feeds"
    feed_dir.mkdir()
    _write_gzip_feed(feed_dir / "nvdcve-2.0-2024.json.gz", n_cves=2)

    db_root = tmp_path / "dbcache"
    db_root.mkdir()
    _patch_cve_bin_tool(monkeypatch, db_root)

    feed_base = str(feed_dir).replace("\\", "/")
    monkeypatch.setattr(
        "sys.argv",
        [
            "nvd_feed_import",
            "--db-root",
            str(db_root),
            "--start-year",
            "2024",
            "--end-year",
            "2024",
            "--no-modified",
            "--feed-base",
            feed_base,
            "--min-cves",
            "9999",  # far above the 2 we provide
        ],
    )

    rc = MOD.main()
    assert rc == 2


def test_main_continues_after_feed_download_failure(tmp_path, monkeypatch):
    """main() skips missing feeds and returns 2 when entries < min-cves."""
    feed_dir = tmp_path / "feeds"
    feed_dir.mkdir()
    # Do NOT create the .json.gz file — shutil.copyfile will raise FileNotFoundError,
    # which main() catches with `except Exception` and appends to failures.

    db_root = tmp_path / "dbcache"
    db_root.mkdir()
    _patch_cve_bin_tool(monkeypatch, db_root)

    feed_base = str(feed_dir).replace("\\", "/")
    monkeypatch.setattr(
        "sys.argv",
        [
            "nvd_feed_import",
            "--db-root",
            str(db_root),
            "--start-year",
            "2024",
            "--end-year",
            "2024",
            "--no-modified",
            "--feed-base",
            feed_base,
            "--min-cves",
            "1",
        ],
    )

    rc = MOD.main()
    # All feeds failed → 0 entries < min-cves=1 → return 2
    assert rc == 2
