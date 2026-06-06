from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "resilient_updates" / "nvd_feed_import.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("nvd_feed_import", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shim_nvd_source_logger_aliases_logger_to_LOGGER():
    module = _load_module()

    class Dummy:
        LOGGER = object()

    src = Dummy()
    assert not hasattr(src, "logger")

    module._shim_nvd_source_logger(src)

    assert src.logger is src.LOGGER


def test_shim_nvd_source_logger_keeps_existing_logger():
    module = _load_module()

    sentinel_logger = object()
    sentinel_upper = object()

    class Dummy:
        LOGGER = sentinel_upper
        logger = sentinel_logger

    src = Dummy()
    module._shim_nvd_source_logger(src)

    assert src.logger is sentinel_logger


def test_format_data_api2_safe_handles_metricless_entries_without_crashing():
    module = _load_module()

    class Logger:
        def __init__(self):
            self.lines = []

        def debug(self, msg):
            self.lines.append(msg)

    class Dummy:
        def __init__(self):
            self.LOGGER = Logger()

        def parse_node_api2(self, node):
            return []

    src = Dummy()
    entries = [
        {
            "cve": {
                "id": "CVE-2099-0001",
                "descriptions": [{"value": "test vuln"}],
                "published": "2026-01-01T00:00:00.000",
            }
        }
    ]

    cve_data, affects_data = module._format_data_api2_safe(src, entries)

    assert affects_data == []
    assert cve_data[0]["ID"] == "CVE-2099-0001"
    assert cve_data[0]["score"] == "invalid"
