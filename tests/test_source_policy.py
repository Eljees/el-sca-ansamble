"""Tests for resilient_updates.source_policy.build_sources.

Original coverage: 1 test (priority ordering for grype).
Added here: trivy layers, cve_bin_tool, syft, disabled-source filtering,
custom_sources injection, and SourceCandidate.to_dict contract.
"""

from __future__ import annotations

import pytest

from resilient_updates.config import load_config
from resilient_updates.source_policy import SourceCandidate, build_sources


def _base_config() -> dict:
    """Minimal config dict exercisable without a real YAML file."""
    return {
        "trivy": {
            "db_repositories": [
                {"name": "trivy-p1", "url": "https://ghcr.io/aquasecurity/trivy-db", "priority": 10, "enabled": True},
                {"name": "trivy-p2", "url": "https://mirror.example/trivy-db", "priority": 20, "enabled": True},
            ],
            "java_db_repositories": [
                {"name": "java-p1", "url": "https://ghcr.io/aquasecurity/trivy-java-db", "priority": 10, "enabled": True}
            ],
            "checks_bundle_repositories": [],
            "vex_repositories": [],
        },
        "grype": {
            "upstream_update_urls": [
                {"name": "primary", "url": "https://toolbox-data.anchore.io/grype/databases/listing.json", "priority": 10, "enabled": True},
                {"name": "disabled-mirror", "url": "https://disabled.example/listing.json", "priority": 5, "enabled": False},
            ]
        },
        "cve_bin_tool": {
            "mirrors": [
                {"name": "cvebt-mirror", "url": "https://cve.circl.lu/", "priority": 10, "enabled": True}
            ]
        },
        "syft": {
            "scan_sources": ["dir", "registry"]
        },
        "custom_sources": {"entries": []},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Original test (kept intact)
# ─────────────────────────────────────────────────────────────────────────────


def test_build_sources_orders_by_priority():
    config = load_config("tests/fixtures/feed_sources.example.yaml")
    config["custom_sources"]["entries"] = [
        {
            "name": "custom-second",
            "type": "http",
            "url": "https://example.invalid/secondary",
            "tool": "grype",
            "layer": "grype-db",
            "priority": 20,
            "enabled": True,
            "trust_level": "custom",
        }
    ]
    sources = build_sources(config, "grype", "grype-db")
    assert [item.priority for item in sources] == [10, 20]
    assert sources[0].name == "primary"


# ─────────────────────────────────────────────────────────────────────────────
# Trivy layers
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.smoke
def test_trivy_db_sources_returned_in_priority_order():
    config = _base_config()
    sources = build_sources(config, "trivy", "trivy-db")
    assert len(sources) == 2
    assert sources[0].name == "trivy-p1"
    assert sources[1].name == "trivy-p2"
    assert all(s.tool == "trivy" for s in sources)
    assert all(s.layer == "trivy-db" for s in sources)


def test_trivy_java_db_layer():
    config = _base_config()
    sources = build_sources(config, "trivy", "trivy-java-db")
    assert len(sources) == 1
    assert sources[0].name == "java-p1"


def test_trivy_empty_checks_bundle():
    config = _base_config()
    assert build_sources(config, "trivy", "trivy-checks") == []


def test_trivy_empty_vex():
    config = _base_config()
    assert build_sources(config, "trivy", "trivy-vex") == []


# ─────────────────────────────────────────────────────────────────────────────
# Disabled sources are filtered out
# ─────────────────────────────────────────────────────────────────────────────


def test_disabled_grype_source_excluded():
    config = _base_config()
    sources = build_sources(config, "grype", "grype-db")
    names = [s.name for s in sources]
    assert "disabled-mirror" not in names
    assert "primary" in names


# ─────────────────────────────────────────────────────────────────────────────
# cve_bin_tool mirrors
# ─────────────────────────────────────────────────────────────────────────────


def test_cve_bin_tool_mirror_source():
    config = _base_config()
    sources = build_sources(config, "cve_bin_tool", "cve-bin-tool-mirror")
    assert len(sources) == 1
    assert sources[0].name == "cvebt-mirror"
    assert sources[0].tool == "cve_bin_tool"


# ─────────────────────────────────────────────────────────────────────────────
# Syft — auto-numbered priority
# ─────────────────────────────────────────────────────────────────────────────


def test_syft_sources_auto_priority():
    config = _base_config()
    sources = build_sources(config, "syft", "syft-scan")
    assert len(sources) == 2
    # First scan_source gets priority 10, second 20.
    assert sources[0].priority == 10
    assert sources[1].priority == 20
    assert sources[0].url == "dir"
    assert sources[1].url == "registry"


# ─────────────────────────────────────────────────────────────────────────────
# custom_sources injection
# ─────────────────────────────────────────────────────────────────────────────


def test_custom_source_injected_for_correct_tool_and_layer():
    config = _base_config()
    config["custom_sources"]["entries"] = [
        {
            "name": "my-trivy-mirror",
            "type": "oci",
            "url": "oci://registry.example/trivy-db:latest",
            "tool": "trivy",
            "layer": "trivy-db",
            "priority": 5,
            "enabled": True,
            "trust_level": "custom",
        },
        {
            "name": "other-tool-entry",
            "type": "http",
            "url": "https://grype.example/listing.json",
            "tool": "grype",
            "layer": "grype-db",
            "priority": 5,
            "enabled": True,
            "trust_level": "custom",
        },
    ]
    sources = build_sources(config, "trivy", "trivy-db")
    names = [s.name for s in sources]
    assert "my-trivy-mirror" in names
    assert "other-tool-entry" not in names
    # Priority 5 < 10/20 so it sorts first.
    assert sources[0].name == "my-trivy-mirror"


def test_disabled_custom_source_excluded():
    config = _base_config()
    config["custom_sources"]["entries"] = [
        {
            "name": "off",
            "type": "http",
            "url": "https://x.example/",
            "tool": "grype",
            "layer": "grype-db",
            "priority": 1,
            "enabled": False,
        }
    ]
    sources = build_sources(config, "grype", "grype-db")
    assert all(s.name != "off" for s in sources)


# ─────────────────────────────────────────────────────────────────────────────
# SourceCandidate.to_dict contract
# ─────────────────────────────────────────────────────────────────────────────


def test_source_candidate_to_dict_contains_required_keys():
    sc = SourceCandidate(
        priority=10,
        name="test",
        url="https://example.com",
        tool="grype",
        layer="grype-db",
    )
    d = sc.to_dict()
    for key in ("priority", "name", "url", "tool", "layer", "enabled", "trust_level"):
        assert key in d, f"missing key: {key}"


def test_source_candidate_ordering():
    low = SourceCandidate(priority=5, name="low", url="u", tool="t", layer="l")
    high = SourceCandidate(priority=50, name="high", url="u", tool="t", layer="l")
    assert low < high
