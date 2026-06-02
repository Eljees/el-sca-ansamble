"""Tests for resilient_updates.update_doctor (ADR-0007 P1, reachability matrix).

The network probe is injected, so these run without any network access.
"""

from __future__ import annotations

from copy import deepcopy

from resilient_updates.config import load_config
from resilient_updates.update_doctor import (
    _probe_url_for,
    build_matrix,
    enumerate_chains,
    format_matrix,
)


def _cfg():
    config = deepcopy(load_config("tests/fixtures/feed_sources.example.yaml"))
    config["proxy"] = {
        "no_proxy": "localhost",
        "chains": {
            "corp": {"hops": [{"url": "http://corp-proxy:8080"}]},
            "via-vpn": {"hops": [{"url": "socks5://127.0.0.1:1080"}]},
        },
    }
    return config


def _prober(*, corp_ok=True):
    def prober(url, proxies, timeout):
        if proxies.get("http", "").startswith("http://corp-proxy"):
            return {"status": "ok" if corp_ok else "timeout", "code": 200 if corp_ok else None}
        return {"status": "timeout", "code": None}

    return prober


def test_enumerate_chains_includes_direct():
    chains = enumerate_chains(_cfg())
    assert "corp" in chains
    assert "via-vpn" in chains
    assert "direct" in chains  # baseline route always present


def test_probe_url_for_rewrites_oci_and_skips_local():
    assert _probe_url_for("oci://ghcr.io/aquasecurity/trivy-db:2") == "https://ghcr.io/v2/"
    assert _probe_url_for("https://mirror/x") == "https://mirror/x"
    assert _probe_url_for("file:///c/x") is None


def test_matrix_shape_and_recommends_reachable_chain():
    matrix = build_matrix(_cfg(), prober=_prober(corp_ok=True))
    assert matrix["rows"]
    # every row probed against every chain
    for row in matrix["rows"]:
        assert {"corp", "via-vpn", "direct"} <= set(row["chains"])
    # corp is first in order and the only reachable chain -> recommended
    assert matrix["recommended"]["trivy"] == "corp"


def test_matrix_recommends_none_when_unreachable():
    matrix = build_matrix(_cfg(), prober=_prober(corp_ok=False))
    assert matrix["recommended"]["trivy"] is None


def test_format_matrix_human_readable():
    out = format_matrix(build_matrix(_cfg(), prober=_prober()))
    assert "update-doctor" in out
    assert "Recommended route per tool" in out
