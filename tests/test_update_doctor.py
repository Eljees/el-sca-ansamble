"""Tests for resilient_updates.update_doctor (ADR-0007 P1, reachability matrix).

The network probe is injected, so these run without any network access.
"""

from __future__ import annotations

from copy import deepcopy

from resilient_updates.config import load_config
from resilient_updates.update_doctor import (
    _env_proxy_transports,
    _probe_url_for,
    _proxy_endpoint,
    build_matrix,
    default_prober,
    discover_local_proxies,
    enumerate_chains,
    format_matrix,
)

# Never touch real loopback sockets in tests.
_NO_LOCAL = lambda host, port, timeout=2.0: False  # noqa: E731


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


def test_matrix_shape_and_recommends_reachable_chain(monkeypatch):
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("ALL_PROXY", raising=False)
    matrix = build_matrix(_cfg(), prober=_prober(corp_ok=True), opener=_NO_LOCAL)
    assert matrix["rows"]
    for row in matrix["rows"]:
        assert {"corp", "via-vpn", "direct"} <= set(row["chains"])
    assert matrix["recommended"]["trivy"] == "corp"


def test_matrix_recommends_none_when_unreachable():
    matrix = build_matrix(_cfg(), prober=_prober(corp_ok=False), opener=_NO_LOCAL)
    assert matrix["recommended"]["trivy"] is None


def test_format_matrix_human_readable():
    out = format_matrix(build_matrix(_cfg(), prober=_prober(), opener=_NO_LOCAL))
    assert "update-doctor" in out
    assert "Recommended route per tool" in out


# --- adaptive discovery (the matrix must reflect what actually works here) ---


def test_discover_local_proxies_finds_open_port():
    # opener reports only 10808 open -> exactly one local SOCKS transport.
    def opener(host, port, timeout=2.0):
        return host == "127.0.0.1" and port == 10808

    found = discover_local_proxies(opener=opener)
    assert "local:127.0.0.1:10808" in found
    assert found["local:127.0.0.1:10808"]["https"] == "socks5h://127.0.0.1:10808"


def test_env_proxy_transports(monkeypatch):
    monkeypatch.setenv("ALL_PROXY", "socks5h://127.0.0.1:10808")
    transports = _env_proxy_transports()
    assert transports["env:ALL_PROXY"]["https"] == "socks5h://127.0.0.1:10808"


def test_proxy_endpoint_parses_socks_and_direct():
    assert _proxy_endpoint({"https": "socks5h://127.0.0.1:10808"}) == ("127.0.0.1", 10808)
    assert _proxy_endpoint({}) is None


def test_default_prober_reports_proxy_down(monkeypatch):
    # proxy endpoint present but TCP-unreachable -> proxy-down, no HTTP attempt.
    monkeypatch.setattr("resilient_updates.update_doctor.tcp_open", lambda *a, **k: False)
    result = default_prober("oci://ghcr.io/x:1", {"https": "socks5h://127.0.0.1:10808"}, 2.0)
    assert result["status"] == "proxy-down"


def test_default_prober_treats_401_as_reachable(monkeypatch):
    # A registry /v2/ ping returns 401 by design — that means REACHED, not failed.
    import resilient_updates.update_doctor as ud

    monkeypatch.setattr(ud, "tcp_open", lambda *a, **k: True)

    class _Resp:
        status_code = 401

    class _Session:
        def head(self, *a, **k):
            return _Resp()

    monkeypatch.setattr(ud, "_session_from_proxies", lambda proxies: _Session())
    result = ud.default_prober("oci://ghcr.io/x:1", {"https": "socks5h://127.0.0.1:10808"}, 2.0)
    assert result["status"] == "ok"
    assert result["code"] == 401
