"""Tests for resilient_updates.proxy_chain.

ProxyRouter parses the YAML schema, picks a chain per source, caches
health probes for a TTL, and writes provenance.  All tests stub the
network probe (no real HTTP) so they run offline.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from resilient_updates.proxy_chain import (
    Hop,
    Policies,
    ProxyChain,
    ProxyRouter,
    validate_chains,
)
from resilient_updates.source_policy import SourceCandidate


# ---------------------------------------------------------------------------
# Dataclass helpers
# ---------------------------------------------------------------------------

def test_hop_from_dict_round_trip():
    raw = {"role": "front", "url": "http://tinyproxy:8888"}
    hop = Hop.from_dict(raw)
    assert hop.role == "front"
    assert hop.url == "http://tinyproxy:8888"
    assert hop.interface is None
    assert hop.to_dict()["url"] == "http://tinyproxy:8888"


def test_proxy_chain_entry_url_walks_back_to_first_url():
    chain = ProxyChain.from_dict("via-vpn", {
        "hops": [
            {"role": "vpn", "interface": "wg0"},
            {"role": "socks", "url": "socks5h://proxy:1080"},
        ]
    })
    # entry_url returns the FIRST hop with a URL — VPN hop has no URL so
    # the SOCKS one wins.
    assert chain.entry_url == "socks5h://proxy:1080"
    assert chain.has_vpn() is True


def test_policies_from_dict_uses_defaults_when_missing():
    p = Policies.from_dict({})
    assert p.healthcheck_timeout_seconds == 5
    assert p.healthcheck_ttl_seconds == 60
    assert p.failover_order == []


# ---------------------------------------------------------------------------
# Router selection
# ---------------------------------------------------------------------------

def _config():
    return {
        "proxy": {
            "default_chain": "corp",
            "chains": {
                "direct": {"hops": []},
                "corp": {"hops": [
                    {"role": "front", "url": "http://tinyproxy:8888"},
                    {"role": "socks", "url": "socks5h://proxy-xray:1080"},
                ]},
            },
            "policies": {
                "failover_order": ["corp", "direct"],
                "healthcheck_timeout_seconds": 1,
                "healthcheck_ttl_seconds": 60,
            },
            "per_source": [
                {"source": "corp-mirror", "chain": "corp"},
            ],
            "no_proxy": "localhost,127.0.0.1",
        }
    }


def _force_chain_health(router: ProxyRouter, name: str, status: str, latency_ms: float = 100.0):
    """Bypass the network probe by pre-seeding the health cache."""
    import time
    from resilient_updates.proxy_chain import _HealthState
    router._health[name] = _HealthState(
        status=status, latency_ms=latency_ms, error=None, checked_at=time.monotonic()
    )


def test_from_config_returns_none_for_legacy_flat_form():
    flat = {"proxy": {"http": "http://x:3128", "https": "http://x:3128"}}
    assert ProxyRouter.from_config(flat) is None


def test_from_config_rejects_unknown_default_chain():
    cfg = _config()
    cfg["proxy"]["default_chain"] = "nope"
    with pytest.raises(ValueError):
        ProxyRouter.from_config(cfg)


def test_select_chain_uses_per_source_pin_when_healthy():
    router = ProxyRouter.from_config(_config())
    _force_chain_health(router, "corp", "ok")
    src = SourceCandidate(priority=10, name="corp-mirror", url="x", tool="grype", layer="grype-db")
    assert router.select_chain_name(src) == "corp"


def test_select_chain_falls_through_to_next_healthy():
    router = ProxyRouter.from_config(_config())
    _force_chain_health(router, "corp", "down")
    _force_chain_health(router, "direct", "ok")
    src = SourceCandidate(priority=10, name="corp-mirror", url="x", tool="grype", layer="grype-db")
    # corp is unhealthy → failover_order says direct next.
    assert router.select_chain_name(src) == "direct"


def test_session_for_source_has_correct_proxies():
    router = ProxyRouter.from_config(_config())
    _force_chain_health(router, "corp", "ok")
    src = SourceCandidate(priority=10, name="corp-mirror", url="x", tool="grype", layer="grype-db")
    session, name = router.session_for_source(src)
    assert name == "corp"
    assert session.proxies.get("http") == "http://tinyproxy:8888"
    assert session.proxies.get("no_proxy") == "localhost,127.0.0.1"


def test_write_provenance_includes_chain_and_policy(tmp_path: Path):
    router = ProxyRouter.from_config(_config())
    _force_chain_health(router, "corp", "ok")
    _force_chain_health(router, "direct", "ok")
    out = router.write_provenance(tmp_path / "proxy.json")
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["default_chain"] == "corp"
    assert "corp" in payload["chains"]
    assert payload["policies"]["healthcheck_ttl_seconds"] == 60


# ---------------------------------------------------------------------------
# validate_chains
# ---------------------------------------------------------------------------

def test_validate_chains_clean_config_returns_no_errors():
    assert validate_chains(_config()["proxy"]) == []


def test_validate_chains_flags_unsupported_scheme():
    section = {
        "chains": {"weird": {"hops": [{"role": "front", "url": "ftp://x:21"}]}},
    }
    errors = validate_chains(section)
    assert any("ftp" in err for err in errors)


def test_validate_chains_flags_undeclared_failover_chain():
    section = {
        "chains": {"corp": {"hops": []}},
        "policies": {"failover_order": ["nope"]},
    }
    errors = validate_chains(section)
    assert any("nope" in err for err in errors)
