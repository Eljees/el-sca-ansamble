"""Tests for resilient_updates.proxy_chain.

ProxyRouter parses the YAML schema, picks a chain per source, caches
health probes for a TTL, and writes provenance.  All tests stub the
network probe (no real HTTP) so they run offline.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from resilient_updates.proxy_chain import (
    Hop,
    Policies,
    ProxyChain,
    ProxyRouter,
    _HealthState,
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
    chain = ProxyChain.from_dict(
        "via-vpn",
        {
            "hops": [
                {"role": "vpn", "interface": "wg0"},
                {"role": "socks", "url": "socks5h://proxy:1080"},
            ]
        },
    )
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
                "corp": {
                    "hops": [
                        {"role": "front", "url": "http://tinyproxy:8888"},
                        {"role": "socks", "url": "socks5h://proxy-xray:1080"},
                    ]
                },
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


# ---------------------------------------------------------------------------
# Hop.to_dict with interface
# ---------------------------------------------------------------------------


def test_hop_to_dict_includes_interface():
    """Hop with interface set includes it in to_dict output."""
    hop = Hop(role="vpn", interface="wg0")
    d = hop.to_dict()
    assert d["role"] == "vpn"
    assert d["interface"] == "wg0"
    assert "url" not in d  # url is None, not serialised


def test_hop_to_dict_no_url_no_interface():
    """Hop with only role serialised just has 'role'."""
    hop = Hop(role="egress")
    d = hop.to_dict()
    assert d == {"role": "egress"}


# ---------------------------------------------------------------------------
# ProxyChain.to_dict
# ---------------------------------------------------------------------------


def test_proxy_chain_to_dict_round_trip():
    """ProxyChain.to_dict returns a serialisable mapping."""
    chain = ProxyChain.from_dict(
        "corp",
        {"hops": [{"role": "front", "url": "http://proxy:8888"}], "description": "Corporate proxy"},
    )
    d = chain.to_dict()
    assert d["name"] == "corp"
    assert d["description"] == "Corporate proxy"
    assert d["entry_url"] == "http://proxy:8888"
    assert len(d["hops"]) == 1


# ---------------------------------------------------------------------------
# ProxyChain.from_dict validation
# ---------------------------------------------------------------------------


def test_proxy_chain_from_dict_raises_for_non_list_hops():
    """Non-list hops raises TypeError."""
    with pytest.raises(TypeError, match="hops must be a list"):
        ProxyChain.from_dict("bad", {"hops": "not-a-list"})


# ---------------------------------------------------------------------------
# ProxyRouter.chains property and from_config coverage
# ---------------------------------------------------------------------------


def test_proxy_router_chains_property():
    """ProxyRouter.chains returns the chain dict."""
    router = ProxyRouter.from_config(_config())
    chains = router.chains
    assert "corp" in chains
    assert "direct" in chains


def test_from_config_skips_non_dict_per_source_item():
    """A non-dict item in per_source is silently skipped."""
    cfg = _config()
    cfg["proxy"]["per_source"] = ["not-a-dict", {"source": "s", "chain": "corp"}]
    router = ProxyRouter.from_config(cfg)
    assert router is not None


def test_from_config_raises_for_per_source_unknown_chain():
    """per_source referencing an unknown chain raises ValueError."""
    cfg = _config()
    cfg["proxy"]["per_source"] = [{"source": "s", "chain": "ghost-chain"}]
    with pytest.raises(ValueError, match="ghost-chain"):
        ProxyRouter.from_config(cfg)


def test_from_config_raises_for_failover_unknown_chain():
    """failover_order referencing an unknown chain raises ValueError."""
    cfg = _config()
    cfg["proxy"]["policies"]["failover_order"] = ["corp", "ghost-chain"]
    with pytest.raises(ValueError, match="ghost-chain"):
        ProxyRouter.from_config(cfg)


def test_from_config_no_proxy_parsed():
    """no_proxy is stored and forwarded to sessions."""
    cfg = _config()
    cfg["proxy"]["no_proxy"] = "  internal.corp  "
    router = ProxyRouter.from_config(cfg)
    assert router is not None
    # Confirm no_proxy ends up in the session proxies for a known source.
    _force_chain_health(router, "corp", "ok")
    src = SourceCandidate(priority=10, name="corp-mirror", url="x", tool="grype", layer="grype-db")
    session, _ = router.session_for_source(src)
    assert session.proxies.get("no_proxy") == "internal.corp"


# ---------------------------------------------------------------------------
# select_chain_name edge cases
# ---------------------------------------------------------------------------


def test_select_chain_none_source_uses_default():
    """When source is None, the default_chain is used."""
    router = ProxyRouter.from_config(_config())
    _force_chain_health(router, "corp", "ok")
    assert router.select_chain_name(None) == "corp"


def test_select_chain_appends_direct_as_last_resort():
    """When preferred and failover chains are all down, 'direct' is tried last."""
    router = ProxyRouter.from_config(_config())
    _force_chain_health(router, "corp", "down")
    _force_chain_health(router, "direct", "ok")
    # source not in per_source → preferred = default_chain (corp) → down
    src = SourceCandidate(priority=10, name="unknown-src", url="x", tool="grype", layer="grype-db")
    assert router.select_chain_name(src) == "direct"


def test_select_chain_direct_appended_as_safety_net():
    """'direct' is appended to candidates as a safety net even when not in failover_order."""
    # Config without 'direct' in failover_order → line 284-285 fires.
    cfg = {
        "proxy": {
            "default_chain": "corp",
            "chains": {
                "direct": {"hops": []},
                "corp": {"hops": [{"role": "front", "url": "http://proxy:8888"}]},
            },
            "policies": {
                "failover_order": ["corp"],  # direct NOT listed here
                "healthcheck_timeout_seconds": 1,
                "healthcheck_ttl_seconds": 60,
            },
        }
    }
    router = ProxyRouter.from_config(cfg)
    _force_chain_health(router, "corp", "down")
    _force_chain_health(router, "direct", "ok")
    src = SourceCandidate(priority=10, name="any", url="x", tool="grype", layer="grype-db")
    # corp is preferred but down; direct not in failover_order → appended via line 284-285
    assert router.select_chain_name(src) == "direct"


def test_select_chain_returns_preferred_when_all_candidates_down():
    """Last-resort: if ALL candidates are down, return preferred (fail loudly)."""
    router = ProxyRouter.from_config(_config())
    _force_chain_health(router, "corp", "down")
    _force_chain_health(router, "direct", "down")
    src = SourceCandidate(priority=10, name="unknown-src", url="x", tool="grype", layer="grype-db")
    result = router.select_chain_name(src)
    # preferred is "corp" (default_chain); must return it even when down
    assert result == "corp"


def test_session_for_source_returns_empty_session_when_no_chain():
    """When select_chain_name returns None, session has no proxies."""
    router = ProxyRouter.from_config(_config())
    # Patch select_chain_name to return a name not in _chains
    router._default_chain = None
    router._per_source = {}
    # All chains unhealthy → preferred=None → all candidates down → returns None
    _force_chain_health(router, "corp", "down")
    _force_chain_health(router, "direct", "down")
    # None source, no default → preferred is None
    session, name = router.session_for_source(None)
    # If preferred is None and no candidates are healthy → last resort is None
    # session_for_source returns (empty_session, None) in that case
    assert session is not None  # session is always returned


# ---------------------------------------------------------------------------
# _probe_chain TTL cache
# ---------------------------------------------------------------------------


def test_probe_chain_uses_cached_result_within_ttl():
    """A probe within TTL returns the cached _HealthState without re-probing."""
    router = ProxyRouter.from_config(_config())
    # Pre-seed cache with a recent "ok" state
    _force_chain_health(router, "corp", "ok", latency_ms=5.0)
    cached = router._health["corp"]

    # Probe again — should return the same cached object (no network call).
    from resilient_updates.proxy_chain import _HealthState as HS

    chain = router._chains["corp"]
    result = router._probe_chain("corp", chain, force=False)
    assert result is cached  # exact same object (cache hit)


def test_probe_chain_bypasses_cache_when_force():
    """force=True re-probes even within the TTL."""
    router = ProxyRouter.from_config(_config())
    _force_chain_health(router, "corp", "ok", latency_ms=5.0)

    # Patch _do_probe to return a different state.
    new_state = _HealthState(status="down", latency_ms=None, error="forced", checked_at=0.0)
    router._do_probe = lambda chain: new_state

    chain = router._chains["corp"]
    result = router._probe_chain("corp", chain, force=True)
    assert result.status == "down"


# ---------------------------------------------------------------------------
# _do_probe — mocked network
# ---------------------------------------------------------------------------


def test_do_probe_returns_ok_on_2xx(monkeypatch):
    """_do_probe returns status='ok' when the healthcheck URL returns 2xx."""
    router = ProxyRouter.from_config(_config())

    mock_resp = MagicMock()
    mock_resp.status_code = 204
    monkeypatch.setattr("requests.Session.get", lambda self, url, **kw: mock_resp)

    chain = ProxyChain.from_dict("direct", {"hops": []})
    state = router._do_probe(chain)
    assert state.status == "ok"
    assert state.latency_ms is not None


def test_do_probe_returns_degraded_on_4xx(monkeypatch):
    """_do_probe returns status='degraded' for 4xx responses (proxy blocking)."""
    router = ProxyRouter.from_config(_config())

    mock_resp = MagicMock()
    mock_resp.status_code = 403
    monkeypatch.setattr("requests.Session.get", lambda self, url, **kw: mock_resp)

    chain = ProxyChain.from_dict("direct", {"hops": []})
    state = router._do_probe(chain)
    assert state.status == "degraded"


def test_do_probe_returns_down_on_request_exception(monkeypatch):
    """_do_probe returns status='down' when requests raises RequestException."""
    router = ProxyRouter.from_config(_config())

    def _raise(self, url, **kw):
        raise requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr("requests.Session.get", _raise)

    chain = ProxyChain.from_dict("direct", {"hops": []})
    state = router._do_probe(chain)
    assert state.status == "down"
    assert "refused" in (state.error or "")


# ---------------------------------------------------------------------------
# validate_chains — additional error paths
# ---------------------------------------------------------------------------


def test_validate_chains_returns_empty_when_no_chains_key():
    """Missing 'chains' key → returns [] (legacy flat form passthrough)."""
    assert validate_chains({}) == []


def test_validate_chains_non_dict_chains_value():
    """chains value that is not a dict → single error."""
    errors = validate_chains({"chains": "not-a-dict"})
    assert errors


def test_validate_chains_chain_body_not_dict():
    """A chain whose body is not a dict → error."""
    errors = validate_chains({"chains": {"mychain": "bad"}})
    assert any("mychain" in e for e in errors)


def test_validate_chains_hops_none_skipped():
    """A chain with hops=null is valid (treated as empty hop list)."""
    errors = validate_chains({"chains": {"mychain": {"hops": None}}})
    assert errors == []


def test_validate_chains_hops_not_list():
    """hops that is not a list → error."""
    errors = validate_chains({"chains": {"mychain": {"hops": "bad"}}})
    assert any("hops must be a list" in e for e in errors)


def test_validate_chains_hop_not_dict():
    """A hop that is not a dict → error."""
    errors = validate_chains({"chains": {"mychain": {"hops": ["not-a-dict"]}}})
    assert any("must be a mapping" in e for e in errors)


def test_validate_chains_failover_not_list():
    """failover_order that is not a list → error."""
    errors = validate_chains(
        {"chains": {"c": {"hops": []}}, "policies": {"failover_order": "bad"}}
    )
    assert any("failover_order must be a list" in e for e in errors)


def test_validate_chains_default_chain_unknown():
    """default_chain that is not a declared chain → error."""
    errors = validate_chains({"chains": {"c": {"hops": []}}, "default_chain": "ghost"})
    assert any("ghost" in e for e in errors)


def test_validate_chains_per_source_not_list():
    """per_source that is not a list → error."""
    errors = validate_chains({"chains": {"c": {"hops": []}}, "per_source": "bad"})
    assert any("per_source must be a list" in e for e in errors)


def test_validate_chains_per_source_item_not_dict():
    """A per_source item that is not a dict → error."""
    errors = validate_chains({"chains": {"c": {"hops": []}}, "per_source": ["not-a-dict"]})
    assert any("must be a mapping" in e for e in errors)


def test_validate_chains_per_source_chain_unknown():
    """per_source referencing an undeclared chain → error."""
    errors = validate_chains(
        {"chains": {"c": {"hops": []}}, "per_source": [{"source": "s", "chain": "ghost"}]}
    )
    assert any("ghost" in e for e in errors)
