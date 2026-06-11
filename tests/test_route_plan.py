"""Tests for resilient_updates.route_plan (ADR-0007 P2, egress plan).

Network probing (Prober) and TCP detection (TcpOpener) are injected, so these
run with no network access — same pattern as test_update_doctor.
"""

from __future__ import annotations

import json
from copy import deepcopy

from resilient_updates.config import load_config
from resilient_updates.route_plan import (
    build_plan,
    chosen_proxy_for_tool,
    discover_container_transports,
    format_plan,
    load_env_file,
    render_env,
    write_plan,
    write_xray_config,
)

# Never touch real sockets.
_NO_TCP = lambda host, port, timeout=2.0: False  # noqa: E731


def _cfg():
    config = deepcopy(load_config("tests/fixtures/feed_sources.example.yaml"))
    config["proxy"] = {
        "no_proxy": "localhost",
        "chains": {
            "corp": {"hops": [{"url": "http://corp-proxy:8080"}]},
        },
    }
    return config


def _opener_sidecars(host, port, timeout=2.0):
    """Only the in-network sidecars answer."""
    return (host, port) in {("tinyproxy", 8888), ("proxy-xray", 1080)}


def _opener_host_http(host, port, timeout=2.0):
    """Only the host's HTTP proxy (8118) answers."""
    return host == "host.docker.internal" and port == 8118


def _opener_host_socks(host, port, timeout=2.0):
    return host == "host.docker.internal" and port == 10808


def _prober_via(substr: str):
    """Probe succeeds only when the transport URL contains *substr*."""

    def prober(url, proxies, timeout):
        target = proxies.get("https") or proxies.get("http") or ""
        if substr in target:
            return {"status": "ok", "code": 200}
        return {"status": "timeout", "code": None}

    return prober


def _prober_direct_only():
    def prober(url, proxies, timeout):
        if proxies.get("https") or proxies.get("http"):
            return {"status": "timeout", "code": None}
        return {"status": "ok", "code": 200}

    return prober


# --- transport discovery -----------------------------------------------------


def test_discovers_sidecars_when_up():
    t = discover_container_transports(_cfg(), opener=_opener_sidecars)
    assert "sidecar-http" in t
    assert t["sidecar-http"]["http"] == "http://tinyproxy:8888"
    assert "sidecar-socks" in t
    assert "direct" in t


def test_skips_sidecars_when_disabled():
    t = discover_container_transports(_cfg(), opener=_opener_sidecars, sidecars=False)
    assert "sidecar-http" not in t
    assert "sidecar-socks" not in t


def test_discovers_host_proxy_both_schemes():
    t = discover_container_transports(_cfg(), opener=_opener_host_socks)
    assert "host-socks:10808" in t
    assert "host-http:10808" in t
    assert t["host-socks:10808"]["https"] == "socks5h://host.docker.internal:10808"


# --- per-tool selection ------------------------------------------------------


def test_cve_bin_tool_never_gets_socks():
    # Only a SOCKS host proxy is reachable; trivy/grype may use it, but
    # cve-bin-tool must NOT (its client can't speak SOCKS) -> direct/none.
    plan = build_plan(_cfg(), prober=_prober_via("socks5h://host"), opener=_opener_host_socks)
    cve = plan["plan"]["cve_bin_tool"]
    assert cve["proxy_url"] is None or cve["proxy_url"].startswith("http://")
    # trivy is allowed to take the SOCKS route.
    assert plan["plan"]["trivy"]["proxy_url"] == "socks5h://host.docker.internal:10808"


def test_cve_bin_tool_takes_http_sidecar():
    plan = build_plan(_cfg(), prober=_prober_via("tinyproxy"), opener=_opener_sidecars)
    cve = plan["plan"]["cve_bin_tool"]
    assert cve["transport"] == "sidecar-http"
    assert cve["proxy_url"] == "http://tinyproxy:8888"


def test_direct_when_only_direct_works():
    plan = build_plan(_cfg(), prober=_prober_direct_only(), opener=_NO_TCP)
    for tool in ("trivy", "grype", "cve_bin_tool"):
        assert plan["plan"][tool]["transport"] == "direct"
        assert plan["plan"][tool]["proxy_url"] is None


def test_no_route_when_nothing_reachable():
    nothing = lambda url, proxies, timeout: {"status": "timeout", "code": None}  # noqa: E731
    plan = build_plan(_cfg(), prober=nothing, opener=_NO_TCP)
    assert plan["plan"]["trivy"]["transport"] is None


# --- env rendering -----------------------------------------------------------


def test_render_env_sets_http_for_cve_and_socks_for_others():
    plan = build_plan(_cfg(), prober=_prober_via("host"), opener=_opener_host_socks)
    env_text = render_env(plan)
    parsed = {}
    for line in env_text.splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            parsed[k] = v
    # trivy/grype routed via SOCKS -> ALL_PROXY set.
    assert parsed.get("ALL_PROXY") == "socks5h://host.docker.internal:10808"
    # cve-bin-tool stays HTTP-only: no SOCKS leaked into its bridge var.
    assert "CVE_BIN_TOOL_ENRICH_PROXY" not in parsed or parsed["CVE_BIN_TOOL_ENRICH_PROXY"].startswith(
        "http://"
    )
    assert parsed["ROUTE_PLAN_TRIVY"] == "host-socks:10808"


def test_render_env_http_bridge_for_cve():
    plan = build_plan(_cfg(), prober=_prober_via("tinyproxy"), opener=_opener_sidecars)
    parsed = load_env_file_from_text(render_env(plan))
    assert parsed["HTTP_PROXY"] == "http://tinyproxy:8888"
    assert parsed["CVE_BIN_TOOL_ENRICH_PROXY"] == "http://tinyproxy:8888"


def load_env_file_from_text(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


# --- artefacts ---------------------------------------------------------------


def test_write_plan_round_trips(tmp_path):
    plan = build_plan(_cfg(), prober=_prober_via("tinyproxy"), opener=_opener_sidecars)
    written = write_plan(plan, artifacts_dir=tmp_path)
    assert written["json"].is_file()
    assert written["env"].is_file()
    loaded = json.loads(written["json"].read_text())
    assert loaded["plan"]["cve_bin_tool"]["proxy_url"] == "http://tinyproxy:8888"
    env = load_env_file(written["env"])
    assert env["HTTP_PROXY"] == "http://tinyproxy:8888"


def test_chosen_proxy_for_tool():
    plan = build_plan(_cfg(), prober=_prober_via("tinyproxy"), opener=_opener_sidecars)
    assert chosen_proxy_for_tool(plan, "grype") == "http://tinyproxy:8888"


def test_format_plan_human_readable():
    out = format_plan(build_plan(_cfg(), prober=_prober_via("tinyproxy"), opener=_opener_sidecars))
    assert "route-plan" in out
    assert "cve_bin_tool" in out


# --- xray config generation --------------------------------------------------


def test_write_xray_config_points_at_host_proxy(tmp_path):
    tpl = tmp_path / "config.json"
    tpl.write_text(
        json.dumps(
            {
                "outbounds": [
                    {
                        "tag": "upstream",
                        "protocol": "socks",
                        "settings": {"servers": [{"address": "x", "port": 1}]},
                    },
                    {"tag": "direct", "protocol": "freedom", "settings": {}},
                ]
            }
        )
    )
    out = tmp_path / "config.gen.json"
    chosen = write_xray_config({}, template_path=tpl, out_path=out, opener=_opener_host_socks)
    assert chosen["mode"] == "socks"
    assert chosen["port"] == 10808
    gen = json.loads(out.read_text())
    up = next(o for o in gen["outbounds"] if o["tag"] == "upstream")
    assert up["settings"]["servers"][0]["port"] == 10808


def test_write_xray_config_direct_when_no_host_proxy(tmp_path):
    tpl = tmp_path / "config.json"
    tpl.write_text(json.dumps({"outbounds": [{"tag": "upstream", "protocol": "socks", "settings": {}}]}))
    out = tmp_path / "config.gen.json"
    chosen = write_xray_config({}, template_path=tpl, out_path=out, opener=_NO_TCP)
    assert chosen["mode"] == "direct"
    gen = json.loads(out.read_text())
    up = next(o for o in gen["outbounds"] if o["tag"] == "upstream")
    assert up["protocol"] == "freedom"


def test_write_xray_config_missing_template_returns_none(tmp_path):
    assert write_xray_config({}, template_path=tmp_path / "nope.json", out_path=tmp_path / "o.json") is None
