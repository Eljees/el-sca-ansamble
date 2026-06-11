"""``route-plan`` — pick a working egress per tool *from inside the stack* and
emit a plan the updaters can consume (ADR-0007 Phase 2: "updates from anywhere").

``update_doctor`` already answers *"which route is alive from here?"* as a
read-only matrix.  ``route_plan`` is the **actionable** counterpart: it runs the
same adaptive probing, but

1. it is meant to run **inside** ``scanner-net`` (the ``route-doctor`` compose
   service), so it also probes the in-network sidecars (``tinyproxy:8888`` HTTP
   front, ``proxy-xray:1080`` SOCKS) and the host's local proxy
   (``host.docker.internal:<port>``) — exactly the endpoints a scanner container
   can actually reach;
2. it produces a **per-tool plan** and writes two artefacts:
     * ``artifacts/route-plan.json`` — full machine-readable decision + matrix;
     * ``artifacts/route-plan.env``  — ``KEY=value`` lines the updater
       containers source to route their fetch through the chosen proxy.

The single hard constraint encoded here: **cve-bin-tool cannot use a SOCKS
proxy** (its Python client only honours ``HTTP_PROXY``/``HTTPS_PROXY``).  So for
cve-bin-tool the plan always selects an ``http://`` transport — the tinyproxy
front (``http://tinyproxy:8888``) when the sidecar stack is up, or a host HTTP
proxy — and never a bare ``socks5://`` URL.  Trivy/Grype (Go ``net/http`` +
``ALL_PROXY``) can take either.

The network probe is injected (``Prober``/``TcpOpener``), so plan construction is
fully unit-testable without a network — same pattern as ``update_doctor``.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    from datetime import UTC  # py3.11+
except ImportError:  # pragma: no cover - py3.10 fallback
    from datetime import timezone as _tz

    UTC = _tz.utc  # noqa: UP017
from datetime import datetime

from .update_doctor import (
    Prober,
    TcpOpener,
    _TOOL_LAYERS,
    _sources_for,
    default_prober,
    discover_transports,
    enumerate_chains,
    tcp_open,
)

_OK_STATUSES = {"ok", "local"}

# Sidecar endpoints reachable from *inside* scanner-net (compose profile
# ``proxy``).  These are the stable, single-place egress the whole stack shares.
_SIDECAR_HTTP = "http://tinyproxy:8888"
_SIDECAR_SOCKS = "socks5h://proxy-xray:1080"

# Loopback proxy ports commonly exposed by v2rayN / xray / sing-box / Tor on the
# host; from a container they live behind ``host.docker.internal``.
_COMMON_HOST_PROXY_PORTS: tuple[int, ...] = (10808, 1080, 10809, 1081, 2080, 2081, 8889, 7890, 8118, 9150)

# Env var cve-bin-tool's updater reads for its HTTP enrichment bridge
# (scripts/update_cve_bin_tool.sh: CVE_BIN_TOOL_ENRICH_PROXY).
_CVE_BIN_TOOL_HTTP_ENV = "CVE_BIN_TOOL_ENRICH_PROXY"


def _is_http(url: str | None) -> bool:
    return bool(url) and urlparse(url).scheme in ("http", "https")


def _transport_url(proxies: dict[str, str]) -> str | None:
    return proxies.get("https") or proxies.get("http")


def discover_container_transports(
    config: dict[str, Any],
    *,
    opener: TcpOpener = tcp_open,
    sidecars: bool = True,
) -> dict[str, dict[str, str]]:
    """Candidate egress routes a scanner *container* can use, newest-first.

    Superset of :func:`update_doctor.discover_transports` plus the in-network
    sidecars and the host's local proxy reached via ``host.docker.internal``.
    Only endpoints that actually accept a TCP connection are offered, so the
    plan never points an updater at a dead proxy.
    """
    no_proxy = (config.get("proxy") or {}).get("no_proxy")
    transports: dict[str, dict[str, str]] = dict(enumerate_chains(config))

    # In-network sidecars (profile "proxy"): probe before offering them.
    if sidecars:
        if opener("tinyproxy", 8888, 1.5):
            transports["sidecar-http"] = _with_no_proxy(
                {"http": _SIDECAR_HTTP, "https": _SIDECAR_HTTP}, no_proxy
            )
        if opener("proxy-xray", 1080, 1.5):
            transports["sidecar-socks"] = _with_no_proxy(
                {"http": _SIDECAR_SOCKS, "https": _SIDECAR_SOCKS}, no_proxy
            )

    # Host's own local proxy (v2rayN/xray/sing-box) via host.docker.internal.
    for port in _COMMON_HOST_PROXY_PORTS:
        if opener("host.docker.internal", port, 1.0):
            socks = f"socks5h://host.docker.internal:{port}"
            http = f"http://host.docker.internal:{port}"
            transports[f"host-socks:{port}"] = _with_no_proxy({"http": socks, "https": socks}, no_proxy)
            transports[f"host-http:{port}"] = _with_no_proxy({"http": http, "https": http}, no_proxy)

    # The plain env-var / direct route stays a candidate (last resort).
    transports.setdefault("direct", {"no_proxy": no_proxy} if no_proxy else {})
    return transports


def _with_no_proxy(proxies: dict[str, str], no_proxy: str | None) -> dict[str, str]:
    if no_proxy:
        return {**proxies, "no_proxy": no_proxy}
    return proxies


def build_plan(
    config: dict[str, Any],
    *,
    prober: Prober | None = None,
    opener: TcpOpener = tcp_open,
    timeout: float = 6.0,
    sidecars: bool = True,
) -> dict[str, Any]:
    """Probe every tool's sources across every container-reachable transport.

    Returns ``{"transports", "rows", "plan", "generated_utc"}`` where ``plan`` maps
    each tool to ``{"transport", "proxy_url", "socks_ok", "reason"}``.  For
    cve-bin-tool ``proxy_url`` is guaranteed HTTP (or ``None`` for direct).
    """
    probe = prober or default_prober
    transports = discover_container_transports(config, opener=opener, sidecars=sidecars)
    order = list(transports.keys())

    rows: list[dict[str, Any]] = []
    for tool, layers in _TOOL_LAYERS.items():
        for layer in layers:
            for src in _sources_for(config, tool, layer):
                cells = {name: probe(src.url, prox, timeout) for name, prox in transports.items()}
                rows.append({"tool": tool, "layer": layer, "source": src.name, "url": src.url, "chains": cells})

    plan: dict[str, dict[str, Any]] = {}
    for tool in _TOOL_LAYERS:
        plan[tool] = _select_for_tool(tool, rows, order, transports)

    return {
        "generated_utc": datetime.now(UTC).isoformat(),
        "transports": order,
        "rows": rows,
        "plan": plan,
    }


def _select_for_tool(
    tool: str,
    rows: list[dict[str, Any]],
    order: list[str],
    transports: dict[str, dict[str, str]],
) -> dict[str, Any]:
    """Pick the best transport for *tool*, honouring the HTTP-only constraint.

    Preference order:
      1. A non-``direct`` transport that reaches a source. For cve-bin-tool only
         HTTP transports are eligible; SOCKS-only ones are skipped.
      2. ``direct`` if it reaches a source (no proxy needed here).
      3. ``None`` — nothing reachable; updater falls back to its own behaviour.
    """
    tool_rows = [r for r in rows if r["tool"] == tool]
    http_only = tool == "cve_bin_tool"

    def reaches(name: str) -> bool:
        return any(r["chains"].get(name, {}).get("status") in _OK_STATUSES for r in tool_rows)

    # 1. proxied transports first, ranked by how many distinct working routes
    #    pick them (popularity tie-break favours the shared sidecar).
    proxied = [n for n in order if n != "direct" and _transport_url(transports.get(n, {}))]
    chosen: str | None = None
    for name in proxied:
        url = _transport_url(transports[name])
        if http_only and not _is_http(url):
            continue
        if reaches(name):
            chosen = name
            break

    if chosen is None and reaches("direct"):
        return {"transport": "direct", "proxy_url": None, "socks_ok": not http_only, "reason": "direct route works"}

    if chosen is None:
        return {"transport": None, "proxy_url": None, "socks_ok": not http_only, "reason": "no reachable route"}

    url = _transport_url(transports[chosen])
    return {
        "transport": chosen,
        "proxy_url": url,
        "socks_ok": _is_http(url) or not http_only,
        "reason": f"reaches a source via {chosen}",
    }


def render_env(plan: dict[str, Any]) -> str:
    """Render the ``route-plan.env`` body the updater containers source.

    Variables:
      * ``HTTP_PROXY`` / ``HTTPS_PROXY`` — the HTTP transport (used by every
        tool that honours these; safe for cve-bin-tool because it is HTTP).
      * ``ALL_PROXY`` — a SOCKS transport, set ONLY when trivy/grype were routed
        through SOCKS (Go honours it; cve-bin-tool's updater explicitly clears
        ALL_PROXY before calling NVD, so this never breaks it).
      * ``CVE_BIN_TOOL_ENRICH_PROXY`` — the HTTP bridge for cve-bin-tool.
      * ``ROUTE_PLAN_*`` — provenance: which transport each tool got.
    """
    tools = plan.get("plan", plan)
    lines = [
        "# Generated by `resilient_updates.cli route-plan`. Source this before updaters.",
        f"# generated_utc={plan.get('generated_utc', '')}",
    ]

    cve = tools.get("cve_bin_tool", {})
    cve_http = cve.get("proxy_url") if _is_http(cve.get("proxy_url")) else None

    # HTTP_PROXY: prefer cve-bin-tool's HTTP route (it is the strict one); else
    # any tool's HTTP route.
    http_url = cve_http
    if http_url is None:
        for t in ("trivy", "grype"):
            u = tools.get(t, {}).get("proxy_url")
            if _is_http(u):
                http_url = u
                break

    # ALL_PROXY (SOCKS): from trivy/grype only.
    socks_url = None
    for t in ("trivy", "grype"):
        u = tools.get(t, {}).get("proxy_url")
        if u and not _is_http(u):
            socks_url = u
            break

    if http_url:
        lines += [f"HTTP_PROXY={http_url}", f"HTTPS_PROXY={http_url}"]
        lines += [f"http_proxy={http_url}", f"https_proxy={http_url}"]
    if socks_url:
        lines += [f"ALL_PROXY={socks_url}", f"all_proxy={socks_url}"]
    if cve_http:
        lines.append(f"{_CVE_BIN_TOOL_HTTP_ENV}={cve_http}")

    for tool, sel in tools.items():
        lines.append(f"ROUTE_PLAN_{tool.upper()}={sel.get('transport') or 'none'}")
    return "\n".join(lines) + "\n"


def write_plan(
    plan: dict[str, Any],
    *,
    artifacts_dir: str | Path = "artifacts",
    json_name: str = "route-plan.json",
    env_name: str = "route-plan.env",
) -> dict[str, Path]:
    """Persist ``route-plan.json`` and ``route-plan.env`` under *artifacts_dir*."""
    base = Path(artifacts_dir)
    base.mkdir(parents=True, exist_ok=True)
    json_path = base / json_name
    env_path = base / env_name
    json_path.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    env_path.write_text(render_env(plan), encoding="utf-8")
    return {"json": json_path, "env": env_path}


def write_xray_config(
    plan: dict[str, Any],
    *,
    template_path: str | Path = "configs/xray/config.json",
    out_path: str | Path = "configs/xray/config.gen.json",
    opener: TcpOpener = tcp_open,
) -> dict[str, Any] | None:
    """Point the xray sidecar's ``upstream`` outbound at whatever egress is live.

    The xray sidecar is the single in-network place where the outbound chain is
    decided.  Its committed ``config.json`` hard-codes the upstream at
    ``host.docker.internal:10808``; if the operator's local proxy listens on a
    different port (or is absent), that outbound is dead and the whole
    ``sidecar-*`` route fails.  This rewrites the ``upstream`` outbound to the
    first live host proxy, or to ``freedom`` (direct) when no host proxy answers,
    and writes ``config.gen.json``.  Mount it over ``config.json`` (see
    ``docker-compose.route-doctor.yml``) so a plain ``xray`` restart picks it up.

    Returns the chosen upstream descriptor, or ``None`` if the template is
    missing.  Pure host-port detection is injected via *opener* for tests.
    """
    tpl = Path(template_path)
    if not tpl.is_file():
        return None
    config = json.loads(tpl.read_text(encoding="utf-8"))

    # Find a live host proxy port (same order as container transport discovery).
    host_port: int | None = None
    host_scheme = "socks"
    for port in _COMMON_HOST_PROXY_PORTS:
        if opener("host.docker.internal", port, 1.0):
            host_port = port
            # 8118 is conventionally an HTTP proxy port; everything else SOCKS.
            host_scheme = "http" if port == 8118 else "socks"
            break

    outbounds = config.get("outbounds", [])
    upstream = next((o for o in outbounds if o.get("tag") == "upstream"), None)
    if upstream is None:
        upstream = {"tag": "upstream"}
        outbounds.insert(0, upstream)
        config["outbounds"] = outbounds

    if host_port is None:
        # No host proxy — make "upstream" a direct egress so the chain still
        # carries traffic (out the docker bridge) instead of black-holing.
        chosen = {"mode": "direct"}
        upstream.clear()
        upstream.update({"tag": "upstream", "protocol": "freedom", "settings": {}})
    elif host_scheme == "http":
        chosen = {"mode": "http", "host": "host.docker.internal", "port": host_port}
        upstream.clear()
        upstream.update(
            {
                "tag": "upstream",
                "protocol": "http",
                "settings": {"servers": [{"address": "host.docker.internal", "port": host_port}]},
            }
        )
    else:
        chosen = {"mode": "socks", "host": "host.docker.internal", "port": host_port}
        upstream.clear()
        upstream.update(
            {
                "tag": "upstream",
                "protocol": "socks",
                "settings": {"servers": [{"address": "host.docker.internal", "port": host_port}]},
            }
        )

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    chosen["written"] = str(out)
    return chosen


def format_plan(plan: dict[str, Any]) -> str:
    """Human-readable summary for the CLI text output."""
    tools = plan.get("plan", {})
    transports = plan.get("transports", [])
    lines = ["# route-plan — chosen egress per tool"]
    lines.append("# candidate transports: " + (", ".join(transports) or "(none)"))
    for tool, sel in tools.items():
        t = sel.get("transport") or "NO ROUTE"
        url = sel.get("proxy_url") or "(direct)"
        lines.append(f"  {tool:14s} -> {t:18s} {url}   [{sel.get('reason', '')}]")
    return "\n".join(lines)


def chosen_proxy_for_tool(plan: dict[str, Any], tool: str) -> str | None:
    """Convenience accessor used by the MCP bridge / run-scan glue."""
    return (plan.get("plan", {}).get(tool) or {}).get("proxy_url")


def _recommended_overall(plan: dict[str, Any]) -> str | None:
    """The transport that the most tools chose (excluding direct/none)."""
    picks = Counter(
        sel.get("transport")
        for sel in plan.get("plan", {}).values()
        if sel.get("transport") and sel.get("transport") != "direct"
    )
    if not picks:
        return None
    return picks.most_common(1)[0][0]


def load_env_file(path: str | Path) -> dict[str, str]:
    """Parse a ``route-plan.env`` file into a dict (for tests / re-injection)."""
    out: dict[str, str] = {}
    p = Path(path)
    if not p.is_file():
        return out
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def apply_env_to_os(env: dict[str, str]) -> None:  # pragma: no cover - thin wrapper
    """Set the proxy vars from a parsed plan env into ``os.environ``."""
    for k, v in env.items():
        if v:
            os.environ[k] = v


__all__ = [
    "build_plan",
    "chosen_proxy_for_tool",
    "discover_container_transports",
    "format_plan",
    "load_env_file",
    "render_env",
    "write_plan",
    "write_xray_config",
]
