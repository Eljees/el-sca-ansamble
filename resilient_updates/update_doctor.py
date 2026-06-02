"""``update-doctor`` — reachability map for DB updates from the current point.

ADR-0007 Phase 1.  Probes every ``(tool, layer)`` source across every configured
proxy chain (plus a baseline ``direct`` route) and reports which routes are alive,
with a recommended chain per tool.  Read-only.  The network probe is injectable
(:data:`Prober`), so :func:`build_matrix` is fully unit-testable without a network.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .fallback import classify_exception, classify_http_status
from .proxy_chain import ProxyChain, _proxies_for_chain, _session_from_proxies
from .source_policy import build_sources

_TOOL_LAYERS: dict[str, list[str]] = {
    "trivy": ["trivy-db", "trivy-java-db", "trivy-checks", "trivy-vex"],
    "grype": ["grype-db"],
    "cve_bin_tool": ["cve-bin-tool-mirror"],
}

# (url, proxies, timeout) -> {"status": str, "code": int | None}
Prober = Callable[[str, dict[str, str], float], dict[str, Any]]

_OK_STATUSES = {"ok", "local"}


def enumerate_chains(config: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Map every configured proxy chain (plus ``direct``) to its proxies dict."""
    section = config.get("proxy") or {}
    no_proxy = section.get("no_proxy")
    raw = section.get("chains") or {}
    chains: dict[str, dict[str, str]] = {}
    for name, body in raw.items():
        try:
            chains[name] = _proxies_for_chain(ProxyChain.from_dict(name, body), no_proxy)
        except (TypeError, ValueError, KeyError):
            continue
    chains.setdefault("direct", {"no_proxy": no_proxy} if no_proxy else {})
    return chains


def _probe_url_for(url: str) -> str | None:
    """The URL to HEAD for a reachability check, or ``None`` for local schemes."""
    if url.startswith("oci://"):
        host = url.removeprefix("oci://").split("/", 1)[0]
        return f"https://{host}/v2/"
    if url.startswith(("http://", "https://")):
        return url
    return None


def default_prober(url: str, proxies: dict[str, str], timeout: float) -> dict[str, Any]:
    probe_url = _probe_url_for(url)
    if probe_url is None:
        return {"status": "local", "code": None}
    session = _session_from_proxies(proxies)
    try:
        resp = session.head(probe_url, timeout=timeout, allow_redirects=True)
        reason = classify_http_status(resp.status_code)
        return {"status": "ok" if reason is None else reason.value, "code": resp.status_code}
    except Exception as exc:  # noqa: BLE001 — fold any transport error into a reason
        return {"status": classify_exception(exc).value, "code": None}


def build_matrix(
    config: dict[str, Any], *, prober: Prober | None = None, timeout: float = 5.0
) -> dict[str, Any]:
    """Probe every source across every chain; return the reachability matrix."""
    probe = prober or default_prober
    chains = enumerate_chains(config)
    chain_order = list(chains.keys())
    rows: list[dict[str, Any]] = []
    for tool, layers in _TOOL_LAYERS.items():
        for layer in layers:
            for src in build_sources(config, tool, layer):
                cells = {name: probe(src.url, proxies, timeout) for name, proxies in chains.items()}
                rows.append(
                    {"tool": tool, "layer": layer, "source": src.name, "url": src.url, "chains": cells}
                )
    return {"chains": chain_order, "rows": rows, "recommended": _recommend(rows, chain_order)}


def _recommend(rows: list[dict[str, Any]], chain_order: list[str]) -> dict[str, str | None]:
    """Per tool: first chain (in failover order) that reaches any of its sources."""
    rec: dict[str, str | None] = {}
    for tool in _TOOL_LAYERS:
        tool_rows = [r for r in rows if r["tool"] == tool]
        chosen: str | None = None
        for cname in chain_order:
            if any(r["chains"].get(cname, {}).get("status") in _OK_STATUSES for r in tool_rows):
                chosen = cname
                break
        rec[tool] = chosen
    return rec


def format_matrix(matrix: dict[str, Any]) -> str:
    chains = matrix["chains"]
    lines = ["# update-doctor — reachability (chains: " + ", ".join(chains) + ")"]
    for r in matrix["rows"]:
        cells = "  ".join(f"{c}:{r['chains'].get(c, {}).get('status', '?')}" for c in chains)
        lines.append(f"{r['tool']}/{r['layer']} [{r['source']}]  {cells}")
    lines.append("")
    lines.append("Recommended route per tool:")
    for tool, chain in matrix["recommended"].items():
        lines.append(f"  {tool}: {chain or 'NO REACHABLE ROUTE'}")
    return "\n".join(lines)
