"""``update-doctor`` — reachability map for DB updates from the current point.

ADR-0007 Phase 1.  Probes every ``(tool, layer)`` source across every configured
proxy chain (plus a baseline ``direct`` route) and reports which routes are alive,
with a recommended chain per tool.  Read-only.  The network probe is injectable
(:data:`Prober`), so :func:`build_matrix` is fully unit-testable without a network.
"""

from __future__ import annotations

import os
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .fallback import classify_exception
from .proxy_chain import ProxyChain, _proxies_for_chain, _session_from_proxies
from .source_policy import SourceCandidate, build_sources

_TOOL_LAYERS: dict[str, list[str]] = {
    "trivy": ["trivy-db", "trivy-java-db", "trivy-checks", "trivy-vex"],
    "grype": ["grype-db"],
    "cve_bin_tool": ["cve-bin-tool-mirror"],
}

# cve-bin-tool updates from NVD (per cve_bin_tool.nvd_modes), NOT from an OCI
# mirror — so build_sources(cve-bin-tool-mirror) is usually empty.  Map each
# declared mode to the endpoint that proves NVD is reachable from here, so
# update-doctor stops reporting a bogus "NO REACHABLE ROUTE".
_NVD_ENDPOINTS: dict[str, tuple[str, str]] = {
    "api2": ("nvd-api2", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
    "json-nvd": ("nvd-json-feeds", "https://nvd.nist.gov/feeds/json/cve/1.1/"),
    "json-mirror": ("nvd-json-mirror", "https://nvd.nist.gov/feeds/json/cve/1.1/"),
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


# ---------------------------------------------------------------------------
# Adaptive transport discovery (ADR-0007) — find the route that actually works
# here, not only the ones named in feed_sources.yaml.  TCP-connect ("ping" at
# the transport level) tells "proxy reachable" apart from "target blocked".
# ---------------------------------------------------------------------------

# Local SOCKS/HTTP proxy ports commonly used by v2rayN / xray / sing-box / Tor.
_COMMON_LOCAL_PROXY_PORTS: tuple[int, ...] = (10808, 1080, 10809, 1081, 2080, 2081, 8889, 7890, 9150)

TcpOpener = Callable[[str, int, float], bool]


def tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """True if a TCP connection to ``host:port`` succeeds within ``timeout``."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _env_proxy_transports() -> dict[str, dict[str, str]]:
    """Proxies declared via the standard environment variables (system settings)."""
    out: dict[str, dict[str, str]] = {}
    seen: set[str] = set()
    for var in ("ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        val = os.environ.get(var)
        if val and val not in seen:
            seen.add(val)
            out[f"env:{var}"] = {"http": val, "https": val}
    return out


def discover_local_proxies(
    *, ports: tuple[int, ...] = _COMMON_LOCAL_PROXY_PORTS, opener: TcpOpener = tcp_open
) -> dict[str, dict[str, str]]:
    """Scan loopback for a live local proxy (e.g. a running xray/v2rayN SOCKS)."""
    out: dict[str, dict[str, str]] = {}
    for port in ports:
        if opener("127.0.0.1", port, 1.0):
            # A v2rayN/xray "mixed" inbound speaks BOTH SOCKS5 and HTTP on the
            # same port.  Offer both so the matrix shows which one Python can
            # actually use here (HTTP needs no PySocks; socks5h resolves DNS at
            # the proxy, dodging local DNS blocks).
            socks = f"socks5h://127.0.0.1:{port}"
            http = f"http://127.0.0.1:{port}"
            out[f"local:127.0.0.1:{port}"] = {"http": socks, "https": socks}
            out[f"local-http:127.0.0.1:{port}"] = {"http": http, "https": http}
    return out


def discover_transports(config: dict[str, Any], *, opener: TcpOpener = tcp_open) -> dict[str, dict[str, str]]:
    """All candidate routes: configured chains + env proxies + live local proxies.

    This is what makes update-doctor *adaptive* — it tests the transport that
    actually exists on this host, not only the placeholder chains in the YAML.
    """
    transports = dict(enumerate_chains(config))
    transports.update(_env_proxy_transports())
    transports.update(discover_local_proxies(opener=opener))
    return transports


def _proxy_endpoint(proxies: dict[str, str]) -> tuple[str, int] | None:
    """``(host, port)`` of the proxy in ``proxies``, or ``None`` for a direct route."""
    url = proxies.get("https") or proxies.get("http")
    if not url:
        return None
    parsed = urlparse(url)
    if not parsed.hostname:
        return None
    port = parsed.port or {"http": 80, "https": 443, "socks5": 1080, "socks5h": 1080}.get(parsed.scheme, 1080)
    return parsed.hostname, int(port)


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
    # TCP "ping" the proxy first: distinguishes "this proxy is down/unreachable"
    # from "the target is blocked through an otherwise-healthy proxy".
    endpoint = _proxy_endpoint(proxies)
    if endpoint is not None and not tcp_open(endpoint[0], endpoint[1], min(timeout, 2.0)):
        return {"status": "proxy-down", "code": None}
    session = _session_from_proxies(proxies)
    try:
        # GET (stream) rather than HEAD: some registries/CDNs ignore or hang on
        # HEAD.  stream=True means only headers are read, body is never pulled.
        resp = session.get(probe_url, timeout=timeout, allow_redirects=True, stream=True)
        code = resp.status_code
        resp.close()
        # Reachability != authorization.  ANY HTTP status proves the transport
        # reached the server — a registry ``/v2/`` ping returns 401 *by design*,
        # mirrors often return 403/404 on HEAD.  Only proxy-level codes are not
        # "reached the target".
        if code == 407:
            status = "proxy-auth-required"
        elif code in (502, 503, 504):
            status = "gateway-error"
        else:
            status = "ok"
        return {"status": status, "code": code}
    except Exception as exc:
        return {"status": classify_exception(exc).value, "code": None}


def _nvd_probe_sources(config: dict[str, Any]) -> list[SourceCandidate]:
    """Synthetic probe targets for cve-bin-tool's NVD modes (see _NVD_ENDPOINTS)."""
    modes = (config.get("cve_bin_tool") or {}).get("nvd_modes") or []
    out: list[SourceCandidate] = []
    seen: set[str] = set()
    for mode in modes:
        endpoint = _NVD_ENDPOINTS.get(str(mode))
        if endpoint and endpoint[1] not in seen:
            seen.add(endpoint[1])
            name, url = endpoint
            out.append(SourceCandidate(priority=10, name=name, url=url, tool="cve_bin_tool", layer="nvd"))
    return out


def _sources_for(config: dict[str, Any], tool: str, layer: str) -> list[SourceCandidate]:
    """Configured sources, augmented with cve-bin-tool's NVD endpoints."""
    sources = list(build_sources(config, tool, layer))
    if tool == "cve_bin_tool":
        sources += _nvd_probe_sources(config)
    return sources


def build_matrix(
    config: dict[str, Any],
    *,
    prober: Prober | None = None,
    timeout: float = 5.0,
    opener: TcpOpener = tcp_open,
) -> dict[str, Any]:
    """Probe every source across every discovered transport; return the matrix.

    Transports include the configured chains **plus** adaptively-discovered
    routes (env proxies, a live local SOCKS) so the matrix reflects what
    actually works on this host.
    """
    probe = prober or default_prober
    chains = discover_transports(config, opener=opener)
    chain_order = list(chains.keys())
    rows: list[dict[str, Any]] = []
    for tool, layers in _TOOL_LAYERS.items():
        for layer in layers:
            for src in _sources_for(config, tool, layer):
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


def _translate_for_container(url: str) -> str:
    """A container can't reach the host's 127.0.0.1 — rewrite to host.docker.internal."""
    return url.replace("127.0.0.1", "host.docker.internal").replace("localhost", "host.docker.internal")


def recommended_proxy(
    config: dict[str, Any],
    *,
    prober: Prober | None = None,
    opener: TcpOpener = tcp_open,
    timeout: float = 8.0,
    for_container: bool = False,
) -> str | None:
    """Best **proxy URL** to use for updates from here (ADR-0007 P2), or ``None``.

    Picks the non-``direct`` transport recommended for the most tools and returns
    its proxy URL.  ``None`` means "no proxy needed/found" (e.g. a direct route
    already works, or nothing is reachable).  With ``for_container=True`` the URL
    is rewritten ``127.0.0.1``/``localhost`` → ``host.docker.internal`` so a
    container can reach the host's local proxy.
    """
    from collections import Counter

    transports = discover_transports(config, opener=opener)
    matrix = build_matrix(config, prober=prober, opener=opener, timeout=timeout)
    counts = Counter(name for name in matrix["recommended"].values() if name and name != "direct")
    if not counts:
        return None
    best = counts.most_common(1)[0][0]
    proxies = transports.get(best) or {}
    url = proxies.get("https") or proxies.get("http")
    if not url:
        return None
    return _translate_for_container(url) if for_container else url
