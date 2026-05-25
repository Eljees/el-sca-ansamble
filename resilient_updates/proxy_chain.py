"""Proxy chains for resilient_updates.

The legacy flat ``proxy:`` block in feed_sources.yaml works as before — it is
turned into a single anonymous chain at load time, so existing setups need no
edits.  When the YAML declares ``proxy.chains`` / ``proxy.policies`` /
``proxy.per_source`` we build the full router described in
``docs/network-design.md`` and ADR-0002:

  ProxyRouter
    ├── chains:     name → ProxyChain
    ├── per_source: source-name → chain-name
    └── policies:   failover order, healthcheck URL/TTL, retry budget

``ProxyRouter.session_for_source(source)`` returns a ``requests.Session`` whose
``proxies`` are wired according to the chain that is BOTH preferred for that
source AND currently healthy.  Health results are cached per chain for
``healthcheck_ttl_seconds`` to avoid hammering an upstream during a long scan.

The router intentionally does NOT bring up VPN tunnels itself: a hop with
``role: vpn`` is metadata only.  The healthcheck still proves that traffic
flows end-to-end through the chain, so if the WireGuard sidecar (compose
profile ``vpn``) is down the chain is marked unhealthy automatically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import time
from typing import Any, Iterable

import requests

from .source_policy import SourceCandidate


_ALLOWED_PROXY_SCHEMES = frozenset(
    {"http", "https", "socks5", "socks5h", "socks4", "socks4a"}
)


@dataclass
class Hop:
    """One link in a proxy chain.

    ``role`` is free-form ("front", "socks", "vpn", "egress", …) — it is
    informational and surfaces in the provenance JSON.  Only ``url`` is wired
    into ``requests.Session.proxies``.  Hops with ``role == "vpn"`` carry no
    URL: they document that the chain depends on a Layer-3 tunnel handled
    outside the python process (the wireguard sidecar).
    """

    role: str
    url: str | None = None
    interface: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Hop":
        return cls(
            role=str(raw.get("role", "")).strip() or "hop",
            url=(str(raw["url"]).strip() if raw.get("url") else None),
            interface=(str(raw["interface"]).strip() if raw.get("interface") else None),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"role": self.role}
        if self.url is not None:
            out["url"] = self.url
        if self.interface is not None:
            out["interface"] = self.interface
        return out


@dataclass
class ProxyChain:
    """A named ordered list of hops.

    The hop the SCANNER touches first is the LAST URL hop in the list (think
    of the order as physical packet flow: front → middle → … → egress).
    ``entry_url`` walks the hops back-to-front and returns the first non-VPN
    URL — that's what we plug into ``requests.Session.proxies``.
    """

    name: str
    hops: list[Hop] = field(default_factory=list)
    description: str = ""

    @classmethod
    def from_dict(cls, name: str, raw: dict[str, Any]) -> "ProxyChain":
        hops_raw = raw.get("hops") or []
        if not isinstance(hops_raw, list):
            raise TypeError(f"proxy.chains.{name}.hops must be a list")
        return cls(
            name=name,
            hops=[Hop.from_dict(item) for item in hops_raw],
            description=str(raw.get("description", "")),
        )

    @property
    def entry_url(self) -> str | None:
        """The URL the scanner connects to first.  ``None`` ⇒ direct."""
        for hop in self.hops:
            if hop.url:
                return hop.url
        return None

    def has_vpn(self) -> bool:
        return any(h.role == "vpn" for h in self.hops)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "hops": [hop.to_dict() for hop in self.hops],
            "entry_url": self.entry_url,
        }


@dataclass
class Policies:
    healthcheck_url: str = "https://www.google.com/generate_204"
    healthcheck_timeout_seconds: int = 5
    healthcheck_ttl_seconds: int = 60
    failover_order: list[str] = field(default_factory=list)
    retry_per_chain: int = 2

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Policies":
        return cls(
            healthcheck_url=str(
                raw.get("healthcheck_url", cls.healthcheck_url)
            ),
            healthcheck_timeout_seconds=int(
                raw.get("healthcheck_timeout_seconds", cls.healthcheck_timeout_seconds)
            ),
            healthcheck_ttl_seconds=int(
                raw.get("healthcheck_ttl_seconds", cls.healthcheck_ttl_seconds)
            ),
            failover_order=[str(item) for item in raw.get("failover_order", [])],
            retry_per_chain=int(raw.get("retry_per_chain", cls.retry_per_chain)),
        )


# ---------------------------------------------------------------------------
# Session building
# ---------------------------------------------------------------------------

def _proxies_for_chain(chain: ProxyChain, no_proxy: str | None) -> dict[str, str]:
    entry = chain.entry_url
    out: dict[str, str] = {}
    if entry:
        out["http"] = entry
        out["https"] = entry
    if no_proxy:
        out["no_proxy"] = no_proxy
    return out


def _session_from_proxies(proxies: dict[str, str]) -> requests.Session:
    sess = requests.Session()
    if proxies:
        sess.proxies.update(proxies)
    return sess


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

@dataclass
class _HealthState:
    status: str = "unknown"
    latency_ms: float | None = None
    error: str | None = None
    checked_at: float = 0.0  # monotonic


class ProxyRouter:
    """Build sessions for sources, respecting chain health + failover order."""

    def __init__(
        self,
        chains: dict[str, ProxyChain],
        policies: Policies,
        default_chain: str | None,
        per_source: dict[str, str],
        no_proxy: str | None,
    ):
        self._chains = chains
        self._policies = policies
        self._default_chain = default_chain
        self._per_source = per_source
        self._no_proxy = no_proxy
        self._health: dict[str, _HealthState] = {}

    # -- factory ------------------------------------------------------------
    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "ProxyRouter | None":
        """Parse a feed_sources.yaml ``proxy:`` block.

        Returns ``None`` if the YAML carries only the legacy flat form
        (``proxy.http`` / ``proxy.https``) — that path stays handled by
        ``config.parse_proxy_config()`` + ``fallback.build_session()``.
        """
        section = config.get("proxy") or {}
        raw_chains = section.get("chains")
        raw_policies = section.get("policies")
        if not raw_chains and not raw_policies:
            return None
        chains_raw = raw_chains if isinstance(raw_chains, dict) else {}
        chains = {
            name: ProxyChain.from_dict(name, body or {})
            for name, body in chains_raw.items()
        }
        policies = Policies.from_dict(raw_policies or {})
        per_source_list = section.get("per_source") or []
        per_source: dict[str, str] = {}
        for item in per_source_list:
            if not isinstance(item, dict):
                continue
            src = item.get("source")
            chain = item.get("chain")
            if src and chain:
                per_source[str(src)] = str(chain)
        default_chain = section.get("default_chain")
        no_proxy = (section.get("no_proxy") or "").strip() or None
        if default_chain and default_chain not in chains:
            raise ValueError(
                f"proxy.default_chain={default_chain!r} is not declared in proxy.chains"
            )
        for src, chain_name in per_source.items():
            if chain_name not in chains:
                raise ValueError(
                    f"proxy.per_source[{src}] references unknown chain {chain_name!r}"
                )
        for entry in policies.failover_order:
            if entry not in chains:
                raise ValueError(
                    f"proxy.policies.failover_order entry {entry!r} is not a declared chain"
                )
        return cls(chains, policies, default_chain, per_source, no_proxy)

    # -- public -------------------------------------------------------------
    @property
    def chains(self) -> dict[str, ProxyChain]:
        return self._chains

    def healthcheck_all(self, *, force: bool = False) -> dict[str, dict[str, Any]]:
        """Probe every declared chain; result is cached for TTL seconds.

        ``force=True`` ignores the cache.
        """
        result: dict[str, dict[str, Any]] = {}
        for name, chain in self._chains.items():
            state = self._probe_chain(name, chain, force=force)
            result[name] = {
                "status": state.status,
                "latency_ms": state.latency_ms,
                "error": state.error,
                "entry_url": chain.entry_url,
                "has_vpn": chain.has_vpn(),
                "hops": [hop.to_dict() for hop in chain.hops],
                "description": chain.description,
            }
        return result

    def select_chain_name(self, source: SourceCandidate | None) -> str | None:
        """Return the chain name that the router would use for *source*.

        Logic:
        1. Per-source pin → preferred chain.
        2. Else default_chain.
        3. If the preferred chain is unhealthy, walk ``failover_order`` and
           pick the first healthy chain.
        4. Fall back to ``direct`` if it exists and is reachable.
        5. Last resort: the preferred chain (let it fail loudly).
        """
        preferred = None
        if source is not None and source.name in self._per_source:
            preferred = self._per_source[source.name]
        if preferred is None:
            preferred = self._default_chain
        candidates: list[str] = []
        if preferred and preferred in self._chains:
            candidates.append(preferred)
        for name in self._policies.failover_order:
            if name in self._chains and name not in candidates:
                candidates.append(name)
        if "direct" in self._chains and "direct" not in candidates:
            candidates.append("direct")
        for name in candidates:
            chain = self._chains[name]
            state = self._probe_chain(name, chain, force=False)
            if state.status == "ok":
                return name
        return preferred

    def session_for_source(self, source: SourceCandidate | None) -> tuple[requests.Session, str | None]:
        name = self.select_chain_name(source)
        if not name or name not in self._chains:
            return _session_from_proxies({}), None
        chain = self._chains[name]
        return _session_from_proxies(_proxies_for_chain(chain, self._no_proxy)), name

    def write_provenance(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "default_chain": self._default_chain,
            "failover_order": list(self._policies.failover_order),
            "policies": {
                "healthcheck_url": self._policies.healthcheck_url,
                "healthcheck_timeout_seconds": self._policies.healthcheck_timeout_seconds,
                "healthcheck_ttl_seconds": self._policies.healthcheck_ttl_seconds,
                "retry_per_chain": self._policies.retry_per_chain,
            },
            "chains": self.healthcheck_all(force=False),
            "per_source": dict(self._per_source),
            "no_proxy": self._no_proxy,
        }
        target.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
        return target

    # -- internals ----------------------------------------------------------
    def _probe_chain(self, name: str, chain: ProxyChain, *, force: bool) -> _HealthState:
        now = time.monotonic()
        cached = self._health.get(name)
        if (
            not force
            and cached is not None
            and cached.checked_at > 0
            and (now - cached.checked_at) < self._policies.healthcheck_ttl_seconds
        ):
            return cached
        state = self._do_probe(chain)
        state.checked_at = now
        self._health[name] = state
        return state

    def _do_probe(self, chain: ProxyChain) -> _HealthState:
        proxies = _proxies_for_chain(chain, self._no_proxy)
        sess = _session_from_proxies(proxies)
        url = self._policies.healthcheck_url
        timeout = self._policies.healthcheck_timeout_seconds
        started = time.monotonic()
        try:
            response = sess.get(url, timeout=timeout, allow_redirects=False)
            elapsed_ms = round((time.monotonic() - started) * 1000.0, 1)
            # Healthcheck OK only on 2xx/3xx.  4xx (401/403 from a corp
            # proxy that rejects our generate_204 probe, 404 from a
            # misconfigured tinyproxy) is NOT healthy; failover must
            # try the next chain.  5xx stays in "degraded" because the
            # chain itself is reachable, just upstream is broken.
            # See docs/audit/10-defects.md.
            if response.status_code < 400:
                return _HealthState(status="ok", latency_ms=elapsed_ms)
            return _HealthState(
                status="degraded",
                latency_ms=elapsed_ms,
                error=f"upstream returned HTTP {response.status_code}",
            )
        except requests.RequestException as exc:
            return _HealthState(status="down", error=str(exc))


# ---------------------------------------------------------------------------
# Pure-function helpers (used by validators and tests)
# ---------------------------------------------------------------------------

def validate_chains(section: dict[str, Any]) -> list[str]:
    """Validate the proxy.chains / proxy.policies / proxy.per_source block.

    Returns a list of human-readable errors (empty = OK).  Used by
    ``config.validate_proxy_config`` after the flat-form checks.
    """
    from urllib.parse import urlparse as _urlparse

    errors: list[str] = []
    chains_raw = section.get("chains")
    if chains_raw is None:
        return errors  # legacy flat form — nothing to validate here
    if not isinstance(chains_raw, dict):
        return ["proxy.chains must be a mapping of name -> {hops: [...]}"]

    chain_names: set[str] = set()
    for name, body in chains_raw.items():
        chain_names.add(name)
        if not isinstance(body, dict):
            errors.append(f"proxy.chains.{name}: expected mapping with 'hops'")
            continue
        hops = body.get("hops")
        if hops is None:
            continue
        if not isinstance(hops, list):
            errors.append(f"proxy.chains.{name}.hops must be a list")
            continue
        for idx, hop in enumerate(hops):
            if not isinstance(hop, dict):
                errors.append(f"proxy.chains.{name}.hops[{idx}] must be a mapping")
                continue
            url = (hop.get("url") or "").strip()
            if url:
                parsed = _urlparse(url)
                if parsed.scheme not in _ALLOWED_PROXY_SCHEMES:
                    errors.append(
                        f"proxy.chains.{name}.hops[{idx}].url has unsupported "
                        f"scheme {parsed.scheme!r}. Allowed: {sorted(_ALLOWED_PROXY_SCHEMES)}"
                    )

    raw_policies = section.get("policies") or {}
    failover = raw_policies.get("failover_order") or []
    if not isinstance(failover, list):
        errors.append("proxy.policies.failover_order must be a list of chain names")
    else:
        for entry in failover:
            if entry not in chain_names:
                errors.append(
                    f"proxy.policies.failover_order entry {entry!r} is not a "
                    f"declared chain"
                )

    default_chain = section.get("default_chain")
    if default_chain is not None and default_chain not in chain_names:
        errors.append(
            f"proxy.default_chain={default_chain!r} is not declared in proxy.chains"
        )

    per_source = section.get("per_source") or []
    if not isinstance(per_source, list):
        errors.append("proxy.per_source must be a list of {source, chain} entries")
    else:
        for idx, item in enumerate(per_source):
            if not isinstance(item, dict):
                errors.append(f"proxy.per_source[{idx}] must be a mapping")
                continue
            chain = item.get("chain")
            if chain is not None and chain not in chain_names:
                errors.append(
                    f"proxy.per_source[{idx}].chain={chain!r} is not a declared chain"
                )

    return errors


__all__ = [
    "Hop",
    "Policies",
    "ProxyChain",
    "ProxyRouter",
    "validate_chains",
]
