from __future__ import annotations

from typing import Any

from .config import load_config, parse_proxy_config
from .fallback import attempt_sources, build_session
from .source_policy import build_sources


# Default retry profile for tools whose YAML schema doesn't declare a
# retry_backoff_policy at the same nesting depth as trivy's
# (grype.timeout_policy / cve_bin_tool.source_health_policy).
_DEFAULT_RETRY_STATUS_CODES = [429, 500, 502, 503, 504]


def _probe_layer(
    config: dict[str, Any],
    tool: str,
    layer: str,
    timeout: int,
    retry_count: int,
    backoff_seconds: int,
    retry_status_codes: list[int],
    session,
) -> dict[str, Any]:
    """Run attempt_sources against one (tool, layer), return a compact health record."""
    sources = build_sources(config, tool, layer)
    if not sources:
        return {
            "configured_sources": 0,
            "selected_source": None,
            "attempted_sources": [],
            "status": "no-sources-configured",
        }
    source, _payload, attempts = attempt_sources(
        sources,
        timeout=timeout,
        retry_count=retry_count,
        backoff_seconds=backoff_seconds,
        retry_status_codes=retry_status_codes,
        session=session,
    )
    failures = [
        {
            "source": attempt.source.name,
            "reason": attempt.reason.value if attempt.reason else None,
            "message": attempt.message,
            "status_code": attempt.status_code,
        }
        for attempt in attempts
        if not attempt.success
    ]
    return {
        "configured_sources": len(sources),
        "selected_source": source.name if source else None,
        "attempted_sources": sorted({attempt.source.name for attempt in attempts}),
        "failures": failures,
        "status": "ok" if source else "all-sources-failed",
    }


def run_healthcheck(config_path: str) -> dict[str, Any]:
    """Probe every configured DB source across trivy / grype / cve-bin-tool.

    The single shared ``requests.Session`` is built from feed_sources.yaml
    ``proxy:`` (or environment variables); the same session is reused for every
    layer so the diagnostic accurately reflects what the update pipeline will
    actually see in this environment.
    """
    config = load_config(config_path)
    proxies = parse_proxy_config(config)
    session = build_session(proxies)
    result: dict[str, Any] = {
        "proxy": {
            "configured": dict(proxies) if proxies else {},
            "active_session_proxies": dict(session.proxies),
        }
    }

    # ── Trivy ──────────────────────────────────────────────────────────────
    trivy_health = config["trivy"]["source_health_policy"]
    trivy_retry_cfg = config["trivy"]["retry_backoff_policy"]
    trivy_kwargs = dict(
        timeout=int(trivy_health["healthcheck_timeout_seconds"]),
        retry_count=int(trivy_retry_cfg["retry_count"]),
        backoff_seconds=int(trivy_retry_cfg["backoff_seconds"]),
        retry_status_codes=list(trivy_retry_cfg["retry_status_codes"]),
        session=session,
    )
    for layer in ("trivy-db", "trivy-java-db", "trivy-checks"):
        result[layer] = _probe_layer(config, "trivy", layer, **trivy_kwargs)

    # ── Grype ──────────────────────────────────────────────────────────────
    grype_timeout = int(config["grype"]["timeout_policy"]["update_available_timeout"])
    result["grype-db"] = _probe_layer(
        config,
        "grype",
        "grype-db",
        timeout=grype_timeout,
        retry_count=1,
        backoff_seconds=1,
        retry_status_codes=_DEFAULT_RETRY_STATUS_CODES,
        session=session,
    )

    # ── cve-bin-tool ───────────────────────────────────────────────────────
    cve_health = config["cve_bin_tool"]["source_health_policy"]
    result["cve-bin-tool-mirror"] = _probe_layer(
        config,
        "cve_bin_tool",
        "cve-bin-tool-mirror",
        timeout=int(cve_health["source_timeout_seconds"]),
        retry_count=int(cve_health["retry_count"]),
        backoff_seconds=1,
        retry_status_codes=_DEFAULT_RETRY_STATUS_CODES,
        session=session,
    )

    return result
