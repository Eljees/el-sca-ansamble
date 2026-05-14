from __future__ import annotations

from typing import Any

from .config import load_config, parse_proxy_config
from .fallback import attempt_sources, build_session
from .source_policy import build_sources


def run_healthcheck(config_path: str) -> dict[str, Any]:
    config = load_config(config_path)
    session = build_session(parse_proxy_config(config))
    result: dict[str, Any] = {}
    trivy_timeout = config["trivy"]["source_health_policy"]["healthcheck_timeout_seconds"]
    trivy_retry = config["trivy"]["retry_backoff_policy"]["retry_count"]
    trivy_backoff = config["trivy"]["retry_backoff_policy"]["backoff_seconds"]
    trivy_codes = config["trivy"]["retry_backoff_policy"]["retry_status_codes"]
    for layer in ("trivy-db", "trivy-java-db", "trivy-checks"):
        source, _payload, attempts = attempt_sources(
            build_sources(config, "trivy", layer),
            timeout=trivy_timeout,
            retry_count=trivy_retry,
            backoff_seconds=trivy_backoff,
            retry_status_codes=trivy_codes,
            session=session,
        )
        result[layer] = {
            "selected_source": source.name if source else None,
            "attempted_sources": [attempt.source.name for attempt in attempts],
        }
    return result
