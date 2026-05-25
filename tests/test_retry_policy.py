"""Tests for resilient_updates._retry.RetryPolicy."""
from __future__ import annotations

from resilient_updates._retry import (
    DEFAULT_BACKOFF_SECONDS,
    DEFAULT_RETRY_COUNT,
    DEFAULT_RETRY_STATUS_CODES,
    DEFAULT_TIMEOUT_SECONDS,
    RetryPolicy,
)


def test_defaults_match_legacy_grype_listing_fetch() -> None:
    """Defaults reproduce the historical 1/1/[429,5xx] hardcode in cli.update_grype."""
    p = RetryPolicy()
    assert p.retry_count == 1
    assert p.backoff_seconds == 1
    assert p.timeout_seconds == 10
    assert p.retry_status_codes == DEFAULT_RETRY_STATUS_CODES


def test_from_yaml_node_none_uses_defaults() -> None:
    assert RetryPolicy.from_yaml_node(None) == RetryPolicy()


def test_from_yaml_node_partial_fills_in_defaults() -> None:
    p = RetryPolicy.from_yaml_node({"retry_count": 5})
    assert p.retry_count == 5
    assert p.backoff_seconds == DEFAULT_BACKOFF_SECONDS
    assert p.timeout_seconds == DEFAULT_TIMEOUT_SECONDS


def test_from_yaml_node_unknown_keys_are_ignored() -> None:
    """Forward-compatibility: future YAML keys must not crash older code."""
    p = RetryPolicy.from_yaml_node({
        "retry_count": 2,
        "future_field_we_dont_know": "ignored",
    })
    assert p.retry_count == 2


def test_from_tool_config_reads_named_section() -> None:
    cfg = {"trivy": {"retry_backoff_policy": {
        "retry_count": 4, "backoff_seconds": 3.5, "timeout_seconds": 20,
        "retry_status_codes": [429, 503],
    }}}
    p = RetryPolicy.from_tool_config(cfg, "trivy")
    assert p.retry_count == 4
    assert p.backoff_seconds == 3.5
    assert p.timeout_seconds == 20
    assert p.retry_status_codes == (429, 503)


def test_from_tool_config_missing_tool_returns_defaults() -> None:
    assert RetryPolicy.from_tool_config({}, "nope") == RetryPolicy()


def test_as_attempt_kwargs_shape() -> None:
    p = RetryPolicy(retry_count=3, backoff_seconds=2.0, timeout_seconds=15,
                    retry_status_codes=(429,))
    kw = p.as_attempt_kwargs()
    assert kw == {
        "timeout": 15,
        "retry_count": 3,
        "backoff_seconds": 2,
        "retry_status_codes": [429],
    }


def test_immutable_after_construction() -> None:
    """Frozen dataclass — keeps the shared instance safe across call sites."""
    import dataclasses
    p = RetryPolicy()
    try:
        p.retry_count = 99  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        return
    assert False, "RetryPolicy should be frozen"
