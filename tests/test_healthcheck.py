"""Unit tests for resilient_updates.healthcheck.

healthcheck.py had 0 test coverage (noted in docs/audit/30-tests.md §5).
These tests cover the two paths in _probe_layer and verify the shape of the
dict returned by run_healthcheck without making any real network connections.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from resilient_updates.fallback import AttemptResult, FailureReason
from resilient_updates.healthcheck import _probe_layer, run_healthcheck
from resilient_updates.source_policy import SourceCandidate

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_source(name: str = "primary") -> SourceCandidate:
    return SourceCandidate(
        priority=10,
        name=name,
        url=f"http://127.0.0.1:0/{name}",
        tool="trivy",
        layer="trivy-db",
    )


def _make_config() -> dict[str, Any]:
    """Minimal config that satisfies run_healthcheck's key lookups."""
    return {
        "trivy": {
            "db_repositories": [
                {"name": "p", "url": "http://127.0.0.1:0/trivy-db", "priority": 10, "enabled": True}
            ],
            "java_db_repositories": [],
            "checks_bundle_repositories": [],
            "retry_backoff_policy": {
                "retry_count": 1,
                "backoff_seconds": 0,
                "retry_status_codes": [429, 500],
            },
            "source_health_policy": {"healthcheck_timeout_seconds": 1},
        },
        "grype": {
            "upstream_update_urls": [],
            "timeout_policy": {"update_available_timeout": 1},
        },
        "cve_bin_tool": {
            "mirror_urls": [],
            "source_health_policy": {
                "source_timeout_seconds": 1,
                "retry_count": 1,
            },
        },
        "proxy": {},
    }


# ---------------------------------------------------------------------------
# _probe_layer
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_probe_layer_no_sources_returns_no_sources_configured():
    """When build_sources yields nothing, probe must return a well-formed dict."""
    config = _make_config()
    # Use grype-db which has no upstream_update_urls in minimal config.
    result = _probe_layer(
        config,
        tool="grype",
        layer="grype-db",
        timeout=1,
        retry_count=1,
        backoff_seconds=0,
        retry_status_codes=[],
        session=MagicMock(),
    )
    assert result["status"] == "no-sources-configured"
    assert result["selected_source"] is None
    assert result["configured_sources"] == 0
    assert result["attempted_sources"] == []


def test_probe_layer_all_failed_returns_all_sources_failed():
    """When attempt_sources returns no winner, status must be all-sources-failed."""
    src = _make_source("bad")
    failed = AttemptResult(src, False, FailureReason.TIMEOUT, "timed out", None)

    with (
        patch("resilient_updates.healthcheck.build_sources", return_value=[src]),
        patch("resilient_updates.healthcheck.attempt_sources", return_value=(None, {}, [failed])),
    ):
        result = _probe_layer(
            _make_config(),
            tool="trivy",
            layer="trivy-db",
            timeout=1,
            retry_count=1,
            backoff_seconds=0,
            retry_status_codes=[],
            session=MagicMock(),
        )

    assert result["status"] == "all-sources-failed"
    assert result["selected_source"] is None
    assert len(result["failures"]) == 1
    assert result["failures"][0]["source"] == "bad"
    assert result["failures"][0]["reason"] == FailureReason.TIMEOUT.value


def test_probe_layer_success_returns_ok():
    """When attempt_sources returns a winner, status must be ok."""
    src = _make_source("primary")
    ok_attempt = AttemptResult(src, True, None, "200 OK", 200)

    with (
        patch("resilient_updates.healthcheck.build_sources", return_value=[src]),
        patch(
            "resilient_updates.healthcheck.attempt_sources", return_value=(src, {"blob": b""}, [ok_attempt])
        ),
    ):
        result = _probe_layer(
            _make_config(),
            tool="trivy",
            layer="trivy-db",
            timeout=1,
            retry_count=1,
            backoff_seconds=0,
            retry_status_codes=[],
            session=MagicMock(),
        )

    assert result["status"] == "ok"
    assert result["selected_source"] == "primary"
    assert result["failures"] == []


# ---------------------------------------------------------------------------
# run_healthcheck
# ---------------------------------------------------------------------------


def test_run_healthcheck_shape(tmp_path):
    """run_healthcheck must return a dict with a proxy key and one key per layer."""
    config_path = "tests/fixtures/feed_sources.example.yaml"

    # Patch attempt_sources so no real network calls are made; every layer fails
    # gracefully (no sources reachable → all-sources-failed or no-sources-configured).
    with patch("resilient_updates.healthcheck.attempt_sources", return_value=(None, {}, [])):
        result = run_healthcheck(config_path)

    assert "proxy" in result
    assert "configured" in result["proxy"]
    # At least the trivy-db layer must appear.
    assert "trivy-db" in result
    # Every layer dict must have a status key.
    for key in ("trivy-db", "trivy-java-db", "trivy-checks", "grype-db", "cve-bin-tool-mirror"):
        if key in result:
            assert "status" in result[key], f"{key} missing 'status'"
