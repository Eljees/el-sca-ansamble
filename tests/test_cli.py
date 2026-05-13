from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json

from resilient_updates.cli import EXIT_ALL_SOURCES_FAILED, _health_summary
from resilient_updates.config import load_config


def test_trivy_health_summary_returns_failure_payload_without_nameerror(tmp_path: Path, monkeypatch):
    config = deepcopy(load_config("tests/fixtures/feed_sources.example.yaml"))
    config["trivy"]["db_repositories"] = [
        {"name": "primary", "url": "http://127.0.0.1:9/trivy-db", "priority": 10, "enabled": True}
    ]
    monkeypatch.chdir(tmp_path)

    code, payload = _health_summary(
        config,
        "trivy",
        "trivy-db",
        timeout=1,
        retry_count=1,
        backoff_seconds=0,
        retry_codes=[429, 500, 502, 503, 504],
    )

    assert code == EXIT_ALL_SOURCES_FAILED
    assert payload["tool"] == "trivy"
    assert payload["artifact_type"] == "trivy-db"
    assert payload["selected_source"] is None
    assert payload["activation_status"] == "healthcheck-only"
    assert isinstance(payload["failures"], list)

    provenance = tmp_path / "artifacts" / "provenance" / "trivy.json"
    assert provenance.exists()
    stored = json.loads(provenance.read_text(encoding="utf-8"))
    assert stored["tool"] == "trivy"
