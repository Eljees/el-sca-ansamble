from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json
import os
import time

from resilient_updates.cli import EXIT_ALL_SOURCES_FAILED, _db_status_payload, _health_summary
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


def test_db_status_payload_warns_when_age_exceeds_threshold(tmp_path: Path):
    db_file = tmp_path / "db.bin"
    db_file.write_bytes(b"db")
    stale_ts = time.time() - 7200
    os.utime(db_file, (stale_ts, stale_ts))
    payload = _db_status_payload("trivy", db_file, "1h")
    assert payload["tool"] == "trivy"
    assert payload["warning"] is True
    assert payload["age_hours"] is not None


def test_cve_bin_tool_db_status_requires_cve_db(tmp_path: Path):
    (tmp_path / "redhat").mkdir()
    (tmp_path / "redhat" / "CVE-1.json").write_text("{}", encoding="utf-8")
    payload = _db_status_payload("cve-bin-tool", tmp_path, "24h")
    assert payload["warning"] is True
    assert "cve.db" in payload["message"]
