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


def test_write_run_summary_cli_produces_four_sidecar_jsons(tmp_path: Path, monkeypatch, capsys):
    """CLI smoke for `write-run-summary` — wiring of argparse → run_summary."""
    from resilient_updates.cli import main

    # Seed a minimal artifacts/ tree the subcommand can derive from.
    (tmp_path / "sbom").mkdir(parents=True)
    (tmp_path / "reports" / "grype").mkdir(parents=True)
    (tmp_path / "reports" / "trivy").mkdir(parents=True)
    (tmp_path / "reports" / "cve-bin-tool").mkdir(parents=True)
    (tmp_path / "sbom" / "syft.json").write_text(
        json.dumps({"artifacts": [{"name": "alpha", "version": "1.0"}]}),
        encoding="utf-8",
    )
    (tmp_path / "reports" / "grype" / "report.json").write_text(
        json.dumps({"matches": []}), encoding="utf-8"
    )

    # The CLI needs a valid feed_sources.yaml.  Point it at the example fixture.
    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--config", "tests/fixtures/feed_sources.example.yaml",
            "write-run-summary",
            "--reports-dir", str(tmp_path),
        ],
    )

    exit_code = main()
    assert exit_code == 0
    out = capsys.readouterr().out
    assert '"status": "ok"' in out

    # All four sidecar files were produced.
    for name in ("summary.json", "status.json", "run_manifest.json", "db_snapshot.json"):
        path = tmp_path / name
        assert path.exists(), f"{name} not written"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["generated_by"] == "resilient_updates.run_summary"


def test_write_run_summary_no_overwrite_keeps_existing(tmp_path: Path, monkeypatch):
    """--no-overwrite must leave a pre-existing sidecar untouched."""
    from resilient_updates.cli import main

    (tmp_path / "sbom").mkdir(parents=True)
    (tmp_path / "reports" / "grype").mkdir(parents=True)
    (tmp_path / "reports" / "trivy").mkdir(parents=True)
    (tmp_path / "reports" / "cve-bin-tool").mkdir(parents=True)
    (tmp_path / "sbom" / "syft.json").write_text(
        '{"artifacts": []}', encoding="utf-8"
    )
    (tmp_path / "reports" / "grype" / "report.json").write_text(
        '{"matches": []}', encoding="utf-8"
    )

    # Manually-authored summary that must survive.
    sentinel = tmp_path / "summary.json"
    sentinel.write_text('{"manual": true}', encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--config", "tests/fixtures/feed_sources.example.yaml",
            "write-run-summary",
            "--reports-dir", str(tmp_path),
            "--no-overwrite",
        ],
    )

    assert main() == 0
    assert json.loads(sentinel.read_text(encoding="utf-8")) == {"manual": True}
    # The other three were created.
    assert (tmp_path / "status.json").exists()
    assert (tmp_path / "run_manifest.json").exists()
    assert (tmp_path / "db_snapshot.json").exists()
