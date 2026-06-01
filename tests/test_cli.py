from __future__ import annotations

import json
import os
import time
from copy import deepcopy
from pathlib import Path

import pytest

from resilient_updates.cli import (
    EXIT_ALL_SOURCES_FAILED,
    EXIT_VALIDATION_FAILED,
    _db_status_payload,
    _dedup_attempted_sources,
    _health_summary,
    _render_trivy_flags,
    _safe_exists,
    _safe_is_dir,
)
from resilient_updates.config import load_config
from resilient_updates.fallback import AttemptResult, FailureReason
from resilient_updates.source_policy import SourceCandidate


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
    (tmp_path / "reports" / "grype" / "report.json").write_text(json.dumps({"matches": []}), encoding="utf-8")

    # The CLI needs a valid feed_sources.yaml.  Point it at the example fixture.
    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--config",
            "tests/fixtures/feed_sources.example.yaml",
            "write-run-summary",
            "--reports-dir",
            str(tmp_path),
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
    (tmp_path / "sbom" / "syft.json").write_text('{"artifacts": []}', encoding="utf-8")
    (tmp_path / "reports" / "grype" / "report.json").write_text('{"matches": []}', encoding="utf-8")

    # Manually-authored summary that must survive.
    sentinel = tmp_path / "summary.json"
    sentinel.write_text('{"manual": true}', encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--config",
            "tests/fixtures/feed_sources.example.yaml",
            "write-run-summary",
            "--reports-dir",
            str(tmp_path),
            "--no-overwrite",
        ],
    )

    assert main() == 0
    assert json.loads(sentinel.read_text(encoding="utf-8")) == {"manual": True}
    # The other three were created.
    assert (tmp_path / "status.json").exists()
    assert (tmp_path / "run_manifest.json").exists()
    assert (tmp_path / "db_snapshot.json").exists()


def test_extract_cli_fails_when_file_input_has_no_extractable_archives(tmp_path, monkeypatch):
    from resilient_updates.cli import main

    plain_file = tmp_path / "plain.txt"
    plain_file.write_text("not an archive", encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--config",
            "tests/fixtures/feed_sources.example.yaml",
            "extract",
            "--input",
            str(plain_file),
            "--output",
            str(tmp_path / "out"),
        ],
    )

    assert main() == EXIT_VALIDATION_FAILED


# ---------------------------------------------------------------------------
# _dedup_attempted_sources -- retry accumulation
# ---------------------------------------------------------------------------


def _make_source(name="primary"):
    return SourceCandidate(
        priority=10,
        name=name,
        url=f"https://example.com/{name}",
        tool="grype",
        layer="grype-db",
    )


@pytest.mark.smoke
def test_dedup_single_attempt_passthrough():
    src = _make_source("primary")
    attempts = [AttemptResult(src, True, None, "ok", 200)]
    result = _dedup_attempted_sources(attempts)
    assert len(result) == 1
    assert result[0]["name"] == "primary"
    assert result[0]["retry_count"] == 1
    assert result[0]["succeeded"] is True
    assert result[0]["outcomes"] == [{"success": True, "reason": None, "message": "ok", "status_code": 200}]


def test_dedup_retries_accumulate_count():
    src = _make_source("mirror")
    attempts = [
        AttemptResult(src, False, FailureReason.HTTP_5XX, "http status 503", 503),
        AttemptResult(src, False, FailureReason.HTTP_5XX, "http status 503", 503),
        AttemptResult(src, True, None, "ok", 200),
    ]
    result = _dedup_attempted_sources(attempts)
    assert len(result) == 1
    rec = result[0]
    assert rec["retry_count"] == 3
    assert rec["succeeded"] is True
    assert len(rec["outcomes"]) == 3
    assert rec["outcomes"][0]["reason"] == FailureReason.HTTP_5XX.value
    assert rec["outcomes"][2]["success"] is True


def test_dedup_all_failed_source():
    src = _make_source("bad-mirror")
    attempts = [
        AttemptResult(src, False, FailureReason.TIMEOUT, "timed out", None),
        AttemptResult(src, False, FailureReason.TIMEOUT, "timed out", None),
    ]
    result = _dedup_attempted_sources(attempts)
    assert result[0]["succeeded"] is False
    assert result[0]["retry_count"] == 2


def test_dedup_multiple_sources_preserve_order():
    src_a = _make_source("alpha")
    src_b = _make_source("beta")
    attempts = [
        AttemptResult(src_a, False, FailureReason.HTTP_5XX, "503", 503),
        AttemptResult(src_b, True, None, "ok", 200),
        AttemptResult(src_a, True, None, "ok", 200),
    ]
    result = _dedup_attempted_sources(attempts)
    assert len(result) == 2
    assert result[0]["name"] == "alpha"
    assert result[0]["retry_count"] == 2
    assert result[0]["succeeded"] is True
    assert result[1]["name"] == "beta"
    assert result[1]["retry_count"] == 1


def test_dedup_empty_input():
    assert _dedup_attempted_sources([]) == []


# ---------------------------------------------------------------------------
# render-flags — VEX layer (ADR-0003)
# ---------------------------------------------------------------------------


def test_render_trivy_flags_emits_vex_when_doc_present_and_enabled(tmp_path: Path):
    """When vex_policy is enabled and a doc exists, --vex is appended."""
    vex_dir = tmp_path / "vex"
    vex_dir.mkdir()
    doc = vex_dir / "internal-vex-hub.openvex.json"
    doc.write_text("{}", encoding="utf-8")

    config = deepcopy(load_config("tests/fixtures/feed_sources.example.yaml"))
    config["trivy"]["cache_dir"] = str(tmp_path)
    config["trivy"]["vex_policy"] = {"enabled": True, "mode": "apply"}

    flags = _render_trivy_flags(config)
    assert f"--vex {doc}" in flags


def test_render_trivy_flags_omits_vex_when_disabled_or_absent(tmp_path: Path):
    """Backward-compat contract: no VEX policy / no doc => no --vex flag."""
    config = deepcopy(load_config("tests/fixtures/feed_sources.example.yaml"))
    config["trivy"]["cache_dir"] = str(tmp_path)

    # No vex_policy at all -> no --vex (existing scans unaffected).
    assert "--vex" not in _render_trivy_flags(config)

    # Policy enabled but the vex/ directory has no docs -> still no --vex.
    config["trivy"]["vex_policy"] = {"enabled": True}
    (tmp_path / "vex").mkdir()
    assert "--vex" not in _render_trivy_flags(config)


# ---------------------------------------------------------------------------
# Filesystem probes survive an unreadable path (non-root container hardening)
# ---------------------------------------------------------------------------


def test_safe_exists_swallows_permission_error(tmp_path: Path, monkeypatch):
    def _boom(self):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "exists", _boom)
    assert _safe_exists(tmp_path) is False


def test_safe_is_dir_swallows_permission_error(tmp_path: Path, monkeypatch):
    def _boom(self):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "is_dir", _boom)
    assert _safe_is_dir(tmp_path) is False


def test_db_status_payload_handles_unreadable_path(tmp_path: Path, monkeypatch):
    """db-status on a root-owned default path (e.g. /root/.cache/cve-bin-tool)
    under USER appuser must report exists=false, not raise PermissionError."""

    def _boom(self):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "exists", _boom)
    payload = _db_status_payload("cve-bin-tool", tmp_path, "24h")
    assert payload["exists"] is False
    assert payload["age_hours"] is None
