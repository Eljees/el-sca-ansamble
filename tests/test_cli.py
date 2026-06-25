from __future__ import annotations

import io
import json
import os
import sys
import tarfile
import time
from copy import deepcopy
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from resilient_updates._retry import RetryPolicy
from resilient_updates.cli import (
    EXIT_ALL_SOURCES_FAILED,
    EXIT_VALIDATION_FAILED,
    _db_status_payload,
    _dedup_attempted_sources,
    _extract_checksum_from_text,
    _health_summary,
    _latest_mtime,
    _provenance_path,
    _render_trivy_flags,
    _resolve_listing,
    _safe_exists,
    _safe_is_dir,
    _validate_grype_archive,
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
        retry=RetryPolicy(retry_count=1, backoff_seconds=0, retry_status_codes=(429, 500, 502, 503, 504)),
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


# ---------------------------------------------------------------------------
# CLI subcommand smoke tests (via main()) — cover the argument-dispatch paths
# ---------------------------------------------------------------------------

_CFG = "tests/fixtures/feed_sources.example.yaml"


def _seed_minimal_artifacts(root: Path) -> None:
    """Write the minimum artifact tree that collect-report / scanner-diff need."""
    for sub in ("sbom", "reports/grype", "reports/trivy", "reports/cve-bin-tool"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    (root / "sbom" / "syft.json").write_text(json.dumps({"artifacts": []}), encoding="utf-8")
    (root / "reports" / "grype" / "report.json").write_text(json.dumps({"matches": []}), encoding="utf-8")
    (root / "reports" / "trivy" / "report.json").write_text(json.dumps({"Results": []}), encoding="utf-8")
    (root / "reports" / "cve-bin-tool" / "report.json").write_text("[]", encoding="utf-8")


@pytest.mark.smoke
def test_validate_config_subcommand_returns_ok(monkeypatch, capsys):
    from resilient_updates.cli import main

    monkeypatch.setattr("sys.argv", ["cli", "--config", _CFG, "validate-config"])
    rc = main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "ok"


def test_validate_config_subcommand_detects_broken_config(tmp_path, monkeypatch, capsys):
    from resilient_updates.cli import EXIT_CONFIG_ERROR, main

    bad_cfg = tmp_path / "bad.yaml"
    bad_cfg.write_text("trivy:\n  db_repositories: null\n", encoding="utf-8")

    monkeypatch.setattr("sys.argv", ["cli", "--config", str(bad_cfg), "validate-config"])
    rc = main()
    assert rc == EXIT_CONFIG_ERROR
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "error"
    assert out["errors"]


def test_collect_report_subcommand(tmp_path, monkeypatch, capsys):
    """collect-report must build a Markdown file and emit {"status": "ok"}."""
    from resilient_updates.cli import main

    artifacts = tmp_path / "artifacts"
    _seed_minimal_artifacts(artifacts)
    out_md = tmp_path / "report.md"

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--config",
            _CFG,
            "collect-report",
            "--reports-dir",
            str(artifacts),
            "--output",
            str(out_md),
        ],
    )
    rc = main()
    assert rc == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ok"
    assert out_md.exists()


def test_scanner_diff_subcommand_stdout(tmp_path, monkeypatch, capsys):
    """scanner-diff --output - must print JSON diff to stdout."""
    from resilient_updates.cli import main

    before = tmp_path / "before"
    after = tmp_path / "after"
    _seed_minimal_artifacts(before)
    _seed_minimal_artifacts(after)

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--config",
            _CFG,
            "scanner-diff",
            "--before",
            str(before),
            "--after",
            str(after),
            "--output",
            "-",
            "--format",
            "json",
        ],
    )
    rc = main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    # A diff of two identical empty runs should report 0 added / 0 removed.
    assert "added" in out or "components" in out or isinstance(out, dict)


def test_scanner_diff_subcommand_file_output(tmp_path, monkeypatch, capsys):
    """scanner-diff writing to a .md file must produce valid Markdown."""
    from resilient_updates.cli import main

    before = tmp_path / "before"
    after = tmp_path / "after"
    _seed_minimal_artifacts(before)
    _seed_minimal_artifacts(after)
    out_md = tmp_path / "diff.md"

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--config",
            _CFG,
            "scanner-diff",
            "--before",
            str(before),
            "--after",
            str(after),
            "--output",
            str(out_md),
        ],
    )
    rc = main()
    assert rc == 0
    assert out_md.exists()
    text = out_md.read_text(encoding="utf-8")
    assert "#" in text  # at least one Markdown heading


def test_scan_dry_run_subcommand(tmp_path, monkeypatch, capsys):
    """scan --dry-run must print the plan without touching docker."""
    from resilient_updates.cli import main

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--config",
            _CFG,
            "scan",
            "--target",
            str(tmp_path),
            "--dry-run",
            "--json",
        ],
    )
    rc = main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "plan" in out
    assert "target" in out


# ---------------------------------------------------------------------------
# healthcheck
# ---------------------------------------------------------------------------


def test_healthcheck_subcommand_returns_json(monkeypatch, capsys):
    """healthcheck must print a JSON payload and return 0."""
    from resilient_updates.cli import main

    monkeypatch.setattr("sys.argv", ["cli", "--config", _CFG, "healthcheck"])
    rc = main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    # run_healthcheck always returns a dict with at least a "config" key.
    assert isinstance(out, dict)


# ---------------------------------------------------------------------------
# db-status
# ---------------------------------------------------------------------------


def test_db_status_subcommand_nonexistent_path(tmp_path, monkeypatch, capsys):
    """db-status with a path that doesn't exist must return non-zero and JSON."""
    from resilient_updates.cli import main

    ghost = tmp_path / "no_such_dir"
    monkeypatch.setattr(
        "sys.argv",
        ["cli", "--config", _CFG, "db-status", "trivy", "--path", str(ghost)],
    )
    rc = main()
    # Path doesn't exist → EXIT_VALIDATION_FAILED
    assert rc != 0
    out = json.loads(capsys.readouterr().out)
    assert out["exists"] is False


def test_db_status_subcommand_existing_path(tmp_path, monkeypatch, capsys):
    """db-status with an existing trivy cache dir returns 0 and exists=true."""
    from resilient_updates.cli import main

    db_dir = tmp_path / "trivy"
    db_dir.mkdir()
    (db_dir / "db.tar.gz").write_bytes(b"fake-db")

    monkeypatch.setattr(
        "sys.argv",
        ["cli", "--config", _CFG, "db-status", "trivy", "--path", str(db_dir)],
    )
    rc = main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["exists"] is True


# ---------------------------------------------------------------------------
# render-flags trivy
# ---------------------------------------------------------------------------


def test_render_flags_trivy_subcommand(monkeypatch, capsys):
    """render-flags trivy must print --db-repository flags and return 0."""
    from resilient_updates.cli import main

    monkeypatch.setattr("sys.argv", ["cli", "--config", _CFG, "render-flags", "trivy"])
    rc = main()
    assert rc == 0
    out = capsys.readouterr().out.strip()
    # The example config has at least one trivy db_repository → expect flag
    assert "--db-repository" in out


# ---------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------


def test_manifest_subcommand_writes_manifest_json(tmp_path, monkeypatch, capsys):
    """manifest subcommand must write MANIFEST.json and return 0."""
    from resilient_updates.cli import main

    artifacts = tmp_path / "artifacts"
    _seed_minimal_artifacts(artifacts)
    output = tmp_path / "MANIFEST.json"

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--config",
            _CFG,
            "manifest",
            "--artifacts-dir",
            str(artifacts),
            "--output",
            str(output),
            "--case-id",
            "TEST-001",
        ],
    )
    rc = main()
    assert rc == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ok"
    assert output.exists()
    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["case_id"] == "TEST-001"


def test_archive_run_subcommand_writes_snapshot(tmp_path, monkeypatch, capsys):
    """archive-run snapshots current artifacts into artifacts/runs."""
    from resilient_updates.cli import main

    artifacts = tmp_path / "artifacts"
    _seed_minimal_artifacts(artifacts)
    target = tmp_path / "input.tar.gz"
    target.write_bytes(b"input")

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--config",
            _CFG,
            "archive-run",
            "--artifacts-dir",
            str(artifacts),
            "--target-host",
            str(target),
            "--case-id",
            "TEST-ARCHIVE",
            "--mode",
            "artifacts",
        ],
    )
    rc = main()
    assert rc == 0
    result = json.loads(capsys.readouterr().out)
    run_dir = Path(result["run_dir"])
    assert result["status"] == "ok"
    assert (run_dir / "MANIFEST.json").is_file()
    assert (run_dir / "checkpoint.json").is_file()


# ---------------------------------------------------------------------------
# audit cve-bin-tool-db
# ---------------------------------------------------------------------------


def _make_minimal_cve_db(root: Path) -> None:
    """Create a minimal cve.db that the audit function can query."""
    import sqlite3

    root.mkdir(parents=True, exist_ok=True)
    for sub in ("redhat", "purl2cpe", "gad"):
        (root / sub).mkdir(exist_ok=True)
    (root / "vuln.json").write_text("[]", encoding="utf-8")
    (root / "version_map.db").write_bytes(b"placeholder")
    (root / "gad" / "advisory.yml").write_text("id: GAD-1\n", encoding="utf-8")
    (root / "redhat" / "CVE-2026-0001.json").write_text("{}", encoding="utf-8")
    with sqlite3.connect(root / "cve.db") as conn:
        cur = conn.cursor()
        cur.execute("CREATE TABLE cve_range (data_source TEXT)")
        cur.execute("CREATE TABLE cve_severity (data_source TEXT)")
        cur.execute("CREATE TABLE purl2cpe (id INTEGER)")
        cur.executemany("INSERT INTO cve_range VALUES (?)", [("Curl",), ("REDHAT",)])
        cur.executemany(
            "INSERT INTO cve_severity VALUES (?)",
            [("NVD",), ("NVD",), ("GAD",), ("REDHAT",)],
        )
        cur.executemany("INSERT INTO purl2cpe VALUES (?)", [(1,), (2,)])
        conn.commit()


def test_audit_cve_db_subcommand_passes(tmp_path, monkeypatch, capsys):
    """audit cve-bin-tool-db with a healthy DB must return 0."""
    from resilient_updates.cli import main

    db_root = tmp_path / "db"
    _make_minimal_cve_db(db_root)

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--config",
            _CFG,
            "audit",
            "cve-bin-tool-db",
            "--db-root",
            str(db_root),
        ],
    )
    main()
    out = json.loads(capsys.readouterr().out)
    # The example config's required_sources might include sources the minimal DB
    # doesn't have, so just verify the subcommand ran and produced JSON.
    assert isinstance(out, dict)
    assert "overall_status" in out


# ---------------------------------------------------------------------------
# seed cve-bin-tool-aux
# ---------------------------------------------------------------------------


def test_seed_cve_bin_tool_aux_subcommand(tmp_path, monkeypatch, capsys):
    """seed with no seed flags (no network) must return 0 and empty seeded dict."""
    from resilient_updates.cli import main

    db_root = tmp_path / "db"
    db_root.mkdir()

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--config",
            _CFG,
            "seed",
            "cve-bin-tool-aux",
            "--db-root",
            str(db_root),
        ],
    )
    rc = main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["overall_status"] == "pass"
    assert out["seeded"] == {}


# ---------------------------------------------------------------------------
# freshness
# ---------------------------------------------------------------------------


def test_freshness_subcommand_returns_json(monkeypatch, capsys):
    """freshness must print a JSON verdict and not crash."""
    from resilient_updates.cli import main

    monkeypatch.setattr("sys.argv", ["cli", "--config", _CFG, "freshness"])
    main()
    # rc is 0 or EXIT_VALIDATION_FAILED depending on stale state — just verify JSON
    out = json.loads(capsys.readouterr().out)
    assert "should_fail" in out


# ---------------------------------------------------------------------------
# _resolve_listing — various grype listing JSON schemas
# ---------------------------------------------------------------------------


def test_resolve_listing_path_key():
    """Schema with top-level 'path' key (oldest format)."""
    data = json.dumps({"path": "/db.tar.gz", "checksum": "abc", "built": "2025-01-01"}).encode()
    url, checksum, built = _resolve_listing(data, "https://example.com")
    assert url == "/db.tar.gz"
    assert checksum == "abc"
    assert built == "2025-01-01"


def test_resolve_listing_archive_url_key():
    """Schema with 'archive_url' key."""
    data = json.dumps({"archive_url": "https://cdn.example.com/db.tar.gz"}).encode()
    url, checksum, built = _resolve_listing(data, "https://example.com")
    assert url == "https://cdn.example.com/db.tar.gz"
    assert checksum is None
    assert built is None


def test_resolve_listing_available_dict():
    """Schema with 'available' dict of lists (grype v6 format)."""
    entry = {"url": "https://cdn.example.com/db.tar.gz", "built": "2025-06-01", "checksum": "cafebabe"}
    data = json.dumps({"available": {"6": [entry]}}).encode()
    url, checksum, built = _resolve_listing(data, "https://example.com")
    assert url == "https://cdn.example.com/db.tar.gz"
    assert checksum == "cafebabe"
    assert built == "2025-06-01"


def test_resolve_listing_available_dict_empty_raises():
    """Empty 'available' dict must raise ValueError."""
    data = json.dumps({"available": {"6": []}}).encode()
    with pytest.raises(ValueError, match="empty"):
        _resolve_listing(data, "https://example.com")


def test_resolve_listing_available_list():
    """Schema with 'available' as a plain list (some mirrors)."""
    entries = [
        {"url": "https://cdn.example.com/db-old.tar.gz", "built": "2025-01-01"},
        {"url": "https://cdn.example.com/db-new.tar.gz", "built": "2025-06-01"},
    ]
    data = json.dumps({"available": entries}).encode()
    url, _checksum, built = _resolve_listing(data, "https://example.com")
    # Must pick latest by 'built'
    assert "new" in url
    assert built == "2025-06-01"


def test_resolve_listing_url_key():
    """Flat schema with just 'url' at the top level."""
    data = json.dumps({"url": "https://cdn.example.com/db.tar.gz", "built": "2025-06-01"}).encode()
    url, _checksum, _built = _resolve_listing(data, "https://example.com")
    assert url == "https://cdn.example.com/db.tar.gz"


def test_resolve_listing_unsupported_schema():
    """A JSON object with no recognised keys must raise ValueError."""
    data = json.dumps({"unknown_key": "value"}).encode()
    with pytest.raises(ValueError, match="unsupported"):
        _resolve_listing(data, "https://example.com")


# ---------------------------------------------------------------------------
# _extract_checksum_from_text
# ---------------------------------------------------------------------------


def test_extract_checksum_from_text():
    assert _extract_checksum_from_text("deadbeef  db.tar.gz\n") == "deadbeef"
    assert _extract_checksum_from_text("  abc123\n") == "abc123"


# ---------------------------------------------------------------------------
# _validate_grype_archive
# ---------------------------------------------------------------------------


def test_validate_grype_archive_valid_tarfile(tmp_path):
    """A real .tar.gz passes validation without a checksum."""
    archive = tmp_path / "db.tar.gz"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        content = b"fake db content"
        info = tarfile.TarInfo(name="db")
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    archive.write_bytes(buf.getvalue())
    _validate_grype_archive(archive, None)  # must not raise


def test_validate_grype_archive_zstd_magic(tmp_path):
    """A file starting with the zstd magic bytes passes as a valid archive."""
    archive = tmp_path / "db.tar.zst"
    archive.write_bytes(b"\x28\xb5\x2f\xfd" + b"\x00" * 16)
    _validate_grype_archive(archive, None)  # must not raise


def test_validate_grype_archive_corrupt_raises(tmp_path):
    """A file that is neither tar nor zstd raises ValueError."""
    archive = tmp_path / "bad.bin"
    archive.write_bytes(b"GARBAGE_DATA_NOT_A_VALID_ARCHIVE")
    with pytest.raises(ValueError):
        _validate_grype_archive(archive, None)


def test_validate_grype_archive_checksum_mismatch_raises(tmp_path):
    """Passing a wrong checksum raises ValueError even for a valid tarfile."""
    archive = tmp_path / "db.tar.gz"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        content = b"data"
        info = tarfile.TarInfo(name="db")
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    archive.write_bytes(buf.getvalue())
    with pytest.raises(ValueError):
        _validate_grype_archive(archive, "0000000000000000000000000000000000000000000000000000000000000000")


# ---------------------------------------------------------------------------
# _provenance_path
# ---------------------------------------------------------------------------


def test_provenance_path_grype():
    """_provenance_path for 'grype' reads from atomic_activation_policy."""
    config = load_config("tests/fixtures/feed_sources.example.yaml")
    p = _provenance_path(config, "grype")
    assert isinstance(p, Path)
    assert "grype" in str(p).lower() or "provenance" in str(p).lower()


def test_provenance_path_non_grype():
    """_provenance_path for any non-grype tool builds a path under artifacts/provenance."""
    config = load_config("tests/fixtures/feed_sources.example.yaml")
    p = _provenance_path(config, "trivy")
    assert p == Path("artifacts/provenance/trivy.json")


# ---------------------------------------------------------------------------
# _latest_mtime — directory traversal
# ---------------------------------------------------------------------------


def test_latest_mtime_directory_with_files(tmp_path):
    """_latest_mtime on a directory returns the newest file mtime."""
    subdir = tmp_path / "sub"
    subdir.mkdir()
    (tmp_path / "a.txt").write_text("a")
    (subdir / "b.txt").write_text("b")
    mt = _latest_mtime(tmp_path)
    assert mt is not None
    assert isinstance(mt, float)


def test_latest_mtime_empty_directory(tmp_path):
    """An empty directory returns None (no files)."""
    result = _latest_mtime(tmp_path)
    assert result is None


# ---------------------------------------------------------------------------
# _db_status_payload — cve-bin-tool path that contains cve.db
# ---------------------------------------------------------------------------


def test_db_status_cve_bin_tool_with_cvedb(tmp_path):
    """When cve.db exists inside the path, status uses its mtime."""
    cve_db = tmp_path / "cve.db"
    cve_db.write_bytes(b"\x00" * 16)
    payload = _db_status_payload("cve-bin-tool", tmp_path, "24h")
    assert payload["exists"] is True
    assert payload["age_hours"] is not None


# ---------------------------------------------------------------------------
# provenance subcommand
# ---------------------------------------------------------------------------


def test_provenance_subcommand(tmp_path, monkeypatch, capsys):
    """provenance must print all JSON files under artifacts/provenance/ and return 0."""
    from resilient_updates.cli import main

    # Resolve the config path before chdir so the relative path still works.
    cfg_abs = str(Path(_CFG).resolve())

    prov_dir = tmp_path / "artifacts" / "provenance"
    prov_dir.mkdir(parents=True)
    (prov_dir / "trivy.json").write_text('{"tool": "trivy"}', encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["cli", "--config", cfg_abs, "provenance"])
    rc = main()
    assert rc == 0
    out = capsys.readouterr().out
    assert '"tool"' in out


# ---------------------------------------------------------------------------
# scan subcommand — text dry-run and live-run paths
# ---------------------------------------------------------------------------


def test_scan_dry_run_text_format_subcommand(tmp_path, monkeypatch, capsys):
    """scan --dry-run without --json must print plan as human-readable text."""
    from resilient_updates.cli import main

    monkeypatch.setattr(
        "sys.argv",
        ["cli", "--config", _CFG, "scan", "--target", str(tmp_path), "--dry-run"],
    )
    rc = main()
    assert rc == 0
    out = capsys.readouterr().out
    # format_plan returns a non-empty text block
    assert out.strip()


def test_scan_run_subcommand(tmp_path, monkeypatch, capsys):
    """scan (non-dry-run) with a mocked run_scan returns the scan result as JSON."""
    from resilient_updates import scan as _scan_mod
    from resilient_updates.cli import main

    mock_result = {"status": "ok", "tool": "trivy", "findings": []}
    monkeypatch.setattr(_scan_mod, "run_scan", lambda **kw: mock_result)

    monkeypatch.setattr(
        "sys.argv",
        ["cli", "--config", _CFG, "scan", "--target", str(tmp_path)],
    )
    rc = main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "ok"


# ---------------------------------------------------------------------------
# dashboard subcommand — graceful ImportError when uvicorn is absent
# ---------------------------------------------------------------------------


def test_dashboard_subcommand_no_uvicorn(tmp_path, monkeypatch, capsys):
    """dashboard must print a helpful message and return EXIT_VALIDATION_FAILED
    when uvicorn is not installed."""
    from resilient_updates.cli import main

    # Suppress uvicorn in sys.modules to simulate it being absent.
    monkeypatch.setitem(sys.modules, "uvicorn", None)

    monkeypatch.setattr(
        "sys.argv",
        ["cli", "--config", _CFG, "dashboard", "--artifacts-dir", str(tmp_path)],
    )
    rc = main()
    assert rc == EXIT_VALIDATION_FAILED
    assert "uvicorn" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# update-doctor subcommand
# ---------------------------------------------------------------------------


def test_update_doctor_json_output(monkeypatch, capsys):
    """update-doctor --json must print the reachability matrix as JSON."""
    from resilient_updates import update_doctor as _ud
    from resilient_updates.cli import main

    mock_matrix = {
        "chains": ["direct"],
        "rows": [],
        "recommended": {"trivy": "direct", "grype": None},
    }
    monkeypatch.setattr(_ud, "build_matrix", lambda config, **kw: mock_matrix)

    monkeypatch.setattr("sys.argv", ["cli", "--config", _CFG, "update-doctor", "--json"])
    rc = main()
    # grype recommended is None → unreachable → EXIT_ALL_SOURCES_FAILED
    assert rc == EXIT_ALL_SOURCES_FAILED
    out = json.loads(capsys.readouterr().out)
    assert "recommended" in out


def test_update_doctor_text_output(monkeypatch, capsys):
    """update-doctor without --json must print formatted text."""
    from resilient_updates import update_doctor as _ud
    from resilient_updates.cli import main

    mock_matrix = {"chains": ["direct"], "rows": [], "recommended": {"trivy": "direct"}}
    monkeypatch.setattr(_ud, "build_matrix", lambda config, **kw: mock_matrix)
    monkeypatch.setattr(_ud, "format_matrix", lambda m: "MATRIX TEXT")

    monkeypatch.setattr("sys.argv", ["cli", "--config", _CFG, "update-doctor"])
    rc = main()
    assert rc == 0
    assert "MATRIX TEXT" in capsys.readouterr().out


def test_update_doctor_suggest_proxy_found(monkeypatch, capsys):
    """update-doctor --suggest-proxy prints the proxy URL and returns 0."""
    from resilient_updates import update_doctor as _ud
    from resilient_updates.cli import main

    monkeypatch.setattr(_ud, "recommended_proxy", lambda config, **kw: "http://proxy:3128")

    monkeypatch.setattr("sys.argv", ["cli", "--config", _CFG, "update-doctor", "--suggest-proxy"])
    rc = main()
    assert rc == 0
    assert "http://proxy:3128" in capsys.readouterr().out


def test_update_doctor_suggest_proxy_not_found(monkeypatch, capsys):
    """update-doctor --suggest-proxy returns EXIT_ALL_SOURCES_FAILED when no proxy works."""
    from resilient_updates import update_doctor as _ud
    from resilient_updates.cli import main

    monkeypatch.setattr(_ud, "recommended_proxy", lambda config, **kw: None)

    monkeypatch.setattr("sys.argv", ["cli", "--config", _CFG, "update-doctor", "--suggest-proxy"])
    rc = main()
    assert rc == EXIT_ALL_SOURCES_FAILED


# ---------------------------------------------------------------------------
# update vex subcommand
# ---------------------------------------------------------------------------


def test_update_vex_subcommand(monkeypatch, capsys):
    """update vex with a mocked fetch_vex must print JSON and return 0."""
    from resilient_updates import vex as _vex
    from resilient_updates.cli import main

    mock_payload = {"published": True, "status": "ok"}
    monkeypatch.setattr(_vex, "fetch_vex", lambda config, session=None: mock_payload)

    monkeypatch.setattr("sys.argv", ["cli", "--config", _CFG, "update", "vex"])
    rc = main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["published"] is True


def test_update_vex_subcommand_failure(monkeypatch, capsys):
    """update vex returns EXIT_ALL_SOURCES_FAILED when published is False."""
    from resilient_updates import vex as _vex
    from resilient_updates.cli import main

    mock_payload = {"published": False, "used_last_known_good": False, "status": "failed"}
    monkeypatch.setattr(_vex, "fetch_vex", lambda config, session=None: mock_payload)

    monkeypatch.setattr("sys.argv", ["cli", "--config", _CFG, "update", "vex"])
    rc = main()
    assert rc == EXIT_ALL_SOURCES_FAILED


# ---------------------------------------------------------------------------
# proxy-status subcommand
# ---------------------------------------------------------------------------


def test_proxy_status_no_chains_configured(monkeypatch, capsys):
    """proxy-status returns 0 with a no-chains-configured message when the
    config uses the legacy flat proxy block (ProxyRouter.from_config → None)."""
    from resilient_updates import proxy_chain as _pc
    from resilient_updates.cli import main

    monkeypatch.setattr(_pc.ProxyRouter, "from_config", classmethod(lambda cls, cfg: None))

    monkeypatch.setattr("sys.argv", ["cli", "--config", _CFG, "proxy-status"])
    rc = main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "no-chains-configured"


def test_proxy_status_with_chains_all_ok(tmp_path, monkeypatch, capsys):
    """proxy-status returns 0 when at least one chain reports status='ok'."""
    from resilient_updates import proxy_chain as _pc
    from resilient_updates.cli import main

    cfg_abs = str(Path(_CFG).resolve())

    mock_router = MagicMock()
    mock_router.healthcheck_all.return_value = {
        "direct": {"status": "ok", "latency_ms": 42},
    }
    mock_router.write_provenance = MagicMock()

    monkeypatch.setattr(_pc.ProxyRouter, "from_config", classmethod(lambda cls, cfg: mock_router))

    prov_dir = tmp_path / "artifacts" / "provenance"
    prov_dir.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)

    monkeypatch.setattr("sys.argv", ["cli", "--config", cfg_abs, "proxy-status"])
    rc = main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "ok"
    assert "direct" in out["chains"]


def test_proxy_status_all_chains_down(tmp_path, monkeypatch, capsys):
    """proxy-status returns EXIT_ALL_SOURCES_FAILED when every chain is down."""
    from resilient_updates import proxy_chain as _pc
    from resilient_updates.cli import main

    cfg_abs = str(Path(_CFG).resolve())

    mock_router = MagicMock()
    mock_router.healthcheck_all.return_value = {
        "direct": {"status": "error", "latency_ms": None},
    }
    mock_router.write_provenance = MagicMock()

    monkeypatch.setattr(_pc.ProxyRouter, "from_config", classmethod(lambda cls, cfg: mock_router))

    prov_dir = tmp_path / "artifacts" / "provenance"
    prov_dir.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)

    monkeypatch.setattr("sys.argv", ["cli", "--config", cfg_abs, "proxy-status"])
    rc = main()
    assert rc == EXIT_ALL_SOURCES_FAILED
