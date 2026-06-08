"""Tests for resilient_updates.enrichment (EPSS + CISA KEV)."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from unittest.mock import patch

from resilient_updates.enrichment import (
    _safe_exists,
    enrich_findings,
    evaluate_enrichment_policy,
    load_epss_scores,
    load_kev_set,
    source_freshness,
)


def _write_epss(root: Path, rows):
    epss_dir = root / "epss"
    epss_dir.mkdir(parents=True, exist_ok=True)
    path = epss_dir / "epss_scores-current.csv"
    lines = ["#model_version:v2024.test,score_date:2024-06-01T00:00:00+0000", "cve,epss,percentile"]
    for cve, epss, percentile in rows:
        lines.append(f"{cve},{epss},{percentile}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_kev(root: Path, ids):
    kev_dir = root / "kev"
    kev_dir.mkdir(parents=True, exist_ok=True)
    path = kev_dir / "known_exploited_vulnerabilities.json"
    path.write_text(
        json.dumps({"vulnerabilities": [{"cveID": x} for x in ids]}),
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# EPSS loader
# ---------------------------------------------------------------------------


def test_load_epss_scores_parses_metadata_header(tmp_path: Path):
    _write_epss(tmp_path, [("CVE-2024-0001", "0.12", "0.55"), ("CVE-2024-0002", "0.85", "0.99")])
    scores = load_epss_scores(roots=[tmp_path])
    assert "CVE-2024-0001" in scores
    assert scores["CVE-2024-0001"]["epss"] == 0.12
    assert scores["CVE-2024-0001"]["percentile"] == 0.55
    assert scores["CVE-2024-0002"]["epss"] == 0.85


def test_load_epss_scores_missing_file_returns_empty(tmp_path: Path):
    assert load_epss_scores(roots=[tmp_path / "nope"]) == {}


def test_load_epss_scores_skips_malformed_rows(tmp_path: Path):
    # CSV with non-numeric epss value — should be dropped, not raise.
    epss_dir = tmp_path / "epss"
    epss_dir.mkdir(parents=True)
    (epss_dir / "epss_scores-current.csv").write_text(
        "cve,epss,percentile\nCVE-X,not-a-float,0.5\nCVE-Y,0.30,0.90\n",
        encoding="utf-8",
    )
    scores = load_epss_scores(roots=[tmp_path])
    assert "CVE-X" not in scores
    assert "CVE-Y" in scores


# ---------------------------------------------------------------------------
# KEV loader
# ---------------------------------------------------------------------------


def test_load_kev_set_picks_up_cve_ids(tmp_path: Path):
    _write_kev(tmp_path, ["CVE-2021-44228", "CVE-2023-44487"])
    kev = load_kev_set(roots=[tmp_path])
    assert "CVE-2021-44228" in kev
    assert "CVE-2023-44487" in kev


def test_load_kev_set_alternate_shape(tmp_path: Path):
    """CISA sometimes ships the dump with `kev_entries` instead of `vulnerabilities`."""
    kev_dir = tmp_path / "kev"
    kev_dir.mkdir(parents=True)
    (kev_dir / "known_exploited_vulnerabilities.json").write_text(
        json.dumps({"kev_entries": [{"cve_id": "CVE-2024-0001"}]}),
        encoding="utf-8",
    )
    kev = load_kev_set(roots=[tmp_path])
    assert kev == {"CVE-2024-0001"}


def test_load_kev_set_missing_returns_empty(tmp_path: Path):
    assert load_kev_set(roots=[tmp_path / "nope"]) == set()


# ---------------------------------------------------------------------------
# enrich_findings
# ---------------------------------------------------------------------------


def test_enrich_findings_adds_epss_and_kev_columns(tmp_path: Path):
    _write_epss(tmp_path, [("CVE-2024-0001", "0.5", "0.8")])
    _write_kev(tmp_path, ["CVE-2024-0002"])
    findings = [
        {"id": "CVE-2024-0001", "severity": "HIGH"},
        {"id": "CVE-2024-0002", "severity": "CRITICAL"},
        {"id": "CVE-9999-0000", "severity": "LOW"},
    ]
    enriched = enrich_findings(
        findings,
        epss=load_epss_scores(roots=[tmp_path]),
        kev=load_kev_set(roots=[tmp_path]),
    )
    by_id = {row["id"]: row for row in enriched}
    assert by_id["CVE-2024-0001"]["epss"] == 0.5
    assert by_id["CVE-2024-0001"]["kev"] == ""
    assert by_id["CVE-2024-0002"]["epss"] == ""
    assert by_id["CVE-2024-0002"]["kev"] == "yes"
    assert by_id["CVE-9999-0000"]["epss"] == ""
    assert by_id["CVE-9999-0000"]["kev"] == ""


# ---------------------------------------------------------------------------
# Freshness / TTL (ADR-0004)
# ---------------------------------------------------------------------------


def test_source_freshness_missing_files_report_absent(tmp_path: Path):
    result = source_freshness(roots=[tmp_path])
    assert result["epss"]["present"] is False
    assert result["epss"]["stale"] is None
    assert result["kev"]["present"] is False


def test_source_freshness_fresh_files_not_stale(tmp_path: Path):
    _write_epss(tmp_path, [("CVE-2024-0001", "0.5", "0.9")])
    _write_kev(tmp_path, ["CVE-2024-0002"])
    result = source_freshness(roots=[tmp_path], epss_max_age_hours=24, kev_max_age_hours=168)
    assert result["epss"]["present"] is True
    assert result["epss"]["stale"] is False
    assert result["epss"]["age_hours"] is not None
    assert result["kev"]["stale"] is False


def test_source_freshness_flags_stale_epss(tmp_path: Path):
    path = _write_epss(tmp_path, [("CVE-2024-0001", "0.5", "0.9")])
    old = time.time() - 73 * 3600  # 73h old
    os.utime(path, (old, old))
    result = source_freshness(roots=[tmp_path], epss_max_age_hours=24)
    assert result["epss"]["stale"] is True
    assert result["epss"]["age_hours"] >= 72


# ---------------------------------------------------------------------------
# evaluate_enrichment_policy (ADR-0004 P3)
# ---------------------------------------------------------------------------


def _stale_epss(tmp_path: Path, hours: int = 100):
    path = _write_epss(tmp_path, [("CVE-2024-0001", "0.5", "0.9")])
    old = time.time() - hours * 3600
    os.utime(path, (old, old))
    return path


def test_policy_fresh_not_stale_no_fail(tmp_path: Path):
    _write_epss(tmp_path, [("CVE-2024-0001", "0.5", "0.9")])
    verdict = evaluate_enrichment_policy({"enrichment_policy": {"on_stale": "fail"}}, roots=[tmp_path])
    assert verdict["stale"] is False
    assert verdict["should_fail"] is False
    assert verdict["on_stale"] == "fail"


def test_policy_stale_fail_mode_sets_should_fail(tmp_path: Path):
    _stale_epss(tmp_path)
    verdict = evaluate_enrichment_policy(
        {"enrichment_policy": {"epss_max_age_hours": 24, "on_stale": "fail"}}, roots=[tmp_path]
    )
    assert verdict["stale"] is True
    assert verdict["should_fail"] is True


def test_policy_stale_warn_mode_does_not_fail(tmp_path: Path):
    _stale_epss(tmp_path)
    verdict = evaluate_enrichment_policy(
        {"enrichment_policy": {"epss_max_age_hours": 24, "on_stale": "warn"}}, roots=[tmp_path]
    )
    assert verdict["stale"] is True
    assert verdict["should_fail"] is False


def test_policy_absent_feeds_not_stale(tmp_path: Path):
    verdict = evaluate_enrichment_policy({"enrichment_policy": {"on_stale": "fail"}}, roots=[tmp_path])
    assert verdict["stale"] is False
    assert verdict["should_fail"] is False


def test_policy_defaults_when_no_config(tmp_path: Path):
    _write_epss(tmp_path, [("CVE-2024-0001", "0.5", "0.9")])
    verdict = evaluate_enrichment_policy(None, roots=[tmp_path])
    assert verdict["on_stale"] == "warn"
    assert verdict["should_fail"] is False


# ---------------------------------------------------------------------------
# Exception / edge-case paths (coverage for previously uncovered branches)
# ---------------------------------------------------------------------------


def test_safe_exists_returns_false_on_oserror():
    """_safe_exists must swallow OSError (e.g. PermissionError on /root/... in containers)."""
    p = Path("/some/path")
    with patch.object(Path, "exists", side_effect=PermissionError("denied")):
        assert _safe_exists(p) is False


def test_load_epss_scores_empty_after_metadata_header_returns_empty(tmp_path: Path):
    """File with only a #metadata row and nothing else → returns {}."""
    epss_dir = tmp_path / "epss"
    epss_dir.mkdir(parents=True)
    (epss_dir / "epss_scores-current.csv").write_text(
        "#model_version:v2024.test,score_date:2024-06-01T00:00:00+0000\n",
        encoding="utf-8",
    )
    assert load_epss_scores(roots=[tmp_path]) == {}


def test_load_epss_scores_missing_required_columns_returns_empty(tmp_path: Path):
    """CSV without 'cve' or 'epss' column names → returns {} (not a crash)."""
    epss_dir = tmp_path / "epss"
    epss_dir.mkdir(parents=True)
    (epss_dir / "epss_scores-current.csv").write_text(
        "date,score,percentile\n2024-01-01,0.5,0.9\n",
        encoding="utf-8",
    )
    assert load_epss_scores(roots=[tmp_path]) == {}


def test_load_epss_scores_oserror_on_open_is_skipped(tmp_path: Path):
    """If opening the CSV raises OSError the root is skipped and {} is returned."""
    epss_dir = tmp_path / "epss"
    epss_dir.mkdir(parents=True)
    target = epss_dir / "epss_scores-current.csv"
    target.write_text("cve,epss,percentile\nCVE-X,0.1,0.5\n", encoding="utf-8")

    original_open = Path.open

    def _patched_open(self, *args, **kwargs):
        if self == target:
            raise OSError("simulated read error")
        return original_open(self, *args, **kwargs)

    with patch.object(Path, "open", _patched_open):
        assert load_epss_scores(roots=[tmp_path]) == {}


def test_load_epss_scores_percentile_malformed_stored_as_empty(tmp_path: Path):
    """Row with bad percentile value → percentile stored as '' but row is kept."""
    epss_dir = tmp_path / "epss"
    epss_dir.mkdir(parents=True)
    (epss_dir / "epss_scores-current.csv").write_text(
        "cve,epss,percentile\nCVE-2024-0001,0.42,NOT_A_FLOAT\n",
        encoding="utf-8",
    )
    scores = load_epss_scores(roots=[tmp_path])
    assert "CVE-2024-0001" in scores
    assert scores["CVE-2024-0001"]["epss"] == 0.42
    assert scores["CVE-2024-0001"]["percentile"] == ""


def test_load_kev_set_invalid_json_is_skipped(tmp_path: Path):
    """A KEV file containing invalid JSON is silently skipped → returns empty set."""
    kev_dir = tmp_path / "kev"
    kev_dir.mkdir(parents=True)
    (kev_dir / "known_exploited_vulnerabilities.json").write_text(
        "{not: valid json",
        encoding="utf-8",
    )
    assert load_kev_set(roots=[tmp_path]) == set()


def test_load_kev_set_oserror_on_read_is_skipped(tmp_path: Path):
    """If reading the KEV file raises OSError the root is skipped → returns empty set."""
    kev_dir = tmp_path / "kev"
    kev_dir.mkdir(parents=True)
    target = kev_dir / "known_exploited_vulnerabilities.json"
    target.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2024-1111"}]}))

    original_read_text = Path.read_text

    def _patched_read_text(self, *args, **kwargs):
        if self == target:
            raise OSError("simulated read error")
        return original_read_text(self, *args, **kwargs)

    with patch.object(Path, "read_text", _patched_read_text):
        assert load_kev_set(roots=[tmp_path]) == set()


def test_candidate_roots_respects_env_vars(tmp_path: Path, monkeypatch):
    """EL_SCA_ENRICHMENT_ROOT and CVE_BIN_TOOL_DB_ROOT env vars are prepended to the root list."""
    custom_root = tmp_path / "custom"
    custom_root.mkdir()
    _write_epss(custom_root, [("CVE-2024-ENV", "0.77", "0.88")])

    monkeypatch.setenv("EL_SCA_ENRICHMENT_ROOT", str(custom_root))
    # CVE_BIN_TOOL_DB_ROOT points to a non-existent path; should be filtered silently
    monkeypatch.setenv("CVE_BIN_TOOL_DB_ROOT", str(tmp_path / "nonexistent"))

    scores = load_epss_scores()  # uses _candidate_roots() internally
    assert "CVE-2024-ENV" in scores
