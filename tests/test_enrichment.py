"""Tests for resilient_updates.enrichment (EPSS + CISA KEV)."""
from __future__ import annotations

import json
from pathlib import Path

from resilient_updates.enrichment import (
    enrich_findings,
    load_epss_scores,
    load_kev_set,
)


def _write_epss(root: Path, rows):
    epss_dir = root / "epss"
    epss_dir.mkdir(parents=True, exist_ok=True)
    path = epss_dir / "epss_scores-current.csv"
    lines = ["#model_version:v2024.test,score_date:2024-06-01T00:00:00+0000",
             "cve,epss,percentile"]
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
    _write_epss(tmp_path, [("CVE-2024-0001", "0.12", "0.55"),
                           ("CVE-2024-0002", "0.85", "0.99")])
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
