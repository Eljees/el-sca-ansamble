"""Tests for resilient_updates.scanner_diff.

scanner_diff reads two artifacts/ trees (a "before" and an "after") and
returns a structured diff of components + findings, plus a Markdown
renderer.  All tests build fixtures on a tmp_path — no network, no
external scanner needed.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from resilient_updates.scanner_diff import diff_runs, to_markdown


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_run(root: Path, *, syft, grype, trivy=None, cve=None) -> Path:
    """Build a minimal artifacts/ tree matching the layout build_report consumes."""
    (root / "sbom").mkdir(parents=True, exist_ok=True)
    (root / "reports" / "grype").mkdir(parents=True, exist_ok=True)
    (root / "reports" / "trivy").mkdir(parents=True, exist_ok=True)
    (root / "reports" / "cve-bin-tool").mkdir(parents=True, exist_ok=True)
    (root / "sbom" / "syft.json").write_text(json.dumps(syft), encoding="utf-8")
    (root / "reports" / "grype" / "report.json").write_text(json.dumps(grype), encoding="utf-8")
    if trivy is not None:
        (root / "reports" / "trivy" / "report.json").write_text(json.dumps(trivy), encoding="utf-8")
    if cve is not None:
        (root / "reports" / "cve-bin-tool" / "report.json").write_text(json.dumps(cve), encoding="utf-8")
    return root


def _syft(components):
    return {
        "artifacts": [
            {"name": n, "version": v, "type": "go-module", "purl": f"pkg:golang/{n}@{v}"}
            for n, v in components
        ],
        "source": {},
        "schema": {},
    }


def _grype(findings):
    return {
        "matches": [
            {
                "vulnerability": {"id": cve, "severity": sev},
                "artifact": {"name": name, "version": ver},
            }
            for cve, sev, name, ver in findings
        ]
    }


# ---------------------------------------------------------------------------
# Components diff
# ---------------------------------------------------------------------------

def test_components_added_and_removed(tmp_path: Path):
    before = _make_run(
        tmp_path / "before",
        syft=_syft([("alpha", "1.0"), ("beta", "2.0")]),
        grype=_grype([]),
    )
    after = _make_run(
        tmp_path / "after",
        syft=_syft([("beta", "2.0"), ("gamma", "3.0")]),
        grype=_grype([]),
    )

    diff = diff_runs(before, after)

    added_names = sorted(c["name"] for c in diff.components_added)
    removed_names = sorted(c["name"] for c in diff.components_removed)

    assert added_names == ["gamma"]
    assert removed_names == ["alpha"]
    # beta is in both — keyed on (name, version) so it counts as unchanged.
    assert diff.components_unchanged == 1


def test_components_version_change_counts_as_add_plus_remove(tmp_path: Path):
    before = _make_run(tmp_path / "before", syft=_syft([("alpha", "1.0")]), grype=_grype([]))
    after = _make_run(tmp_path / "after", syft=_syft([("alpha", "1.1")]), grype=_grype([]))

    diff = diff_runs(before, after)

    assert len(diff.components_added) == 1
    assert len(diff.components_removed) == 1
    assert diff.components_added[0]["version"] == "1.1"
    assert diff.components_removed[0]["version"] == "1.0"


# ---------------------------------------------------------------------------
# Findings diff
# ---------------------------------------------------------------------------

def test_findings_added_and_severity_delta(tmp_path: Path):
    before = _make_run(
        tmp_path / "before",
        syft=_syft([]),
        grype=_grype([("CVE-2024-0001", "High", "alpha", "1.0")]),
    )
    after = _make_run(
        tmp_path / "after",
        syft=_syft([]),
        grype=_grype([
            ("CVE-2024-0001", "High", "alpha", "1.0"),
            ("CVE-2024-0002", "Critical", "beta", "2.0"),
        ]),
    )

    diff = diff_runs(before, after)

    added_ids = sorted(f["id"] for f in diff.findings_added)
    removed_ids = sorted(f["id"] for f in diff.findings_removed)

    assert added_ids == ["CVE-2024-0002"]
    assert removed_ids == []
    assert diff.findings_unchanged == 1
    # Severity delta: CRITICAL gained one; HIGH unchanged.
    assert diff.severity_delta.get("CRITICAL", 0) == 1
    assert diff.severity_delta.get("HIGH", 0) == 0


def test_findings_dedup_via_tuple_key(tmp_path: Path):
    """Same (id, product, version, tool) is one finding even if reported twice."""
    after = _make_run(
        tmp_path / "after",
        syft=_syft([]),
        grype={
            "matches": [
                {"vulnerability": {"id": "CVE-1", "severity": "High"},
                 "artifact": {"name": "x", "version": "1.0"}},
                {"vulnerability": {"id": "CVE-1", "severity": "High"},
                 "artifact": {"name": "x", "version": "1.0"}},
            ]
        },
    )
    before = _make_run(tmp_path / "before", syft=_syft([]), grype=_grype([]))

    diff = diff_runs(before, after)

    # Both raw matches collapse to a single "added" entry.
    assert len(diff.findings_added) == 1


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def test_to_markdown_includes_section_headers(tmp_path: Path):
    before = _make_run(tmp_path / "before", syft=_syft([("a", "1")]), grype=_grype([]))
    after = _make_run(
        tmp_path / "after",
        syft=_syft([("a", "1"), ("b", "2")]),
        grype=_grype([("CVE-X", "High", "b", "2")]),
    )

    md = to_markdown(diff_runs(before, after), before_label="v1", after_label="v2")

    assert "# scanner-diff: v1 → v2" in md
    assert "## Severity delta" in md
    assert "## Components" in md
    assert "## Findings" in md
    assert "CVE-X" in md
    assert "+1" in md  # severity delta line for HIGH
