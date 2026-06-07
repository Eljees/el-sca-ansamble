"""Tests for resilient_updates.scanner_diff.

scanner_diff reads two artifacts/ trees (a "before" and an "after") and
returns a structured diff of components + findings, plus a Markdown
renderer.  All tests build fixtures on a tmp_path — no network, no
external scanner needed.
"""

from __future__ import annotations

import json
from pathlib import Path

from resilient_updates.scanner_diff import (
    _components_from_syft,
    _findings_from_cve_bin_tool,
    _findings_from_grype,
    _findings_from_trivy,
    diff_runs,
    to_markdown,
)

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
        grype=_grype(
            [
                ("CVE-2024-0001", "High", "alpha", "1.0"),
                ("CVE-2024-0002", "Critical", "beta", "2.0"),
            ]
        ),
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
                {
                    "vulnerability": {"id": "CVE-1", "severity": "High"},
                    "artifact": {"name": "x", "version": "1.0"},
                },
                {
                    "vulnerability": {"id": "CVE-1", "severity": "High"},
                    "artifact": {"name": "x", "version": "1.0"},
                },
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


# ---------------------------------------------------------------------------
# _components_from_syft edge cases
# ---------------------------------------------------------------------------


def test_components_from_syft_non_dict_input():
    """Non-dict input returns empty list."""
    assert _components_from_syft("not a dict") == []
    assert _components_from_syft(None) == []


def test_components_from_syft_skips_non_dict_items():
    """Non-dict items in artifacts list are skipped."""
    syft = {"artifacts": ["not-a-dict", {"name": "valid", "version": "1.0"}]}
    rows = _components_from_syft(syft)
    assert len(rows) == 1
    assert rows[0]["name"] == "valid"


# ---------------------------------------------------------------------------
# _findings_from_grype edge cases
# ---------------------------------------------------------------------------


def test_findings_from_grype_non_dict_input():
    """Non-dict input returns empty list."""
    assert _findings_from_grype(None) == []
    assert _findings_from_grype([]) == []


# ---------------------------------------------------------------------------
# _findings_from_trivy
# ---------------------------------------------------------------------------


def test_findings_from_trivy_with_vulnerabilities():
    """Trivy report with Results→Vulnerabilities is parsed correctly."""
    trivy = {
        "Results": [
            {
                "Target": "alpine:3.18",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1111",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1",
                        "Severity": "HIGH",
                    }
                ],
            }
        ]
    }
    rows = _findings_from_trivy(trivy)
    assert len(rows) == 1
    assert rows[0]["id"] == "CVE-2024-1111"
    assert rows[0]["tool"] == "trivy"
    assert rows[0]["severity"] == "HIGH"


def test_findings_from_trivy_non_dict_input():
    """Non-dict input returns empty list."""
    assert _findings_from_trivy("bad") == []


# ---------------------------------------------------------------------------
# _findings_from_cve_bin_tool
# ---------------------------------------------------------------------------


def test_findings_from_cve_bin_tool_with_entries():
    """cve-bin-tool report (list of dicts) is parsed correctly."""
    cve_report = [
        {"cve_number": "CVE-2024-2222", "severity": "MEDIUM", "product": "curl", "version": "7.80.0"},
        {"CVE": "CVE-2024-3333", "severity": "LOW", "product": "libz", "version": "1.2.11"},
    ]
    rows = _findings_from_cve_bin_tool(cve_report)
    assert len(rows) == 2
    assert rows[0]["id"] == "CVE-2024-2222"
    assert rows[1]["id"] == "CVE-2024-3333"
    assert rows[0]["tool"] == "cve-bin-tool"


def test_findings_from_cve_bin_tool_non_list_input():
    """Non-list input returns empty list."""
    assert _findings_from_cve_bin_tool({}) == []


def test_findings_from_cve_bin_tool_skips_non_dict_items():
    """Non-dict entries are skipped."""
    rows = _findings_from_cve_bin_tool(["not-a-dict", {"cve_number": "CVE-X", "severity": "LOW"}])
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# DiffSummary.to_dict
# ---------------------------------------------------------------------------


def test_diff_summary_to_dict(tmp_path: Path):
    """DiffSummary.to_dict() returns the expected structure."""
    before = _make_run(tmp_path / "before", syft=_syft([("a", "1")]), grype=_grype([]))
    after = _make_run(
        tmp_path / "after",
        syft=_syft([("a", "1"), ("b", "2")]),
        grype=_grype([("CVE-X", "High", "b", "2")]),
    )
    diff = diff_runs(before, after)
    d = diff.to_dict()
    assert "components" in d
    assert "findings" in d
    assert "severity_delta" in d
    assert d["components"]["added_count"] == 1
    assert d["findings"]["added_count"] == 1


# ---------------------------------------------------------------------------
# Markdown renderer — removed components and resolved findings
# ---------------------------------------------------------------------------


def test_to_markdown_shows_removed_components(tmp_path: Path):
    """Markdown includes a 'Removed components' section when components are removed."""
    before = _make_run(
        tmp_path / "before",
        syft=_syft([("alpha", "1.0"), ("beta", "2.0")]),
        grype=_grype([]),
    )
    after = _make_run(
        tmp_path / "after",
        syft=_syft([("beta", "2.0")]),
        grype=_grype([]),
    )
    md = to_markdown(diff_runs(before, after), before_label="v1", after_label="v2")
    assert "Removed components" in md
    assert "alpha" in md


def test_to_markdown_shows_resolved_findings(tmp_path: Path):
    """Markdown includes a 'Resolved findings' section when findings are removed."""
    before = _make_run(
        tmp_path / "before",
        syft=_syft([]),
        grype=_grype([("CVE-2024-OLD", "High", "alpha", "1.0")]),
    )
    after = _make_run(
        tmp_path / "after",
        syft=_syft([]),
        grype=_grype([]),
    )
    md = to_markdown(diff_runs(before, after), before_label="v1", after_label="v2")
    assert "Resolved findings" in md
    assert "CVE-2024-OLD" in md


# ---------------------------------------------------------------------------
# Trivy and cve-bin-tool integrated into diff_runs
# ---------------------------------------------------------------------------


def test_diff_runs_includes_trivy_findings(tmp_path: Path):
    """Trivy findings from reports/trivy/report.json are included in the diff."""
    trivy_report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-TRIVY",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1",
                        "Severity": "HIGH",
                    }
                ]
            }
        ]
    }
    before = _make_run(tmp_path / "before", syft=_syft([]), grype=_grype([]), trivy=trivy_report)
    after = _make_run(tmp_path / "after", syft=_syft([]), grype=_grype([]), trivy={"Results": []})
    diff = diff_runs(before, after)
    removed_ids = [f["id"] for f in diff.findings_removed]
    assert "CVE-2024-TRIVY" in removed_ids


def test_diff_runs_includes_cve_bin_tool_findings(tmp_path: Path):
    """cve-bin-tool findings from reports/cve-bin-tool/report.json are included."""
    cve_report = [{"cve_number": "CVE-2024-CBT", "severity": "MEDIUM", "product": "curl", "version": "7.80.0"}]
    before = _make_run(tmp_path / "before", syft=_syft([]), grype=_grype([]), cve=[])
    after = _make_run(tmp_path / "after", syft=_syft([]), grype=_grype([]), cve=cve_report)
    diff = diff_runs(before, after)
    added_ids = [f["id"] for f in diff.findings_added]
    assert "CVE-2024-CBT" in added_ids
