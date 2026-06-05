"""Unit tests for resilient_updates.reporting helper functions.

The existing test_reporting.py covers build_report end-to-end.
These tests cover the pure helper functions that transform raw scanner JSON
into normalised finding rows — functions that could silently break if a
scanner changes its output schema.

See docs/audit/130-fixups-2026-06-01c.md §2.2 for context.
"""

from __future__ import annotations

import pytest

from resilient_updates.reporting import (
    _cve_bin_tool_findings,
    _dedup_findings,
    _grype_findings,
    _markdown_table,
    _normalize_severity,
    _syft_count,
    _trivy_findings,
)

# ─────────────────────────────────────────────────────────────────────────────
# _normalize_severity
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.smoke
@pytest.mark.parametrize(
    "value,expected",
    [
        ("critical", "CRITICAL"),
        ("HIGH", "HIGH"),
        ("medium", "MEDIUM"),
        (None, "UNKNOWN"),
        ("", "UNKNOWN"),
        (0, "UNKNOWN"),  # falsy int
        ("unknown", "UNKNOWN"),
    ],
)
def test_normalize_severity(value, expected):
    assert _normalize_severity(value) == expected


# ─────────────────────────────────────────────────────────────────────────────
# _syft_count
# ─────────────────────────────────────────────────────────────────────────────


def test_syft_count_artifacts_list():
    assert _syft_count({"artifacts": ["a", "b", "c"]}) == 3


def test_syft_count_components_fallback():
    assert _syft_count({"components": [1, 2]}) == 2


def test_syft_count_empty_artifacts():
    assert _syft_count({"artifacts": []}) == 0


def test_syft_count_not_a_dict():
    assert _syft_count(None) == 0
    assert _syft_count([]) == 0
    assert _syft_count("string") == 0


def test_syft_count_no_known_key():
    assert _syft_count({"packages": [1, 2]}) == 0


# ─────────────────────────────────────────────────────────────────────────────
# _grype_findings
# ─────────────────────────────────────────────────────────────────────────────


def _grype_match(cve_id="CVE-2024-1234", severity="HIGH", pkg="libfoo", version="1.0"):
    return {
        "vulnerability": {"id": cve_id, "severity": severity, "cvss": []},
        "artifact": {"name": pkg, "version": version, "type": "deb"},
    }


def test_grype_findings_typical():
    data = {"matches": [_grype_match()]}
    result = _grype_findings(data)
    assert len(result) == 1
    row = result[0]
    assert row["tool"] == "grype"
    assert row["id"] == "CVE-2024-1234"
    assert row["severity"] == "HIGH"
    assert row["product"] == "libfoo"
    assert row["version"] == "1.0"


def test_grype_findings_empty_matches():
    assert _grype_findings({"matches": []}) == []


def test_grype_findings_null_input():
    assert _grype_findings(None) == []
    assert _grype_findings("string") == []


def test_grype_findings_missing_vuln_id_falls_back():
    match = {
        "vulnerability": {"name": "GHSA-xxxx", "severity": "MEDIUM", "cvss": []},
        "artifact": {"name": "pkg", "version": "2.0", "type": "java"},
    }
    result = _grype_findings({"matches": [match]})
    assert result[0]["id"] == "GHSA-xxxx"


def test_grype_findings_no_id_no_name_is_unknown():
    match = {
        "vulnerability": {"severity": "LOW", "cvss": []},
        "artifact": {"name": "pkg", "version": "1", "type": "rpm"},
    }
    result = _grype_findings({"matches": [match]})
    assert result[0]["id"] == "UNKNOWN"


def test_grype_findings_cvss_basescore_extracted():
    match = {
        "vulnerability": {
            "id": "CVE-2024-9999",
            "severity": "CRITICAL",
            "cvss": [{"metrics": {"baseScore": 9.8}}],
        },
        "artifact": {"name": "openssl", "version": "3.0.0", "type": "binary"},
    }
    result = _grype_findings({"matches": [match]})
    assert result[0]["score"] == 9.8


# ─────────────────────────────────────────────────────────────────────────────
# _trivy_findings
# ─────────────────────────────────────────────────────────────────────────────


def _trivy_result(vuln_id="CVE-2024-5678", severity="CRITICAL", pkg="curl", version="7.88"):
    return {
        "Type": "debian",
        "Vulnerabilities": [
            {
                "VulnerabilityID": vuln_id,
                "Severity": severity,
                "PkgName": pkg,
                "InstalledVersion": version,
                "CVSS": {},
            }
        ],
    }


def test_trivy_findings_typical():
    data = {"Results": [_trivy_result()]}
    result = _trivy_findings(data)
    assert len(result) == 1
    row = result[0]
    assert row["tool"] == "trivy"
    assert row["id"] == "CVE-2024-5678"
    assert row["severity"] == "CRITICAL"
    assert row["product"] == "curl"
    assert row["vendor"] == "debian"


def test_trivy_findings_empty_results():
    assert _trivy_findings({"Results": []}) == []


def test_trivy_findings_null_input():
    assert _trivy_findings(None) == []


def test_trivy_findings_empty_vulnerabilities():
    data = {"Results": [{"Type": "alpine", "Vulnerabilities": []}]}
    assert _trivy_findings(data) == []


def test_trivy_findings_missing_vuln_id_is_unknown():
    data = {
        "Results": [
            {
                "Type": "rpm",
                "Vulnerabilities": [
                    {"Severity": "HIGH", "PkgName": "bash", "InstalledVersion": "5.0", "CVSS": {}}
                ],
            }
        ]
    }
    result = _trivy_findings(data)
    assert result[0]["id"] == "UNKNOWN"


def test_trivy_findings_nvd_cvss_score():
    data = {
        "Results": [
            {
                "Type": "alpine",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "Severity": "HIGH",
                        "PkgName": "zlib",
                        "InstalledVersion": "1.2.11",
                        "CVSS": {"nvd": {"V3Score": 8.1}},
                    }
                ],
            }
        ]
    }
    result = _trivy_findings(data)
    assert result[0]["score"] == 8.1


# ─────────────────────────────────────────────────────────────────────────────
# _cve_bin_tool_findings
# ─────────────────────────────────────────────────────────────────────────────


def test_cve_bin_tool_findings_list_input():
    data = [{"cve_number": "CVE-2023-0001", "severity": "HIGH", "product": "openssl", "version": "1.1.1"}]
    result = _cve_bin_tool_findings(data)
    assert len(result) == 1
    assert result[0]["id"] == "CVE-2023-0001"
    assert result[0]["tool"] == "cve-bin-tool"
    assert result[0]["severity"] == "HIGH"


def test_cve_bin_tool_findings_dict_with_findings_key():
    data = {
        "findings": [
            {"cve_number": "CVE-2023-0002", "severity": "CRITICAL", "product": "curl", "version": "7.0"}
        ]
    }
    result = _cve_bin_tool_findings(data)
    assert result[0]["id"] == "CVE-2023-0002"


def test_cve_bin_tool_findings_dict_with_results_key():
    data = {"results": [{"cve": "CVE-2023-0003", "severity": "medium", "product": "zlib", "version": "1.2"}]}
    result = _cve_bin_tool_findings(data)
    assert result[0]["id"] == "CVE-2023-0003"
    assert result[0]["severity"] == "MEDIUM"


def test_cve_bin_tool_findings_empty_list():
    assert _cve_bin_tool_findings([]) == []


def test_cve_bin_tool_findings_null_input():
    assert _cve_bin_tool_findings(None) == []


def test_cve_bin_tool_findings_no_id_is_unknown():
    data = [{"severity": "LOW", "product": "foo", "version": "1.0"}]
    result = _cve_bin_tool_findings(data)
    assert result[0]["id"] == "UNKNOWN"


def test_cve_bin_tool_findings_skips_non_dicts():
    data = [{"cve_number": "CVE-X", "severity": "HIGH", "product": "a", "version": "1"}, "not-a-dict", 42]
    result = _cve_bin_tool_findings(data)
    assert len(result) == 1


# ─────────────────────────────────────────────────────────────────────────────
# _dedup_findings
# ─────────────────────────────────────────────────────────────────────────────


def test_dedup_removes_identical_tuples():
    finding = {"id": "CVE-X", "product": "lib", "version": "1.0", "tool": "grype", "severity": "HIGH"}
    result = _dedup_findings([finding, finding])
    assert len(result) == 1


def test_dedup_keeps_different_tools():
    base = {"id": "CVE-X", "product": "lib", "version": "1.0", "severity": "HIGH"}
    grype = {**base, "tool": "grype"}
    trivy = {**base, "tool": "trivy"}
    result = _dedup_findings([grype, trivy])
    assert len(result) == 2


def test_dedup_keeps_different_versions():
    base = {"id": "CVE-X", "product": "lib", "tool": "grype", "severity": "HIGH"}
    v1 = {**base, "version": "1.0"}
    v2 = {**base, "version": "2.0"}
    result = _dedup_findings([v1, v2])
    assert len(result) == 2


# ─────────────────────────────────────────────────────────────────────────────
# _markdown_table
# ─────────────────────────────────────────────────────────────────────────────


def test_markdown_table_empty_returns_no_findings_message():
    result = _markdown_table([])
    assert "не обнаружены" in result


def test_markdown_table_renders_rows():
    findings = [
        {
            "tool": "grype",
            "id": "CVE-2024-1",
            "severity": "CRITICAL",
            "score": "9.8",
            "vendor": "os",
            "product": "curl",
            "version": "7.0",
            "source": "grype",
        },
    ]
    result = _markdown_table(findings)
    assert "CVE-2024-1" in result
    assert "CRITICAL" in result
    assert "|" in result


def test_markdown_table_sorts_critical_before_high():
    findings = [
        {
            "tool": "grype",
            "id": "B",
            "severity": "HIGH",
            "score": "",
            "vendor": "",
            "product": "",
            "version": "",
            "source": "",
        },
        {
            "tool": "grype",
            "id": "A",
            "severity": "CRITICAL",
            "score": "",
            "vendor": "",
            "product": "",
            "version": "",
            "source": "",
        },
    ]
    result = _markdown_table(findings)
    assert result.index("CRITICAL") < result.index("HIGH")


def test_markdown_table_with_enrichment_adds_epss_kev_columns():
    findings = [
        {
            "tool": "grype",
            "id": "CVE-2024-X",
            "severity": "CRITICAL",
            "score": "9.5",
            "vendor": "",
            "product": "ssl",
            "version": "1.0",
            "source": "grype",
            "epss": "0.9512",
            "kev": "yes",
        },
    ]
    result = _markdown_table(findings)
    assert "EPSS" in result
    assert "KEV" in result
    assert "0.951" in result
    assert "yes" in result
