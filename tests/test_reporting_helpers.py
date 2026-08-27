"""Unit tests for resilient_updates.reporting helper functions.

The existing test_reporting.py covers build_report end-to-end.
These tests cover the pure helper functions that transform raw scanner JSON
into normalised finding rows — functions that could silently break if a
scanner changes its output schema.

See docs/audit/130-fixups-2026-06-01c.md §2.2 for context.
"""

from __future__ import annotations

import os
from pathlib import Path

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


# ─────────────────────────────────────────────────────────────────────────────
# _collect_paths — the report's Evidence section
#
# Regression for CYBERSEC-14277 (2026-08-27): artifacts/ is shared state reused
# by every scan the server ever ran, and _collect_paths walked all of it. A
# report about agent-3.29.3.tar.gz listed prometheus, PIX_Process_Studio,
# avandoc, ssdu and other customers' delivery filenames plus archived runs of
# unrelated tickets. The findings themselves were correct — only this listing
# leaked. Evidence must be limited to the current run's own output.
# ─────────────────────────────────────────────────────────────────────────────


def _touch(path, *, mtime=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}", encoding="utf-8")
    if mtime is not None:
        os.utime(path, (mtime, mtime))


def test_collect_paths_excludes_other_cases_and_stale_leftovers(tmp_path):
    import time

    from resilient_updates.reporting import _collect_paths

    root = tmp_path / "artifacts"
    now = time.time()

    # This run's own output.
    for rel in (
        "sbom/syft.json",
        "reports/grype/report.json",
        "reports/trivy/report.json",
        "reports/cve-bin-tool/report.json",
        "reports/final/index.html",
        "summary.json",
        "provenance/grype.json",
        "db_status/grype.json",
        "extracted/current/extraction_manifest.json",
    ):
        _touch(root / rel, mtime=now)

    # Other cases / not this run — must never appear.
    _touch(root / "runs/CYBERSEC-11531-20260707-132613/summary.json", mtime=now)
    _touch(root / "runs/CYBERSEC-11531-20260707-132613/provenance/grype.json", mtime=now)
    _touch(root / "uploads/artifact-20260709-143029-f6e9a5/PIX_Process_Studio_2-2.zip", mtime=now)
    _touch(root / "logs/dashboard.log", mtime=now)
    _touch(root / "_sbom_probe/CycloneDX-SBOM-RTK-DAS.json", mtime=now)
    _touch(root / "db_status/updates/20260827-114432_all.log", mtime=now)
    _touch(root / "run-scan.log.3", mtime=now)
    # Extracted payload itself is not evidence (only its manifest is).
    _touch(root / "extracted/current/depth0/some-file.json", mtime=now)
    # Stale analyzer report from an earlier APK run, this run was a tarball.
    _touch(root / "reports/apk/apk_analysis.txt", mtime=now - 9 * 24 * 3600)

    collected = {str(Path(p).relative_to(root)).replace("\\", "/") for p in _collect_paths(root)}

    assert "sbom/syft.json" in collected
    assert "reports/final/index.html" in collected
    assert "provenance/grype.json" in collected
    assert "db_status/grype.json" in collected
    assert "extracted/current/extraction_manifest.json" in collected

    for leaked in (
        "runs/CYBERSEC-11531-20260707-132613/summary.json",
        "runs/CYBERSEC-11531-20260707-132613/provenance/grype.json",
        "uploads/artifact-20260709-143029-f6e9a5/PIX_Process_Studio_2-2.zip",
        "logs/dashboard.log",
        "_sbom_probe/CycloneDX-SBOM-RTK-DAS.json",
        "db_status/updates/20260827-114432_all.log",
        "run-scan.log.3",
        "extracted/current/depth0/some-file.json",
        "reports/apk/apk_analysis.txt",
    ):
        assert leaked not in collected, f"{leaked} must not be listed as this run's evidence"


def test_report_stem_combines_case_and_package():
    from resilient_updates.reporting import report_stem

    assert (
        report_stem("CYBERSEC-13860", "/srv/x/Reliz-RTK_DAS_1.10.31.0-KHED.zip")
        == "CYBERSEC-13860_Reliz-RTK_DAS_1.10.31.0-KHED_report"
    )
    # Either part alone still yields a usable name.
    assert report_stem("CYBERSEC-1", "") == "CYBERSEC-1_report"
    assert report_stem("", "agent-3.29.3.tar.gz") == "agent-3.29.3_report"
    # The UNKNOWN placeholder is not a case id.
    assert report_stem("CYBERSEC-UNKNOWN", "") == ""
    assert report_stem(None, None) == ""


def test_package_stem_strips_archives_and_transliterates():
    from resilient_updates.reporting import package_stem

    assert package_stem("agent-3.29.3.tar.gz") == "agent-3.29.3"
    assert package_stem("/deep/path/app.apk") == "app"
    assert package_stem("Сборки на проверку ИБ.zip") == "Sborki-na-proverku-IB"
    assert package_stem("") == ""


def test_collect_paths_keeps_fresh_analyzer_report(tmp_path):
    """The apk/win analyzer report IS evidence when it belongs to this run."""
    import time

    from resilient_updates.reporting import _collect_paths

    root = tmp_path / "artifacts"
    now = time.time()
    _touch(root / "reports/grype/report.json", mtime=now)
    _touch(root / "reports/apk/apk_analysis.txt", mtime=now)

    collected = {str(Path(p).relative_to(root)).replace("\\", "/") for p in _collect_paths(root)}
    assert "reports/apk/apk_analysis.txt" in collected
