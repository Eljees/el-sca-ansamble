"""The cve-bin-tool vendor-collision filter (CYBERSEC-14277).

Shapes mirror the real case: an in-house artifact whose artifactId collides with
several unrelated NVD products, next to genuine third-party libraries.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from resilient_updates.collision_filter import (
    filter_vendor_collisions,
    maven_groups_from_sbom,
    summarize_dropped,
    vendor_matches_group,
)
from resilient_updates.reporting import build_report

SBOM = {
    "artifacts": [
        {
            "name": "core",
            "version": "3.29.3-SNAPSHOT",
            "purl": "pkg:maven/ru.example.agent/core@3.29.3-SNAPSHOT",
        },
        {"name": "xmlsec", "version": "2.3.4", "purl": "pkg:maven/org.apache.santuario/xmlsec@2.3.4"},
        {"name": "snakeyaml", "version": "1.33", "purl": "pkg:maven/org.yaml/snakeyaml@1.33"},
        {"name": "zlib", "version": "1.2.11", "purl": "pkg:generic/zlib@1.2.11"},
    ]
}


def _cbt(vendor, product, version, cve="CVE-2016-9450", severity="CRITICAL"):
    return {
        "tool": "cve-bin-tool",
        "id": cve,
        "severity": severity,
        "score": "",
        "vendor": vendor,
        "product": product,
        "version": version,
        "fixed": "",
        "source": "cve-bin-tool",
    }


@pytest.mark.parametrize(
    "vendor,group,artifact,expected",
    [
        ("apache", "org.apache.santuario", "xmlsec", True),
        ("netty", "io.netty", "netty-codec-http", True),
        ("snakeyaml_project", "org.yaml", "snakeyaml", True),
        ("fasterxml", "com.fasterxml.jackson.core", "jackson-databind", True),
        ("drupal", "ru.example.agent", "core", False),
        ("mobileiron", "ru.example.agent", "core", False),
        ("onlyoffice", "ru.example.agent", "core", False),
    ],
)
def test_vendor_matches_group(vendor, group, artifact, expected):
    assert vendor_matches_group(vendor, group, artifact) is expected


def test_maven_groups_from_sbom_indexes_exact_and_versionless_keys():
    groups = maven_groups_from_sbom(SBOM)
    assert groups[("core", "3.29.3-SNAPSHOT")] == {"ru.example.agent"}
    assert groups[("core", "")] == {"ru.example.agent"}
    assert ("zlib", "1.2.11") not in groups  # not maven, no groupId to reason with


def test_internal_core_loses_drupal_mobileiron_onlyoffice_but_nothing_else():
    """The CYBERSEC-14277 shape: three vendors fanned out onto one in-house module."""
    findings = [
        _cbt("drupal", "core", "3.29.3-SNAPSHOT"),
        _cbt("mobileiron", "core", "3.29.3-SNAPSHOT", cve="CVE-2016-7570"),
        _cbt("onlyoffice", "core", "3.29.3-SNAPSHOT", cve="CVE-2017-10993"),
        _cbt("apache", "xmlsec", "2.3.4", cve="CVE-2023-44483", severity="HIGH"),
        _cbt("snakeyaml_project", "snakeyaml", "1.33", cve="CVE-2022-1471"),
    ]
    kept, dropped = filter_vendor_collisions(findings, maven_groups_from_sbom(SBOM))

    assert [(f["vendor"], f["id"]) for f in dropped] == [
        ("drupal", "CVE-2016-9450"),
        ("mobileiron", "CVE-2016-7570"),
        ("onlyoffice", "CVE-2017-10993"),
    ]
    assert all("not corroborated by groupId ru.example.agent" in f["dropped_reason"] for f in dropped)
    assert [(f["vendor"], f["product"]) for f in kept] == [
        ("apache", "xmlsec"),
        ("snakeyaml_project", "snakeyaml"),
    ]


def test_single_vendor_attribution_is_never_touched():
    """No fan-out signature -> the vendor may have come from purl2cpe; leave it alone
    even when the groupId would not corroborate it (org.springframework -> vmware)."""
    sbom = {"artifacts": [{"purl": "pkg:maven/org.springframework/spring-core@6.2.18"}]}
    findings = [_cbt("vmware", "spring-core", "6.2.18", cve="CVE-2025-1", severity="MEDIUM")]
    kept, dropped = filter_vendor_collisions(findings, maven_groups_from_sbom(sbom))
    assert dropped == [] and kept == findings


def test_legacy_groupid_without_a_dot_names_no_owner():
    """log4j:log4j 1.2.13 really is apache's; a bare groupId cannot contradict that."""
    sbom = {"artifacts": [{"purl": "pkg:maven/log4j/log4j@1.2.13"}]}
    findings = [_cbt("apache", "log4j", "1.2.13"), _cbt("someoneelse", "log4j", "1.2.13", cve="CVE-2")]
    kept, dropped = filter_vendor_collisions(findings, maven_groups_from_sbom(sbom))
    assert dropped == [] and len(kept) == 2


def test_no_sbom_evidence_means_keep():
    """A component the SBOM does not know cannot be called a collision."""
    findings = [_cbt("drupal", "core", "9.9.9"), _cbt("somebody", "unknown-thing", "1.0")]
    kept, dropped = filter_vendor_collisions(findings, maven_groups_from_sbom({"artifacts": []}))
    assert dropped == [] and len(kept) == 2


def test_versionless_fallback_only_when_unambiguous():
    sbom = {
        "artifacts": [
            {"purl": "pkg:maven/ru.example.agent/core@3.29.3"},
            {"purl": "pkg:maven/org.drupal/core@10.1"},
        ]
    }
    # exact version known -> judged; version cve-bin-tool rendered differently -> two groups, no verdict
    kept, dropped = filter_vendor_collisions(
        [
            _cbt("drupal", "core", "3.29.3"),
            _cbt("mobileiron", "core", "3.29.3", cve="CVE-2"),
            _cbt("drupal", "core", "3.29.3-SNAPSHOT"),
            _cbt("mobileiron", "core", "3.29.3-SNAPSHOT", cve="CVE-2"),
        ],
        maven_groups_from_sbom(sbom),
    )
    assert sorted(f["version"] for f in dropped) == ["3.29.3", "3.29.3"]
    assert sorted(f["version"] for f in kept) == ["3.29.3-SNAPSHOT", "3.29.3-SNAPSHOT"]


def test_other_tools_and_unknown_vendor_pass_through():
    grype = {
        "tool": "grype",
        "id": "GHSA-x",
        "severity": "HIGH",
        "vendor": "",
        "product": "core",
        "version": "3.29.3-SNAPSHOT",
    }
    unknown = _cbt("UNKNOWN", "core", "3.29.3-SNAPSHOT")
    kept, dropped = filter_vendor_collisions([grype, unknown], maven_groups_from_sbom(SBOM))
    assert dropped == [] and kept == [grype, unknown]


def test_summarize_dropped_collapses_per_component():
    dropped = [_cbt("drupal", "core", "1.0", cve=f"CVE-2020-{i}") for i in range(5)]
    for f in dropped:
        f["dropped_reason"] = "r"
    rows = summarize_dropped([*dropped, dict(_cbt("mobileiron", "core", "1.0"), dropped_reason="r")])
    assert [(r["vendor"], r["cves"]) for r in rows] == [("drupal", 5), ("mobileiron", 1)]


def test_build_report_drops_collisions_and_says_so(tmp_path: Path):
    artifacts = tmp_path / "artifacts"
    for sub in ("sbom", "reports/grype", "reports/trivy", "reports/cve-bin-tool"):
        (artifacts / sub).mkdir(parents=True)
    target = tmp_path / "agent-3.29.3.tar.gz"
    target.write_bytes(b"x")
    (artifacts / "sbom" / "syft.json").write_text(json.dumps(SBOM), encoding="utf-8")
    (artifacts / "reports" / "grype" / "report.json").write_text(
        json.dumps({"matches": []}), encoding="utf-8"
    )
    (artifacts / "reports" / "trivy" / "report.json").write_text(
        json.dumps({"Results": []}), encoding="utf-8"
    )
    (artifacts / "reports" / "cve-bin-tool" / "report.json").write_text(
        json.dumps(
            [
                {
                    "cve_number": "CVE-2016-9450",
                    "severity": "CRITICAL",
                    "vendor": "drupal",
                    "product": "core",
                    "version": "3.29.3-SNAPSHOT",
                },
                {
                    "cve_number": "CVE-2016-7570",
                    "severity": "CRITICAL",
                    "vendor": "mobileiron",
                    "product": "core",
                    "version": "3.29.3-SNAPSHOT",
                },
                {
                    "cve_number": "CVE-2023-44483",
                    "severity": "HIGH",
                    "vendor": "apache",
                    "product": "xmlsec",
                    "version": "2.3.4",
                },
            ]
        ),
        encoding="utf-8",
    )
    output = tmp_path / "report.md"
    build_report(artifacts, output, target_path=target, case_id="CYBERSEC-14277")
    text = output.read_text(encoding="utf-8")

    assert "- cve-bin-tool findings: `1`" in text
    assert "- Total findings: `1`" in text
    assert "CVE-2016-9450" not in text.split("## Dropped as vendor name collisions")[0]
    assert "## Dropped as vendor name collisions" in text
    assert "drupal" in text and "ru.example.agent" in text
    assert (
        "CRITICAL"
        not in text.split("## Dropped as vendor name collisions")[0]
        .split("Severity counts")[1]
        .split("\n")[0]
    )
