from pathlib import Path
import json

from resilient_updates.reporting import build_report, _dedup_findings


def test_build_report_aggregates_scanner_outputs(tmp_path: Path):
    reports = tmp_path / "artifacts"
    (reports / "sbom").mkdir(parents=True)
    (reports / "reports" / "grype").mkdir(parents=True)
    (reports / "reports" / "trivy").mkdir(parents=True)
    (reports / "reports" / "cve-bin-tool").mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir()
    (target / "prometheus").write_text("binary-placeholder", encoding="utf-8")
    (reports / "sbom" / "syft.json").write_text(json.dumps({"artifacts": [{"name": "prometheus"}]}), encoding="utf-8")
    (reports / "reports" / "grype" / "report.json").write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {"id": "GHSA-test", "severity": "High"},
                        "artifact": {"name": "lib", "version": "1.0.0", "type": "go-module"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (reports / "reports" / "trivy" / "report.json").write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Type": "gobinary",
                        "Vulnerabilities": [
                            {"VulnerabilityID": "CVE-2024-0001", "Severity": "CRITICAL", "PkgName": "go", "InstalledVersion": "1.0"}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (reports / "reports" / "cve-bin-tool" / "report.json").write_text(
        json.dumps([{"cve_number": "CVE-2024-0002", "severity": "HIGH", "vendor": "golang", "product": "go", "version": "1.0"}]),
        encoding="utf-8",
    )

    output = build_report(reports, tmp_path / "report.md", target, str(target), "CYBERSEC-11531")
    text = output.read_text(encoding="utf-8")

    assert "Syft components: `1`" in text
    assert "GHSA-test" in text
    assert "CVE-2024-0001" in text
    assert "CVE-2024-0002" in text


def test_build_report_reads_provenance_from_evidence_dir(tmp_path: Path):
    reports = tmp_path / "evidence"
    (reports / "sbom").mkdir(parents=True)
    (reports / "reports" / "grype").mkdir(parents=True)
    (reports / "reports" / "trivy").mkdir(parents=True)
    (reports / "reports" / "cve-bin-tool").mkdir(parents=True)
    (reports / "provenance").mkdir(parents=True)
    (reports / "sbom" / "syft.json").write_text(json.dumps({"artifacts": []}), encoding="utf-8")
    (reports / "reports" / "grype" / "report.json").write_text(json.dumps({"matches": []}), encoding="utf-8")
    (reports / "reports" / "trivy" / "report.json").write_text(json.dumps({"Results": []}), encoding="utf-8")
    (reports / "reports" / "cve-bin-tool" / "report.json").write_text(json.dumps([]), encoding="utf-8")
    (reports / "provenance" / "grype.json").write_text("{}", encoding="utf-8")
    output = build_report(reports, tmp_path / "report.md", None, "target", "CASE")
    text = output.read_text(encoding="utf-8")

    assert "provenance" in text
    assert "grype.json" in text


def test_build_report_uses_tool_specific_report_paths_when_report_names_collide(tmp_path: Path):
    reports = tmp_path / "artifacts"
    (reports / "sbom").mkdir(parents=True)
    (reports / "reports" / "grype").mkdir(parents=True)
    (reports / "reports" / "trivy").mkdir(parents=True)
    (reports / "reports" / "cve-bin-tool").mkdir(parents=True)
    (reports / "sbom" / "syft.json").write_text(json.dumps({"artifacts": []}), encoding="utf-8")
    (reports / "reports" / "grype" / "report.json").write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {"id": "GHSA-grype", "severity": "HIGH"},
                        "artifact": {"name": "grype-lib", "version": "1.0.0", "type": "go-module"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (reports / "reports" / "trivy" / "report.json").write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Type": "library",
                        "Vulnerabilities": [
                            {"VulnerabilityID": "CVE-trivy", "Severity": "CRITICAL", "PkgName": "trivy-lib", "InstalledVersion": "2.0.0"}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (reports / "reports" / "cve-bin-tool" / "report.json").write_text(
        json.dumps([{"cve_number": "CVE-cvebt", "severity": "HIGH", "vendor": "vendor", "product": "component", "version": "3.0.0"}]),
        encoding="utf-8",
    )

    output = build_report(reports, tmp_path / "report.md", None, "target", "CASE")
    text = output.read_text(encoding="utf-8")

    assert "GHSA-grype" in text
    assert "CVE-trivy" in text
    assert "CVE-cvebt" in text


def test_build_report_fails_when_required_scan_artifacts_are_missing(tmp_path: Path):
    reports = tmp_path / "artifacts"
    (reports / "reports" / "grype").mkdir(parents=True)
    (reports / "reports" / "grype" / "report.json").write_text(json.dumps({"matches": []}), encoding="utf-8")

    try:
        build_report(reports, tmp_path / "report.md", None, "target", "CASE")
    except FileNotFoundError as exc:
        message = str(exc)
    else:
        raise AssertionError("build_report should fail when required scan artifacts are missing")

    assert "missing required scan artifacts" in message
    assert "syft" in message
    assert "trivy" in message
    assert "cve-bin-tool" in message


def _make_minimal_reports(root: Path, syft_artifacts: list | None = None) -> None:
    """Create the minimum valid report structure under *root*."""
    (root / "sbom").mkdir(parents=True, exist_ok=True)
    (root / "reports" / "grype").mkdir(parents=True, exist_ok=True)
    (root / "reports" / "trivy").mkdir(parents=True, exist_ok=True)
    (root / "reports" / "cve-bin-tool").mkdir(parents=True, exist_ok=True)
    artifacts = syft_artifacts if syft_artifacts is not None else []
    (root / "sbom" / "syft.json").write_text(json.dumps({"artifacts": artifacts}), encoding="utf-8")
    (root / "reports" / "grype" / "report.json").write_text(json.dumps({"matches": []}), encoding="utf-8")
    (root / "reports" / "trivy" / "report.json").write_text(json.dumps({"Results": []}), encoding="utf-8")
    (root / "reports" / "cve-bin-tool" / "report.json").write_text(json.dumps([]), encoding="utf-8")


def test_build_report_auto_detects_case_id_from_target_when_missing(tmp_path: Path):
    reports = tmp_path / "artifacts"
    _make_minimal_reports(reports, syft_artifacts=[{"name": "android-app"}])

    display_target = r"D:\__tests\_SCA\CYBERSEC-12080\android-build.zip"
    output = build_report(reports, tmp_path / "report.md", None, display_target)
    text = output.read_text(encoding="utf-8")

    assert text.startswith("# CYBERSEC-12080: контейнерный SCA-отчет")
    assert "CYBERSEC-11531" not in text


def test_build_report_uses_unknown_case_id_when_missing_and_not_detectable(tmp_path: Path):
    reports = tmp_path / "artifacts"
    _make_minimal_reports(reports, syft_artifacts=[{"name": "component"}])

    output = build_report(reports, tmp_path / "report.md", None, "target-without-ticket")
    text = output.read_text(encoding="utf-8")

    assert text.startswith("# CYBERSEC-UNKNOWN: контейнерный SCA-отчет")
    assert "CYBERSEC-11531" not in text


def test_build_report_warns_when_syft_has_zero_components(tmp_path: Path):
    reports = tmp_path / "artifacts"
    _make_minimal_reports(reports, syft_artifacts=[])  # explicitly 0 components

    output = build_report(reports, tmp_path / "report.md", None, "target", "CASE")
    text = output.read_text(encoding="utf-8")

    assert "syft: 0 components" in text
    assert "extraction" in text.lower()


def test_build_report_does_not_warn_when_syft_has_components(tmp_path: Path):
    reports = tmp_path / "artifacts"
    _make_minimal_reports(reports, syft_artifacts=[{"name": "libc"}])

    output = build_report(reports, tmp_path / "report.md", None, "target", "CASE")
    text = output.read_text(encoding="utf-8")

    assert "syft: 0 components" not in text


def test_build_report_warns_when_cve_bin_tool_timed_out(tmp_path: Path):
    reports = tmp_path / "artifacts"
    _make_minimal_reports(reports)
    # Write the sentinel file that update_cve_bin_tool.sh creates on timeout
    (reports / "reports" / "cve-bin-tool" / "timeout.flag").write_text(
        "timed_out_after=600\n", encoding="utf-8"
    )

    output = build_report(reports, tmp_path / "report.md", None, "target", "CASE")
    text = output.read_text(encoding="utf-8")

    assert "cve-bin-tool" in text
    assert "timed out" in text
    assert "600" in text
    assert "CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS" in text


def test_build_report_no_timeout_warning_without_flag(tmp_path: Path):
    reports = tmp_path / "artifacts"
    _make_minimal_reports(reports)
    # No timeout.flag → no warning

    output = build_report(reports, tmp_path / "report.md", None, "target", "CASE")
    text = output.read_text(encoding="utf-8")

    assert "timed out" not in text


def test_build_report_timeout_warning_handles_missing_seconds_gracefully(tmp_path: Path):
    """timeout.flag exists but is empty or malformed — should not crash, shows 'unknown'."""
    reports = tmp_path / "artifacts"
    _make_minimal_reports(reports)
    (reports / "reports" / "cve-bin-tool" / "timeout.flag").write_text("", encoding="utf-8")

    output = build_report(reports, tmp_path / "report.md", None, "target", "CASE")
    text = output.read_text(encoding="utf-8")

    assert "timed out" in text
    assert "unknown" in text


def test_build_report_summarizes_extraction_manifest_without_listing_payload(tmp_path: Path):
    reports = tmp_path / "artifacts"
    (reports / "sbom").mkdir(parents=True)
    (reports / "reports" / "grype").mkdir(parents=True)
    (reports / "reports" / "trivy").mkdir(parents=True)
    (reports / "reports" / "cve-bin-tool").mkdir(parents=True)
    (reports / "extracted" / "current" / "payload").mkdir(parents=True)
    (reports / "sbom" / "syft.json").write_text(json.dumps({"artifacts": []}), encoding="utf-8")
    (reports / "reports" / "grype" / "report.json").write_text(json.dumps({"matches": []}), encoding="utf-8")
    (reports / "reports" / "trivy" / "report.json").write_text(json.dumps({"Results": []}), encoding="utf-8")
    (reports / "reports" / "cve-bin-tool" / "report.json").write_text(json.dumps([]), encoding="utf-8")
    (reports / "extracted" / "current" / "extraction_manifest.json").write_text(
        json.dumps({"status": "pass", "extracted_count": 2}),
        encoding="utf-8",
    )
    (reports / "extracted" / "current" / "payload" / "large.bin").write_text("payload", encoding="utf-8")

    output = build_report(reports, tmp_path / "report.md", None, "target", "CASE")
    text = output.read_text(encoding="utf-8")

    assert "Extraction status: `pass`" in text
    assert "Extracted archives: `2`" in text
    assert "extraction_manifest.json" in text
    assert "large.bin" not in text


# ── _dedup_findings tests ─────────────────────────────────────────────────────

def _make_finding(cve_id: str, product: str, version: str = "1.0", tool: str = "grype") -> dict:
    return {"id": cve_id, "product": product, "version": version, "tool": tool,
            "severity": "HIGH", "score": 7.5, "vendor": "test", "source": tool}


def test_dedup_findings_removes_exact_duplicates():
    """Same CVE for same product/version/tool appears twice → deduplicated to one."""
    findings = [
        _make_finding("CVE-2026-001", "prometheus"),
        _make_finding("CVE-2026-001", "prometheus"),  # duplicate from promtool
    ]
    result = _dedup_findings(findings)
    assert len(result) == 1
    assert result[0]["id"] == "CVE-2026-001"


def test_dedup_findings_keeps_different_cves():
    """Different CVE IDs are not deduplicated."""
    findings = [
        _make_finding("CVE-2026-001", "prometheus"),
        _make_finding("CVE-2026-002", "prometheus"),
    ]
    result = _dedup_findings(findings)
    assert len(result) == 2


def test_dedup_findings_keeps_different_versions():
    """Same CVE but different versions are not deduplicated (different packages)."""
    findings = [
        _make_finding("CVE-2026-001", "openssl", version="1.0"),
        _make_finding("CVE-2026-001", "openssl", version="1.1"),
    ]
    result = _dedup_findings(findings)
    assert len(result) == 2


def test_dedup_findings_keeps_different_tools():
    """Same CVE found by two different tools is kept from each tool separately."""
    findings = [
        _make_finding("CVE-2026-001", "curl", tool="grype"),
        _make_finding("CVE-2026-001", "curl", tool="cve-bin-tool"),
    ]
    result = _dedup_findings(findings)
    assert len(result) == 2


def test_dedup_findings_empty_input():
    assert _dedup_findings([]) == []


def test_dedup_findings_realistic_prometheus_scenario():
    """Prometheus + promtool both trigger the same CVEs — should halve the count."""
    cves = ["CVE-2026-001", "CVE-2026-002", "CVE-2026-003"]
    findings = []
    for cve in cves:
        findings.append(_make_finding(cve, "stdlib", version="go1.26.1"))
        findings.append(_make_finding(cve, "stdlib", version="go1.26.1"))  # second binary
    assert len(findings) == 6
    result = _dedup_findings(findings)
    assert len(result) == 3


def test_build_report_deduplicates_multi_binary_findings(tmp_path: Path):
    """End-to-end: build_report deduplicates same CVE reported for both binaries."""
    reports = tmp_path / "artifacts"
    _make_minimal_reports(reports, syft_artifacts=[{"name": "prometheus"}, {"name": "promtool"}])
    # Grype reports same CVE twice (once per binary)
    (reports / "reports" / "grype" / "report.json").write_text(
        json.dumps({
            "matches": [
                {"vulnerability": {"id": "CVE-2026-001", "severity": "Critical"},
                 "artifact": {"name": "stdlib", "version": "go1.26.1", "type": "go-module"}},
                {"vulnerability": {"id": "CVE-2026-001", "severity": "Critical"},
                 "artifact": {"name": "stdlib", "version": "go1.26.1", "type": "go-module"}},
            ]
        }),
        encoding="utf-8",
    )
    output = build_report(reports, tmp_path / "report.md", None, "prometheus", "CASE")
    text = output.read_text(encoding="utf-8")
    # CVE-2026-001 should appear exactly once in the findings table
    assert text.count("CVE-2026-001") == 1
