from pathlib import Path
import json

from resilient_updates.reporting import build_report


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
