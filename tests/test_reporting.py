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
    (reports / "reports" / "trivy" / "trivy.json").write_text(
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
    (reports / "reports" / "cve-bin-tool" / "cve_raw.json").write_text(
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
    (reports / "provenance").mkdir(parents=True)
    (reports / "provenance" / "grype.json").write_text("{}", encoding="utf-8")
    output = build_report(reports, tmp_path / "report.md", None, "target", "CASE")
    text = output.read_text(encoding="utf-8")

    assert "provenance" in text
    assert "grype.json" in text
