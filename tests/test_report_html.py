from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_report_html_module():
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "report_html.py"
    spec = importlib.util.spec_from_file_location("report_html", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _make_artifacts(root: Path) -> None:
    (root / "sbom").mkdir(parents=True, exist_ok=True)
    (root / "reports" / "grype").mkdir(parents=True, exist_ok=True)
    (root / "reports" / "trivy").mkdir(parents=True, exist_ok=True)
    (root / "reports" / "cve-bin-tool").mkdir(parents=True, exist_ok=True)
    (root / "sbom" / "syft.json").write_text(
        json.dumps(
            {
                "artifacts": [
                    {
                        "name": "prometheus",
                        "version": "3.11.0",
                        "type": "binary",
                        "purl": "pkg:generic/prometheus@3.11.0",
                        "locations": [{"path": "/scan-target/prometheus"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (root / "reports" / "grype" / "report.json").write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {"id": "GHSA-test", "severity": "HIGH"},
                        "artifact": {"name": "stdlib", "version": "go1.26.1", "type": "go-module"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (root / "reports" / "trivy" / "report.json").write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Type": "gobinary",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-0001",
                                "Severity": "CRITICAL",
                                "PkgName": "go",
                                "InstalledVersion": "1.26.1",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (root / "reports" / "cve-bin-tool" / "report.json").write_text(
        json.dumps(
            [
                {
                    "cve_number": "CVE-2026-0002",
                    "severity": "HIGH",
                    "product": "openssl",
                    "version": "3.0.0",
                }
            ]
        ),
        encoding="utf-8",
    )
    (root / "summary.json").write_text(
        json.dumps(
            {
                "input_sha256": "feedface",
                "input_hashes": {"sha1": "abc123", "sha256": "feedface"},
                "db_snapshot_id": "snap123456789",
                "db_drift": "fresh-or-reused",
                "update_trivy_db": "unknown",
                "update_grype_db": "refreshed-this-run",
                "update_cve_db": "reused-cached",
            }
        ),
        encoding="utf-8",
    )
    (root / "status.json").write_text(
        json.dumps({"tool_failures": "none", "db_drift": "fresh-or-reused"}),
        encoding="utf-8",
    )
    (root / "db_snapshot.json").write_text(
        json.dumps(
            {
                "snapshot_id": "snap123456789",
                "tools": {
                    "grype": {
                        "db_version": "sha256:deadbeef",
                        "db_source": "mirror-a",
                        "updated_at": "2026-05-16T08:00:00Z",
                        "built_at": "2026-05-16T07:00:00Z",
                        "update_state": "refreshed-this-run",
                    },
                    "trivy": {
                        "db_version": "trivy-db",
                        "db_source": "ghcr",
                        "updated_at": "2026-05-16T06:00:00Z",
                        "update_state": "unknown",
                    },
                    "cve-bin-tool": {
                        "db_version": "/var/lib/.../active",
                        "db_source": "/var/lib/.../active",
                        "updated_at": "2026-05-16T19:38:00Z",
                        "update_state": "reused-cached",
                    },
                },
            }
        ),
        encoding="utf-8",
    )


def test_generate_html_site_creates_overview_and_tool_pages(tmp_path: Path):
    module = _load_report_html_module()
    artifacts = tmp_path / "artifacts"
    _make_artifacts(artifacts)

    findings = []
    findings += module.parse_grype(module.load_json(artifacts / "reports" / "grype" / "report.json"))
    findings += module.parse_trivy(module.load_json(artifacts / "reports" / "trivy" / "report.json"))
    findings += module.parse_cvebt(module.load_json(artifacts / "reports" / "cve-bin-tool" / "report.json"))
    components = module.parse_syft_components(module.load_json(artifacts / "sbom" / "syft.json"))

    output = tmp_path / "site" / "index.html"
    result = module.generate_html_site(findings, "D:/__tests/_SCA/CYBERSEC-11531/prometheus.tar.gz", str(artifacts), output, components)

    assert result == 0
    assert output.exists()
    assert (output.parent / "grype.html").exists()
    assert (output.parent / "trivy.html").exists()
    assert (output.parent / "cve-bin-tool.html").exists()
    assert (output.parent / "syft.html").exists()


def test_overview_page_links_to_tool_pages_and_syft(tmp_path: Path):
    module = _load_report_html_module()
    artifacts = tmp_path / "artifacts"
    _make_artifacts(artifacts)

    findings = []
    findings += module.parse_grype(module.load_json(artifacts / "reports" / "grype" / "report.json"))
    findings += module.parse_trivy(module.load_json(artifacts / "reports" / "trivy" / "report.json"))
    findings += module.parse_cvebt(module.load_json(artifacts / "reports" / "cve-bin-tool" / "report.json"))
    components = module.parse_syft_components(module.load_json(artifacts / "sbom" / "syft.json"))

    output = tmp_path / "report.html"
    module.generate_html_site(findings, "target", str(artifacts), output, components)
    text = output.read_text(encoding="utf-8")

    assert 'href="report_grype.html"' in text
    assert 'href="report_trivy.html"' in text
    assert 'href="report_cve-bin-tool.html"' in text
    assert 'href="report_syft.html"' in text
    assert "SCA report overview" in text
    assert "Final target SHA-256" in text
    assert "Tool database versions and update times" in text
