"""CYBERSEC-14915: compiler-marker and distro-patched OS-file filters for cve-bin-tool."""

from __future__ import annotations

import json
from pathlib import Path

from resilient_updates.collision_filter import (
    distro_from_grype,
    filter_compiler_markers,
    filter_distro_owned_binaries,
)
from resilient_updates.reporting import _cve_bin_tool_findings


def _cbt(product: str, version: str, cve: str, paths: str = "", severity: str = "HIGH") -> dict:
    return {
        "tool": "cve-bin-tool",
        "id": cve,
        "severity": severity,
        "vendor": "gnu" if product == "gcc" else product,
        "product": product,
        "version": version,
        "paths": paths,
    }


def test_gcc_marker_dropped_other_products_kept():
    findings = [
        _cbt("gcc", "4.4.7", "CVE-2018-12886", "/x/opt/dynatrace/agent/lib64/fips.so"),
        _cbt("zlib", "1.2.7", "CVE-2022-37434", "/x/opt/dynatrace/agent/lib64/libz.so.1"),
        {"tool": "grype", "id": "CVE-2021-1", "product": "gcc", "version": "4.4.7", "severity": "HIGH"},
    ]
    kept, dropped = filter_compiler_markers(findings)
    assert [f["product"] for f in dropped] == ["gcc"]
    assert dropped[0]["dropped_evidence"] == "compiler build marker"
    # grype's gcc is a real package match -- only cve-bin-tool's string match is a marker
    assert {(f["tool"], f["product"]) for f in kept} == {("cve-bin-tool", "zlib"), ("grype", "gcc")}


def test_distro_filter_is_noop_without_distro():
    findings = [_cbt("curl", "7.76.1", "CVE-2023-38545", "/l/usr/bin/curl", "CRITICAL")]
    kept, dropped = filter_distro_owned_binaries(findings, "")
    assert kept == findings
    assert dropped == []


def test_distro_filter_drops_os_files_keeps_opt():
    findings = [
        _cbt("curl", "7.76.1", "CVE-2023-38545", "/tmp/cbt/layer.tar.extracted/usr/bin/curl", "CRITICAL"),
        _cbt(
            "glibc", "2.34", "CVE-2026-5450", "/tmp/cbt/layer.tar.extracted/usr/lib64/libc.so.6", "CRITICAL"
        ),
        _cbt(
            "zlib",
            "1.2.11",
            "CVE-2022-37434",
            "/tmp/cbt/x/opt/dynatrace/remotepluginmodule/agent/lib64/libz.so.1",
        ),
        _cbt("sqlite", "3.49.1", "CVE-2025-6965", ""),  # no path: cannot prove ownership -> keep
    ]
    kept, dropped = filter_distro_owned_binaries(findings, "redhat 9.6")
    assert {f["product"] for f in dropped} == {"curl", "glibc"}
    assert {f["product"] for f in kept} == {"zlib", "sqlite"}
    assert "redhat 9.6" in dropped[0]["dropped_reason"]


def test_distro_from_grype():
    assert (
        distro_from_grype({"distro": {"name": "redhat", "version": "9.6", "idLike": ["fedora"]}})
        == "redhat 9.6"
    )
    # file-level scan of an unpacked image: grype reports an empty distro
    assert distro_from_grype({"distro": {"name": "", "version": "", "idLike": None}}) == ""
    assert distro_from_grype({}) == ""
    assert distro_from_grype(None) == ""


def test_cve_bin_tool_findings_keep_paths():
    rows = _cve_bin_tool_findings(
        [{"cve_number": "CVE-1", "severity": "HIGH", "product": "curl", "paths": "/usr/bin/curl"}]
    )
    assert rows[0]["paths"] == "/usr/bin/curl"


def test_report_drops_markers_and_os_files(tmp_path: Path):
    """End to end through build_report: dropped rows are reported, not counted."""
    from resilient_updates.reporting import build_report

    target = tmp_path / "image.tar.gz"
    target.write_bytes(b"x")
    art = tmp_path / "artifacts"
    (art / "reports" / "cve-bin-tool").mkdir(parents=True)
    (art / "reports" / "grype").mkdir(parents=True)
    (art / "reports" / "trivy").mkdir(parents=True)
    (art / "sbom").mkdir(parents=True)
    (art / "reports" / "cve-bin-tool" / "report.json").write_text(
        json.dumps(
            [
                {
                    "cve_number": "CVE-2018-12886",
                    "severity": "HIGH",
                    "vendor": "gnu",
                    "product": "gcc",
                    "version": "4.4.7",
                    "paths": "/t/opt/app/bin/x",
                },
                {
                    "cve_number": "CVE-2023-38545",
                    "severity": "CRITICAL",
                    "vendor": "haxx",
                    "product": "curl",
                    "version": "7.76.1",
                    "paths": "/t/usr/bin/curl",
                },
                {
                    "cve_number": "CVE-2022-37434",
                    "severity": "CRITICAL",
                    "vendor": "zlib",
                    "product": "zlib",
                    "version": "1.2.11",
                    "paths": "/t/opt/app/lib64/libz.so.1",
                },
            ]
        ),
        encoding="utf-8",
    )
    (art / "reports" / "grype" / "report.json").write_text(
        json.dumps({"matches": [], "distro": {"name": "redhat", "version": "9.6"}}), encoding="utf-8"
    )
    (art / "reports" / "trivy" / "report.json").write_text(json.dumps({"Results": []}), encoding="utf-8")
    (art / "sbom" / "syft.json").write_text(json.dumps({"artifacts": []}), encoding="utf-8")

    out = tmp_path / "report.md"
    build_report(art, out, target_path=target, case_id="CYBERSEC-14915")
    text = out.read_text(encoding="utf-8")
    table = text.split("## High / Critical findings", 1)[1].split("## ", 1)[0]
    assert "CVE-2022-37434" in table  # vendor-bundled zlib under /opt stays
    assert "CVE-2023-38545" not in table  # RHEL curl judged by the distro feed
    assert "CVE-2018-12886" not in table  # compiler marker
    assert "## Dropped as build markers and distro-patched OS files" in text
    assert "compiler markers / distro-patched OS files: `1` / `1`" in text
