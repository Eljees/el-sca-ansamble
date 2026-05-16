from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_cve_bin_tool_binary_findings_exit_code_is_success():
    script = (ROOT / "scripts" / "update_cve_bin_tool.sh").read_text(encoding="utf-8")

    assert "1 = success, CVEs found" in script
    assert 'if [ "$scan_rc" -le 1 ]; then' in script
    assert 'echo "[cve-bin-tool] binary scan done (exit $scan_rc)"' in script


def test_compose_uses_cyclonedx_as_cve_bin_tool_sbom_default():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert "CVE_BIN_TOOL_SBOM_FORMAT: ${CVE_BIN_TOOL_SBOM_FORMAT:-cyclonedx}" in compose
    assert "CVE_BIN_TOOL_SBOM_FORMAT: ${CVE_BIN_TOOL_SBOM_FORMAT:-syft}" not in compose
