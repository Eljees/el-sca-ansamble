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


def test_compose_extractor_source_no_longer_uses_nested_interpolation():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert "${EXTRACT_INPUT_HOST:-/tmp/el-sca-extract-input-not-set}" in compose
    assert "${EXTRACT_INPUT_HOST:-${SCAN_TARGET_HOST" not in compose


def test_runtime_entrypoints_use_runtime_stable_paths():
    dockerfile = (ROOT / "Dockerfile.cve-bin-tool").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    collect_script = (ROOT / "scripts" / "collect_reports.sh").read_text(encoding="utf-8")

    assert 'ENTRYPOINT ["/bin/sh", "/opt/app/scripts/update_cve_bin_tool.sh"]' in dockerfile
    assert 'entrypoint: ["/bin/sh", "/workspace/scripts/collect_reports.sh"]' in compose
    assert 'python /workspace/scripts/report_html.py' in collect_script


def test_preflight_script_checks_unresolved_vars_and_trailing_brace():
    script = (ROOT / "scripts" / "preflight_compose.sh").read_text(encoding="utf-8")

    assert "SCAN_TARGET_HOST" in script
    assert "EXTRACT_INPUT_HOST" in script
    assert "REPORT_OUTPUT" in script
    assert "Unresolved compose variables found in rendered config" in script
    assert "Bad trailing brace in rendered compose source path" in script
