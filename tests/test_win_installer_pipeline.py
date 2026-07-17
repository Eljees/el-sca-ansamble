"""GUI win-installer pipeline (2026-07-17).

A lone Windows installer (.exe/.msi) uploaded through the dashboard used to run
the generic stages (extract -> syft over the raw file), which cataloged 0
components. The GUI orchestrator now mirrors the CLI run-scan.sh "win" branch:
detect the installer, run win-analyzer to build a PE SBOM, and render a
dedicated "Win-analyzer" stage instead of "SBOM . Syft" (CYBERSEC-13388).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from resilient_updates.orchestrator import (
    SCAN_STAGES,
    SCAN_STAGES_WIN,
    is_windows_installer_target,
)


@pytest.mark.parametrize("name", ["setup.exe", "SETUP.EXE", "pkg.msi", "Pkg.Msi"])
def test_installer_file_is_win_target(tmp_path: Path, name: str):
    f = tmp_path / name
    f.write_bytes(b"MZ\x00\x00")
    assert is_windows_installer_target(str(f)) is True


@pytest.mark.parametrize("name", ["app.tar.gz", "lib.zip", "pkg.deb", "notes.txt", "server.jar"])
def test_non_installer_file_is_not_win_target(tmp_path: Path, name: str):
    f = tmp_path / name
    f.write_bytes(b"\x00\x00")
    assert is_windows_installer_target(str(f)) is False


def test_directory_with_only_installer_is_win_target(tmp_path: Path):
    (tmp_path / "a.exe").write_bytes(b"MZ")
    (tmp_path / "readme.txt").write_text("x", encoding="utf-8")
    assert is_windows_installer_target(str(tmp_path)) is True


def test_directory_with_a_real_archive_is_not_win_target(tmp_path: Path):
    # An installer next to a real archive -> the generic extractor should own it.
    (tmp_path / "a.exe").write_bytes(b"MZ")
    (tmp_path / "bundle.tar.gz").write_bytes(b"\x1f\x8b")
    assert is_windows_installer_target(str(tmp_path)) is False


def test_missing_path_is_not_win_target():
    assert is_windows_installer_target(r"/no/such/path/x.exe") is False


def test_win_pipeline_replaces_syft_stage_with_win_analyzer():
    win_keys = [s[0] for s in SCAN_STAGES_WIN]
    generic_keys = [s[0] for s in SCAN_STAGES]
    # win-analyzer takes the SBOM slot; the generic "sbom" stage is gone.
    assert "win-analyzer" in win_keys
    assert "sbom" not in win_keys
    assert "sbom" in generic_keys
    # everything else (extract, grype, trivy, cve-bin-tool, report) is preserved
    assert win_keys == ["extract", "win-analyzer", "grype", "trivy", "cve-bin-tool", "report"]
    # win-analyzer stage is fed by the win-analyzer compose service
    win_analyzer_stage = next(s for s in SCAN_STAGES_WIN if s[0] == "win-analyzer")
    assert win_analyzer_stage[2] == ["win-analyzer"]
