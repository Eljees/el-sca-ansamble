"""CYBERSEC-14231 — `run-scan.sh` must unpack a Java delivery on its own.

The auto-extract branch used to list only tar/zip/rpm/deb, so a `.war` (or
`.jar`, `.hpi`, `.whl` …) went to the scanners unextracted: Docker bind-mounted
the FILE at `/scan-target` while `SYFT_FROM=dir`, and the sbom stage died with
``not a directory source: /scan-target`` — an error that says nothing about
extraction.  The fix keeps the extension list as a fast path and adds a content
sniff that mirrors ``resilient_updates.extractor._archive_kind``, so anything
the extractor can open is unpacked regardless of the file name.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run-scan.sh"

_needs_bash = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="runs scripts/run-scan.sh under bash",
)


# ---------------------------------------------------------------------------
# Text contract
# ---------------------------------------------------------------------------


def test_java_archive_extensions_are_in_the_fast_path():
    script = SCRIPT.read_text(encoding="utf-8")

    for ext in (".war", ".jar", ".ear", ".hpi", ".jpi", ".aar", ".whl"):
        assert f"*{ext}|" in script or f"*{ext})" in script, ext


def test_content_sniff_is_the_fallback():
    script = SCRIPT.read_text(encoding="utf-8")

    assert "archive detected by content" in script
    assert "zipfile.is_zipfile(path) or tarfile.is_tarfile(path)" in script


# ---------------------------------------------------------------------------
# The sniff itself, taken from the script so the test cannot drift from it
# ---------------------------------------------------------------------------


def _sniff_snippet() -> str:
    script = SCRIPT.read_text(encoding="utf-8")
    body = re.search(r"<<'PYSNIFF'[^\n]*\n(.*?)\nPYSNIFF\n", script, re.S)
    assert body, "PYSNIFF heredoc not found in run-scan.sh"
    return body.group(1)


def _sniff(tmp_path: Path, target: Path) -> bool:
    """Run the script's own snippet; True when it votes for extraction."""
    snippet = tmp_path / "sniff.py"
    snippet.write_text(_sniff_snippet(), encoding="utf-8")
    proc = subprocess.run(
        ["python3", str(snippet), str(target)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return proc.returncode == 0


def test_sniff_accepts_zip_and_tar_whatever_the_name(tmp_path: Path):
    war = tmp_path / "app.war"
    with zipfile.ZipFile(war, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    mystery = tmp_path / "delivery.bin"
    with zipfile.ZipFile(mystery, "w") as z:
        z.writestr("a.txt", "x")
    tarball = tmp_path / "delivery.noext"
    payload = tmp_path / "payload.txt"
    payload.write_text("x", encoding="utf-8")
    with tarfile.open(tarball, "w") as t:
        t.add(payload, arcname="payload.txt")

    assert _sniff(tmp_path, war)
    assert _sniff(tmp_path, mystery)
    assert _sniff(tmp_path, tarball)


def test_sniff_rejects_a_plain_file_and_a_missing_one(tmp_path: Path):
    plain = tmp_path / "notes.txt"
    plain.write_text("hello", encoding="utf-8")

    assert not _sniff(tmp_path, plain)
    assert not _sniff(tmp_path, tmp_path / "nope.bin")


# ---------------------------------------------------------------------------
# Behaviour: run the real script with a stub docker and read its decision
# ---------------------------------------------------------------------------


def _extract_line(tmp_path: Path, target: Path) -> str:
    """Run run-scan.sh far enough to print its Extract decision.

    ``docker`` is stubbed to a no-op so the run never reaches a container; the
    banner and the auto-extract branch are printed before any real work.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "docker"
    stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    stub.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    proc = subprocess.run(
        ["bash", str(SCRIPT), "-t", str(target)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    for line in (proc.stdout + proc.stderr).splitlines():
        if "Extract :" in line:
            return line.strip()
    return ""


@_needs_bash
@pytest.mark.slow
def test_a_war_is_unpacked_without_the_e_flag(tmp_path: Path):
    war = tmp_path / "app.war"
    with zipfile.ZipFile(war, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")

    assert "enabled automatically" in _extract_line(tmp_path, war)


@_needs_bash
@pytest.mark.slow
def test_a_plain_file_is_still_scanned_as_is(tmp_path: Path):
    plain = tmp_path / "binary.dat"
    plain.write_bytes(b"\x7fELF not really")

    assert _extract_line(tmp_path, plain) == ""
