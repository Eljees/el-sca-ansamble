"""CYBERSEC-14277 — an embedded ``META-INF/maven/**/pom.xml`` is a build
descriptor, not a manifest, and the two settings that follow from that must be
wired into the repo rather than live only in a server-side ``.env``:

* compose deselects Syft's ``java-pom-cataloger`` (``SYFT_SELECT_CATALOGERS``),
  which catalogs every declared dependency with no scope filtering;
* ``scripts/update_trivy.sh`` scans with ``trivy rootfs`` by default: Trivy
  analyses JAR/WAR/EAR only in the image/rootfs/vm modes, while ``fs`` reads
  manifests and lockfiles, so on an unpacked delivery ``fs`` saw nothing but
  the embedded poms (``TRIVY_SCAN_KIND=fs`` remains available for source
  trees).

There is deliberately no ``--skip-files`` guard for embedded poms; the last
test pins its absence, because it hid real components (see the CHANGELOG entry
and aquasecurity/trivy#11203).

The behavioural tests run the real script under ``/bin/sh`` with a fake
``trivy`` on ``PATH`` and inspect the argv it received.  They also pin the
``set -f`` hardening: without it, a glob-shaped value inside
``TRIVY_RENDERED_FLAGS`` (exactly what the server hotfix passed) is expanded
by the shell against ``/workspace`` before Trivy ever sees it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "update_trivy.sh"
SKIP_GLOB = "**/META-INF/maven/**/pom.xml"

_needs_sh = pytest.mark.skipif(
    os.name == "nt" or shutil.which("sh") is None,
    reason="runs scripts/update_trivy.sh under a POSIX sh",
)


# ---------------------------------------------------------------------------
# Text contracts (portable)
# ---------------------------------------------------------------------------


def test_compose_deselects_syft_pom_cataloger_by_default():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert "SYFT_SELECT_CATALOGERS: ${SYFT_SELECT_CATALOGERS:--java-pom-cataloger}" in compose


def test_no_embedded_pom_skip_guard_anywhere():
    """The guard is gone on purpose: it removed real components.

    On an exploded WAR whose ``META-INF/maven`` pom declares log4j-core 2.14.1
    with the jar in ``WEB-INF/lib``, skipping the pom dropped log4j-core and
    its 7 findings (CVE-2021-44228 among them) from the default report.
    """
    script = SCRIPT.read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")

    assert f"--skip-files '{SKIP_GLOB}'" not in script
    assert "TRIVY_SKIP_EMBEDDED_POM:" not in compose
    assert "\nTRIVY_SKIP_EMBEDDED_POM=" not in env_example


def test_update_trivy_script_splits_flags_with_globbing_off():
    script = SCRIPT.read_text(encoding="utf-8")

    assert "set -f\n# shellcheck disable=SC2086\nset -- $FLAGS\nset +f" in script


def test_env_example_documents_the_knobs():
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")

    assert "SYFT_SELECT_CATALOGERS=+java-pom-cataloger" in env_example
    assert "TRIVY_SCAN_KIND=rootfs" in env_example


def test_trivy_scans_deliveries_as_rootfs_on_every_entry_point():
    """A built delivery is a post-build artefact: only image/rootfs analyse jars."""
    script = SCRIPT.read_text(encoding="utf-8")
    scan_archive = (ROOT / "scripts" / "scan_archive.sh").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert 'SCAN_KIND="${TRIVY_SCAN_KIND:-rootfs}"' in script
    assert 'export TRIVY_SCAN_KIND="${TRIVY_SCAN_KIND:-rootfs}"' in scan_archive
    # compose must declare the variable, otherwise neither .env nor an
    # exported override ever reaches the container.
    assert "TRIVY_SCAN_KIND: ${TRIVY_SCAN_KIND:-rootfs}" in compose


# ---------------------------------------------------------------------------
# Behaviour: run the script with a fake trivy and read the argv it got
# ---------------------------------------------------------------------------


def _run_script(tmp_path: Path, mode: str, script: Path = SCRIPT, **env: str) -> list[str]:
    """Run ``update_trivy.sh <mode> /scan-target`` with a fake ``trivy`` that
    records its argv; return the argv of the *last* trivy call."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    argv_file = tmp_path / "trivy.argv"
    fake = bin_dir / "trivy"
    fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$TRIVY_ARGS_OUT"\n', encoding="utf-8")
    fake.chmod(0o755)
    # A cwd that *does* contain matching paths, so an unguarded glob expands.
    workspace = tmp_path / "workspace"
    for leaf in ("y/META-INF/maven/g", "z/META-INF/maven/h"):
        (workspace / leaf).mkdir(parents=True, exist_ok=True)
        (workspace / leaf / "pom.xml").write_text("<project/>", encoding="utf-8")
    run_env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "TRIVY_ARGS_OUT": str(argv_file),
        "REPORT_DIR": str(tmp_path / "reports"),
        "TRIVY_CACHE_DIR": str(tmp_path / "cache"),
        "TRIVY_RENDERED_FLAGS": "--db-repository ghcr.io/example/trivy-db",
        **env,
    }
    proc = subprocess.run(
        ["sh", str(script), mode, "/scan-target"],
        cwd=workspace,
        env=run_env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return argv_file.read_text(encoding="utf-8").splitlines()


@_needs_sh
@pytest.mark.parametrize("mode", ["scan", "offline"])
def test_deliveries_are_scanned_as_rootfs(tmp_path: Path, mode: str):
    argv = _run_script(tmp_path, mode)

    assert argv[0] == "rootfs"
    assert "--skip-files" not in argv
    assert argv[-1] == "/scan-target"
    assert "--db-repository" in argv, "rendered flags still pass through"


@_needs_sh
def test_source_trees_can_still_be_scanned_as_fs(tmp_path: Path):
    argv = _run_script(tmp_path, "scan", TRIVY_SCAN_KIND="fs")

    assert argv[0] == "fs"
    assert argv[-1] == "/scan-target"


@_needs_sh
def test_update_mode_is_untouched(tmp_path: Path):
    argv = _run_script(tmp_path, "update")

    assert argv[0] == "image"
    assert "--skip-files" not in argv
    assert "--download-java-db-only" in argv


@_needs_sh
def test_rendered_flags_are_split_without_glob_expansion(tmp_path: Path):
    """Regression pin for ``set -f``: a glob inside TRIVY_RENDERED_FLAGS must
    arrive as one literal argument, even when cwd has files matching it."""
    argv = _run_script(
        tmp_path,
        "scan",
        TRIVY_RENDERED_FLAGS=f"--skip-files {SKIP_GLOB}",
    )

    idx = argv.index("--skip-files")
    assert argv[idx + 1] == SKIP_GLOB
    assert argv.count("--skip-files") == 1
    assert not any(a.startswith(("y/", "z/")) for a in argv), argv
