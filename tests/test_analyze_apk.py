"""apk-analyzer: find_apk() must recognize an extension-less mount.

Regression cover for CYBERSEC-13942, where every standalone-APK run failed
with "no .apk file found at /scan-target". Root cause: docker-compose.yml's
apk-analyzer service bind-mounts ${SCAN_TARGET_HOST} straight to the fixed
container path /scan-target — no extension survives the mount. find_apk()
only recognized a direct APK via ``path.suffix == ".apk"``, which can never
match a path literally named ``/scan-target``, so the very case the analyzer
exists for (a single standalone .apk file) always fell through to None.

The fix sniffs zip content when the suffix is empty: real APK content
(AndroidManifest.xml / classes.dex at top level) is used directly; a
zip-of-zip wrapper carrying an inner .apk has that inner file extracted, same
as the existing ``.zip``-suffix path.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import analyze_apk  # noqa: E402


def _write_apk_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("classes.dex", b"dex")


def test_extensionless_mount_with_real_apk_content_is_found(tmp_path: Path) -> None:
    # Simulates the docker bind-mount target: real APK bytes at a path with no
    # ".apk" suffix, exactly what /scan-target looks like in the container.
    scan_target = tmp_path / "scan-target"
    _write_apk_zip(scan_target)

    result = analyze_apk.find_apk(scan_target)

    assert result == scan_target


def test_extensionless_mount_with_zip_of_apk_extracts_inner_apk(tmp_path: Path) -> None:
    inner = tmp_path / "inner.apk"
    _write_apk_zip(inner)
    outer = tmp_path / "scan-target"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.write(inner, arcname="payload/app-release.apk")

    result = analyze_apk.find_apk(outer)

    assert result is not None
    assert result.name == "app-release.apk"


def test_proper_apk_suffix_still_works(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    _write_apk_zip(apk)

    assert analyze_apk.find_apk(apk) == apk


def test_extensionless_non_zip_file_returns_none(tmp_path: Path) -> None:
    junk = tmp_path / "scan-target"
    junk.write_bytes(b"not a zip at all")

    assert analyze_apk.find_apk(junk) is None
