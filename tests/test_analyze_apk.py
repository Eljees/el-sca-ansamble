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

import analyze_apk


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


# ---------------------------------------------------------------------------
# Qt6 native-library version detection
#
# Regression cover for CYBERSEC-13942 (2026-08-18): every Qt6 native .so
# component was emitted with version="unknown" and purl=pkg:generic/<name>@unknown.
# grype has nothing to compare a vulnerable range against without a version,
# so all 70 Qt6 components on that APK matched 0 CVEs no matter how fresh the
# grype/cve-bin-tool DBs were (confirmed fresh: 21.8h / 15.8h old). Not every
# Qt module embeds its own "Qt X.Y.Z" string, but every Qt6 library shipped in
# one APK build comes from the same Qt release, so detecting the string once
# (from libQt6Core/libQt6Gui, which reliably carry it) is enough to
# version-tag every libQt6*.so component in the SBOM.
# ---------------------------------------------------------------------------


def test_detect_qt_version_finds_string_in_core_module(tmp_path: Path) -> None:
    native_dir = tmp_path / "native"
    native_dir.mkdir()
    (native_dir / "libQt6Core_arm64-v8a.so").write_bytes(b"junk" * 50 + b"Qt 6.10.2" + b"junk" * 50)
    (native_dir / "libQt6Network_arm64-v8a.so").write_bytes(b"no version string in this one")

    assert analyze_apk._detect_qt_version(native_dir) == "6.10.2"


def test_detect_qt_version_missing_returns_none(tmp_path: Path) -> None:
    native_dir = tmp_path / "native"
    native_dir.mkdir()
    (native_dir / "libQt6Network_arm64-v8a.so").write_bytes(b"nothing useful in here")
    (native_dir / "libcrypto_3.so").write_bytes(b"OpenSSL, not Qt")

    assert analyze_apk._detect_qt_version(native_dir) is None
    assert analyze_apk._detect_qt_version(None) is None
    assert analyze_apk._detect_qt_version(tmp_path / "does-not-exist") is None


def test_sbom_tags_every_qt6_component_from_one_detected_version(tmp_path: Path) -> None:
    meta = {
        "package": "test.pkg",
        "version_name": "1.0",
        "version_code": "1",
        "native_libs": [
            "lib/arm64-v8a/libQt6Core_arm64-v8a.so",
            "lib/arm64-v8a/libQt6Network_arm64-v8a.so",  # no string of its own
            "lib/arm64-v8a/libcrypto_3.so",  # non-Qt: must stay unknown
        ],
        "third_party_packages": [],
        "qt_version_detected": "6.10.2",
    }

    sbom = analyze_apk.build_syft_sbom(tmp_path / "fake.apk", meta, "fake.apk")
    by_name = {a["name"]: a for a in sbom["artifacts"] if a["type"] == "binary"}

    for qt_lib in ("libQt6Core_arm64-v8a", "libQt6Network_arm64-v8a"):
        comp = by_name[qt_lib]
        assert comp["version"] == "6.10.2"
        assert comp["cpes"] == ["cpe:2.3:a:qt:qt:6.10.2:*:*:*:*:*:*:*"]
        assert comp["purl"] == "pkg:generic/qt@6.10.2"

    crypto = by_name["libcrypto_3"]
    assert crypto["version"] == "unknown"
    assert crypto["purl"] == "pkg:generic/libcrypto_3@unknown"


def test_sbom_leaves_qt6_libs_unknown_when_no_version_detected(tmp_path: Path) -> None:
    meta = {
        "package": "test.pkg",
        "version_name": "1.0",
        "version_code": "1",
        "native_libs": ["lib/arm64-v8a/libQt6Core_arm64-v8a.so"],
        "third_party_packages": [],
        # no "qt_version_detected" key — the embedded-string probe found nothing.
    }

    sbom = analyze_apk.build_syft_sbom(tmp_path / "fake.apk", meta, "fake.apk")
    comp = next(a for a in sbom["artifacts"] if a["name"] == "libQt6Core_arm64-v8a")
    assert comp["version"] == "unknown"
    assert comp["purl"] == "pkg:generic/libQt6Core_arm64-v8a@unknown"
