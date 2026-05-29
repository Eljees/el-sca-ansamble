"""
Tests for scripts/analyze_apk.py and scripts/analyze_win_installer.py.

These tests use only Python stdlib and temporary files — no Docker, no network.
Run with:  pytest tests/test_analyzers.py
           python -m pytest tests/test_analyzers.py -v
"""

from __future__ import annotations

import types
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers to load the scripts as modules without pytest conftest magic
# ---------------------------------------------------------------------------


def _load_script(name: str) -> types.ModuleType:
    script_path = Path(__file__).parent.parent / "scripts" / name
    src = script_path.read_text(encoding="utf-8")
    mod = types.ModuleType(name.replace(".py", "").replace("-", "_"))
    mod.__file__ = str(script_path)
    exec(compile(src, str(script_path), "exec"), mod.__dict__)
    return mod


# ---------------------------------------------------------------------------
# analyze_win_installer tests
# ---------------------------------------------------------------------------


class TestDetectFormat:
    def test_msi_by_extension(self, tmp_path):
        f = tmp_path / "setup.msi"
        f.write_bytes(b"\xd0\xcf\x11\xe0" + b"\x00" * 100)  # MSI magic
        mod = _load_script("analyze_win_installer.py")
        assert mod.detect_format(f) == "msi"

    def test_zip_by_extension(self, tmp_path):
        f = tmp_path / "bundle.zip"
        f.write_bytes(b"PK\x03\x04" + b"\x00" * 10)
        mod = _load_script("analyze_win_installer.py")
        assert mod.detect_format(f) == "zip"

    def test_exe_with_nsis_magic(self, tmp_path):
        f = tmp_path / "setup.exe"
        f.write_bytes(b"MZ" + b"\x00" * 10 + b"Nullsoft" + b"\x00" * 80)
        mod = _load_script("analyze_win_installer.py")
        assert mod.detect_format(f) == "nsis"

    def test_plain_exe(self, tmp_path):
        f = tmp_path / "app.exe"
        f.write_bytes(b"MZ" + b"\x00" * 200)
        mod = _load_script("analyze_win_installer.py")
        assert mod.detect_format(f) in ("exe", "nsis")

    def test_unknown_format(self, tmp_path):
        f = tmp_path / "file.bin"
        f.write_bytes(b"\x00" * 50)
        mod = _load_script("analyze_win_installer.py")
        assert mod.detect_format(f) == "unknown"


class TestFindInstaller:
    def test_finds_exe_in_directory(self, tmp_path):
        (tmp_path / "setup.exe").write_bytes(b"MZ" + b"\x00" * 10)
        mod = _load_script("analyze_win_installer.py")
        result = mod.find_installer(tmp_path)
        assert result is not None
        assert result.suffix.lower() == ".exe"

    def test_finds_msi_in_directory(self, tmp_path):
        (tmp_path / "app.msi").write_bytes(b"\xd0\xcf" + b"\x00" * 10)
        mod = _load_script("analyze_win_installer.py")
        result = mod.find_installer(tmp_path)
        assert result is not None
        assert result.suffix.lower() == ".msi"

    def test_returns_none_when_empty(self, tmp_path):
        mod = _load_script("analyze_win_installer.py")
        assert mod.find_installer(tmp_path) is None

    def test_direct_file_input(self, tmp_path):
        f = tmp_path / "setup.exe"
        f.write_bytes(b"MZ")
        mod = _load_script("analyze_win_installer.py")
        assert mod.find_installer(f) == f


class TestCountFiles:
    def test_counts_files_recursively(self, tmp_path):
        (tmp_path / "a.dll").write_bytes(b"MZ")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "b.exe").write_bytes(b"MZ")
        mod = _load_script("analyze_win_installer.py")
        assert mod._count_files(tmp_path) == 2

    def test_returns_zero_for_empty_dir(self, tmp_path):
        mod = _load_script("analyze_win_installer.py")
        assert mod._count_files(tmp_path) == 0

    def test_returns_zero_for_nonexistent(self, tmp_path):
        mod = _load_script("analyze_win_installer.py")
        assert mod._count_files(tmp_path / "nope") == 0


class TestBuildSyftSbomWin:
    def test_sbom_has_correct_schema(self, tmp_path):
        installer = tmp_path / "setup.exe"
        installer.write_bytes(b"MZ")
        mod = _load_script("analyze_win_installer.py")
        sbom = mod.build_syft_sbom(installer, [])
        assert sbom.get("bomFormat") == "CycloneDX" or "schema" in sbom
        assert "artifacts" in sbom or "components" in sbom

    def test_sbom_includes_components(self, tmp_path):
        installer = tmp_path / "setup.exe"
        installer.write_bytes(b"MZ")
        mod = _load_script("analyze_win_installer.py")
        comp = {
            "id": "abc-123",
            "name": "OpenSSL",
            "version": "1.1.1",
            "type": "binary",
            "foundBy": "win-analyzer-pe",
            "locations": [{"path": "/setup/openssl.dll"}],
            "licenses": [],
            "language": "",
            "cpes": ["cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"],
            "purl": "pkg:generic/openssl@1.1.1",
            "metadataType": "WindowsBinaryMetadata",
            "metadata": {"originalFileName": "openssl.dll", "companyName": "OpenSSL", "legalCopyright": ""},
        }
        sbom = mod.build_syft_sbom(installer, [comp])
        assert len(sbom["artifacts"]) == 1
        assert sbom["artifacts"][0]["name"] == "OpenSSL"


# ---------------------------------------------------------------------------
# analyze_apk tests
# ---------------------------------------------------------------------------


def _make_minimal_apk(dest: Path, pkg: str = "com.example.app") -> Path:
    """Create a minimal valid APK (ZIP) with placeholder files."""
    apk_path = dest / "test.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        # Minimal binary AndroidManifest.xml placeholder (not real AXML)
        zf.writestr("AndroidManifest.xml", b"\x03\x00" + b"\x00" * 20)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 50)
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 50)
        zf.writestr("lib/armeabi-v7a/libnative.so", b"\x7fELF" + b"\x00" * 50)
    return apk_path


class TestFindApk:
    def test_finds_direct_apk_file(self, tmp_path):
        apk = _make_minimal_apk(tmp_path)
        mod = _load_script("analyze_apk.py")
        result = mod.find_apk(apk)
        assert result == apk

    def test_finds_apk_in_directory(self, tmp_path):
        apk = _make_minimal_apk(tmp_path)
        mod = _load_script("analyze_apk.py")
        result = mod.find_apk(tmp_path)
        assert result == apk

    def test_finds_apk_in_nested_directory(self, tmp_path):
        nested = tmp_path / "depth0" / "input_extracted"
        nested.mkdir(parents=True)
        apk = _make_minimal_apk(nested)
        mod = _load_script("analyze_apk.py")
        result = mod.find_apk(tmp_path)
        assert result == apk

    def test_extracts_apk_from_zip(self, tmp_path):
        apk = _make_minimal_apk(tmp_path)
        zip_path = tmp_path / "bundle.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(apk, "test.apk")
        apk.unlink()  # remove original so only ZIP remains
        mod = _load_script("analyze_apk.py")
        result = mod.find_apk(zip_path)
        assert result is not None
        assert result.suffix.lower() == ".apk"

    def test_returns_none_for_empty_directory(self, tmp_path):
        mod = _load_script("analyze_apk.py")
        assert mod.find_apk(tmp_path) is None

    def test_finds_extracted_apk_by_classes_dex(self, tmp_path):
        """When APK was pre-extracted (no .apk file), find via classes.dex."""
        (tmp_path / "AndroidManifest.xml").write_bytes(b"\x03\x00" + b"\x00" * 10)
        (tmp_path / "classes.dex").write_bytes(b"dex\n035\x00" + b"\x00" * 20)
        mod = _load_script("analyze_apk.py")
        result = mod.find_apk(tmp_path)
        # Should return a Path (the directory with classes.dex)
        assert result is not None
        assert result.is_dir()


class TestExtractNativeLibs:
    def test_extracts_so_files(self, tmp_path):
        apk = _make_minimal_apk(tmp_path)
        dest = tmp_path / "native"
        mod = _load_script("analyze_apk.py")
        extracted = mod.extract_native_libs(apk, dest)
        assert len(extracted) > 0
        assert all(f.suffix == ".so" for f in extracted)
        assert dest.exists()

    def test_no_so_in_empty_apk(self, tmp_path):
        apk_path = tmp_path / "empty.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"\x03\x00")
        dest = tmp_path / "native"
        mod = _load_script("analyze_apk.py")
        extracted = mod.extract_native_libs(apk_path, dest)
        assert extracted == []


class TestBuildSyftSbomApk:
    def test_sbom_has_required_fields(self, tmp_path):
        apk = _make_minimal_apk(tmp_path)
        meta = {
            "package": "com.example.app",
            "version_name": "1.2.3",
            "version_code": "42",
            "min_sdk": "21",
            "target_sdk": "33",
            "permissions": ["android.permission.INTERNET"],
            "libraries": [],
            "native_libs": ["lib/arm64-v8a/libnative.so"],
            "third_party_packages": ["com.squareup.okhttp3"],
        }
        mod = _load_script("analyze_apk.py")
        sbom = mod.build_syft_sbom(apk, meta)
        assert "artifacts" in sbom
        assert len(sbom["artifacts"]) >= 1
        # Main app component
        app = sbom["artifacts"][0]
        assert app["name"] == "com.example.app"
        assert app["version"] == "1.2.3"

    def test_sbom_includes_native_libs(self, tmp_path):
        apk = _make_minimal_apk(tmp_path)
        meta = {
            "package": "com.test",
            "version_name": "1.0",
            "version_code": "1",
            "min_sdk": "21",
            "target_sdk": "33",
            "permissions": [],
            "libraries": [],
            "native_libs": ["lib/arm64-v8a/libssl.so", "lib/arm64-v8a/libcrypto.so"],
            "third_party_packages": [],
        }
        mod = _load_script("analyze_apk.py")
        sbom = mod.build_syft_sbom(apk, meta)
        names = [a["name"] for a in sbom["artifacts"]]
        assert "libssl" in names
        assert "libcrypto" in names

    def test_sbom_source_uses_display_name(self, tmp_path):
        apk = _make_minimal_apk(tmp_path)
        meta = {
            "package": "com.test",
            "version_name": "1.0",
            "version_code": "1",
            "min_sdk": "21",
            "target_sdk": "33",
            "permissions": [],
            "libraries": [],
            "native_libs": [],
            "third_party_packages": [],
        }
        mod = _load_script("analyze_apk.py")
        sbom = mod.build_syft_sbom(apk, meta, display_name="my-custom-name")
        assert sbom["source"]["name"] == "my-custom-name"
