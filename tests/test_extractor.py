from __future__ import annotations

from pathlib import Path
import zipfile

from resilient_updates.extractor import extract_artifacts


def _zip_file(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)


def test_extract_artifacts_recurses_into_nested_archives(tmp_path: Path):
    inner = tmp_path / "inner.zip"
    _zip_file(inner, {"payload/app.bin": b"binary"})
    outer = tmp_path / "outer.zip"
    _zip_file(outer, {"nested/inner.zip": inner.read_bytes()})

    output = tmp_path / "out"
    manifest = extract_artifacts(outer, output, max_depth=2)

    assert manifest["status"] == "pass"
    assert manifest["extracted_count"] == 2
    assert (output / "extraction_manifest.json").exists()
    assert list(output.rglob("app.bin"))


def test_extract_artifacts_recurses_when_output_path_contains_artifacts(tmp_path: Path):
    inner = tmp_path / "inner.zip"
    _zip_file(inner, {"payload/app.bin": b"binary"})
    outer = tmp_path / "outer.zip"
    _zip_file(outer, {"nested/inner.zip": inner.read_bytes()})

    output = tmp_path / "artifacts" / "out"
    manifest = extract_artifacts(outer, output, max_depth=2)

    assert manifest["status"] == "pass"
    assert manifest["extracted_count"] == 2
    assert list(output.rglob("app.bin"))


def test_extract_artifacts_blocks_zip_slip_paths(tmp_path: Path):
    archive = tmp_path / "bad.zip"
    _zip_file(archive, {"../evil.txt": b"nope"})

    output = tmp_path / "out"
    manifest = extract_artifacts(archive, output)

    assert manifest["status"] == "warn"
    assert manifest["failures"]
    assert not (tmp_path / "evil.txt").exists()
