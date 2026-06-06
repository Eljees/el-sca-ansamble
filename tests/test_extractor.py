from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

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


def test_extract_artifacts_marks_empty_file_input_as_failure(tmp_path: Path):
    plain_file = tmp_path / "plain.txt"
    plain_file.write_text("not an archive", encoding="utf-8")

    output = tmp_path / "out"
    manifest = extract_artifacts(plain_file, output)

    assert manifest["extracted_count"] == 0
    assert manifest["status"] == "warn"
    assert manifest["failures"]
    assert "no supported archive entries" in manifest["failures"][0]["error"]


def test_extract_tar_allows_root_dot_directory_entry(tmp_path: Path):
    archive = tmp_path / "sample.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        root = tarfile.TarInfo(".")
        root.type = tarfile.DIRTYPE
        tar.addfile(root)

        payload = b"hello"
        member = tarfile.TarInfo("./bin/tool")
        member.size = len(payload)
        tar.addfile(member, io.BytesIO(payload))

    output = tmp_path / "out"
    manifest = extract_artifacts(archive, output)

    assert manifest["status"] == "pass"
    assert manifest["extracted_count"] == 1
    assert list(output.rglob("tool"))


# ---------------------------------------------------------------------------
# _strip_archive_suffix — §12 regression guard
# ---------------------------------------------------------------------------

import pytest  # noqa: E402

from resilient_updates.extractor import _strip_archive_suffix  # noqa: E402


@pytest.mark.parametrize(
    "name,expected",
    [
        ("grype-db.tar.gz", "grype-db"),
        ("trivy.tar.bz2", "trivy"),
        ("syft.tar.xz", "syft"),
        ("data.tar.zst", "data"),
        ("archive.tgz", "archive"),
        ("archive.tbz2", "archive"),
        ("archive.zip", "archive"),
        ("simple.tar", "simple"),
        ("file.gz", "file"),
        ("file.zst", "file"),
        ("unknown.exe", "unknown"),  # falls back to Path.stem
        ("nodot", "nodot"),  # no extension at all
    ],
)
def test_strip_archive_suffix(name: str, expected: str):
    assert _strip_archive_suffix(name) == expected


# ---------------------------------------------------------------------------
# manifest structure — pre_filter and manifest_path keys present
# ---------------------------------------------------------------------------


def test_manifest_contains_pre_filter_block(tmp_path: Path):
    archive = tmp_path / "a.zip"
    _zip_file(archive, {"file.bin": b"data"})

    manifest = extract_artifacts(archive, tmp_path / "out")

    assert "pre_filter" in manifest, "manifest must contain pre_filter"
    pf = manifest["pre_filter"]
    assert "skipped_by_extension" in pf
    assert "skipped_by_size" in pf
    assert "examples" in pf


def test_manifest_contains_manifest_path_key(tmp_path: Path):
    archive = tmp_path / "a.zip"
    _zip_file(archive, {"file.bin": b"data"})
    output = tmp_path / "out"

    manifest = extract_artifacts(archive, output)

    assert "manifest_path" in manifest
    assert Path(manifest["manifest_path"]).name == "extraction_manifest.json"


def test_pre_filter_counts_skipped_by_extension(tmp_path: Path):
    archive = tmp_path  # noqa: F841 — test body incomplete, placeholder


from resilient_updates.extractor import _ensure_safe_member  # noqa: E402


def test_ensure_safe_member_strips_trailing_dot_component(tmp_path: Path):
    """``app./lib`` must normalize to the same path as ``app/lib`` (no ``app.`` dir).

    Regression for the duplicate ``app/`` + ``app.`` trees produced when a
    Windows app-image archive is unpacked in a Linux container.
    """
    dotted = _ensure_safe_member(tmp_path, "app./lib/x.txt")
    plain = _ensure_safe_member(tmp_path, "app/lib/x.txt")
    assert dotted == plain
    assert "app." not in dotted.parts
    assert "app" in dotted.parts


def test_ensure_safe_member_trailing_space_and_dots(tmp_path: Path):
    assert _ensure_safe_member(tmp_path, "dir .  /f").parts[-2] == "dir"
    # A component that is all dots/spaces collapses to a placeholder, not empty.
    assert _ensure_safe_member(tmp_path, ".../f").parts[-2] == "_"


def test_ensure_safe_member_still_blocks_traversal(tmp_path: Path):
    for bad in ("../evil", "a/../../evil", "/abs/path"):
        with pytest.raises(ValueError):
            _ensure_safe_member(tmp_path, bad)


def test_extract_artifacts_purges_previous_run_output(tmp_path: Path):
    """Regression: ``output_root`` must be purged before extraction.

    A leftover tree from a previous (different-target) run used to leak into
    the new scan — syft walks the whole ``current/`` dir, so stale files
    contaminated component/finding counts (CYBERSEC-12306 inherited 427
    Prometheus components from a prior CYBERSEC-11531 run).
    """
    output = tmp_path / "out"
    stale_dir = output / "depth0" / "old-target.tar.gz"
    stale_dir.mkdir(parents=True)
    (stale_dir / "stale.bin").write_bytes(b"old run")
    (output / "stale-root-file.txt").write_text("old", encoding="utf-8")

    archive = tmp_path / "new.zip"
    _zip_file(archive, {"fresh/app.bin": b"new"})

    manifest = extract_artifacts(archive, output, max_depth=1)

    assert manifest["status"] == "pass"
    assert not stale_dir.exists()
    assert not (output / "stale-root-file.txt").exists()
    assert list(output.rglob("app.bin"))
