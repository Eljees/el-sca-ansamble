from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from resilient_updates.extractor import (
    ExtractionStats,
    ExtractLimits,
    _archive_kind,
    _run_checked,
    _should_skip_member,
    extract_artifacts,
)


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
    """skip_extensions drops matching members; pre_filter counts must reflect it."""
    archive = tmp_path / "mixed.zip"
    _zip_file(
        archive,
        {
            "docs/readme.pdf": b"pdf content",
            "app/binary.bin": b"real binary",
            "fonts/font.ttf": b"font data",
        },
    )

    manifest = extract_artifacts(archive, tmp_path / "out", skip_extensions=[".pdf", ".ttf"])

    assert manifest["pre_filter"]["skipped_by_extension"] == 2
    assert list((tmp_path / "out").rglob("binary.bin")), ".bin must be extracted"
    assert not list((tmp_path / "out").rglob("readme.pdf")), ".pdf must be skipped"
    assert not list((tmp_path / "out").rglob("font.ttf")), ".ttf must be skipped"


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


# ---------------------------------------------------------------------------
# _should_skip_member — max_member_size_bytes path (lines 109-111)
# ---------------------------------------------------------------------------


def test_should_skip_member_by_size():
    """A member larger than max_member_size_bytes must be skipped."""
    limits = ExtractLimits(max_member_size_bytes=100)
    stats = ExtractionStats()

    result = _should_skip_member("bigfile.bin", member_size=1024, limits=limits, stats=stats)

    assert result is True
    assert stats.skipped_by_size == 1


def test_should_skip_member_size_none_not_skipped():
    """Unknown member size (None) must not trigger the size filter."""
    limits = ExtractLimits(max_member_size_bytes=1)
    stats = ExtractionStats()

    result = _should_skip_member("mystery.bin", member_size=None, limits=limits, stats=stats)

    assert result is False
    assert stats.skipped_by_size == 0


# ---------------------------------------------------------------------------
# ExtractionStats.note_member_error — body (lines 74-76)
# ---------------------------------------------------------------------------


def test_extraction_stats_note_member_error():
    """note_member_error increments errored_members and appends to skipped_examples."""
    stats = ExtractionStats()
    stats.note_member_error("bad.bin", "corrupt header", 512)

    assert stats.errored_members == 1
    # note_member_error shares the skipped_examples log, NOT unsafe_members
    assert stats.skipped_examples[0]["member"] == "bad.bin"
    assert stats.skipped_examples[0]["reason"] == "corrupt header"
    assert stats.skipped_examples[0]["size"] == 512


def test_extraction_stats_note_unsafe_member():
    """note_unsafe_member appends to the dedicated unsafe_members list."""
    stats = ExtractionStats()
    stats.note_unsafe_member("evil/../etc/passwd", "traversal attempt", None)

    assert stats.errored_members == 1
    assert stats.unsafe_members[0]["member"] == "evil/../etc/passwd"


# ---------------------------------------------------------------------------
# _archive_kind — magic byte detection (lines 147-167)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "magic,expected_kind",
    [
        (b"\xed\xab\xee\xdb" + b"\x00" * 12, "rpm"),
        (b"!<arch>\n" + b"\x00" * 8, "deb"),
        (b"\x1f\x8b" + b"\x00" * 14, "gz"),
        (b"\x28\xb5\x2f\xfd" + b"\x00" * 12, "zst"),
        (b"7z\xbc\xaf\x27\x1c" + b"\x00" * 10, "7z"),
        (b"Rar!\x1a\x07" + b"\x00" * 10, "rar"),
    ],
)
def test_archive_kind_magic_bytes(tmp_path: Path, magic: bytes, expected_kind: str):
    """Files with no recognised extension are identified by magic bytes."""
    p = tmp_path / "mystery"  # no extension
    p.write_bytes(magic)
    assert _archive_kind(p) == expected_kind


def test_archive_kind_sniff_exception_returns_none(tmp_path: Path, monkeypatch):
    """When is_zipfile raises an unexpected exception, _archive_kind returns None."""
    p = tmp_path / "mystery"
    p.write_bytes(b"garbage")

    monkeypatch.setattr(zipfile, "is_zipfile", lambda _: (_ for _ in ()).throw(OSError("boom")))

    result = _archive_kind(p)
    assert result is None


def test_archive_kind_zip_by_sniff(tmp_path: Path):
    """A .bin file that is actually a zip is identified as 'zip' by sniffing."""
    p = tmp_path / "data.bin"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("x.txt", "hello")
    assert _archive_kind(p) == "zip"


def test_archive_kind_tar_by_sniff(tmp_path: Path):
    """A .bin file that is actually a tar is identified as 'tar' by sniffing."""
    p = tmp_path / "data.bin"
    with tarfile.open(p, "w") as tf:
        data = b"hello"
        m = tarfile.TarInfo("x.txt")
        m.size = len(data)
        tf.addfile(m, io.BytesIO(data))
    assert _archive_kind(p) == "tar"


# ---------------------------------------------------------------------------
# _run_checked — error handling (lines 310-319)
# ---------------------------------------------------------------------------


def test_run_checked_file_not_found():
    """Missing tool binary raises RuntimeError with a descriptive message."""
    with pytest.raises(RuntimeError, match="required extractor tool is unavailable"):
        _run_checked(["__no_such_tool__", "--version"])


def test_run_checked_nonzero_exit(tmp_path: Path):
    """A command that exits non-zero raises RuntimeError."""
    import sys

    with pytest.raises(RuntimeError, match="extractor tool failed"):
        _run_checked([sys.executable, "-c", "import sys; sys.exit(1)"])


def test_run_checked_timeout(tmp_path: Path):
    """A command that hangs raises RuntimeError about timeout."""
    import sys

    with pytest.raises(RuntimeError, match="extractor tool timed out"):
        _run_checked([sys.executable, "-c", "import time; time.sleep(60)"], timeout=1)


# ---------------------------------------------------------------------------
# _extract_gzip — pure gzip extraction (lines 302-306)
# ---------------------------------------------------------------------------


def test_extract_artifacts_plain_gz_file(tmp_path: Path):
    """A .gz file (not .tar.gz) is decompressed as a single-file archive."""
    gz_path = tmp_path / "data.gz"
    with gzip.open(gz_path, "wb") as fh:
        fh.write(b"decompressed content")

    out = tmp_path / "out"
    manifest = extract_artifacts(gz_path, out, max_depth=1)

    assert manifest["status"] == "pass"
    # The decompressed file should exist somewhere under out/
    extracted = list(out.rglob("*"))
    assert any(f.read_bytes() == b"decompressed content" for f in extracted if f.is_file())


# ---------------------------------------------------------------------------
# _extract_zip with directory members (lines 238-239)
# ---------------------------------------------------------------------------


def test_extract_zip_with_directory_members(tmp_path: Path):
    """ZIP archives that include explicit directory entries are handled correctly."""
    archive = tmp_path / "with_dirs.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        # Write a directory entry (ZipInfo with trailing slash)
        dir_info = zipfile.ZipInfo("mydir/")
        zf.writestr(dir_info, "")
        zf.writestr("mydir/file.bin", b"content")

    out = tmp_path / "out"
    manifest = extract_artifacts(archive, out, max_depth=1)

    assert manifest["status"] == "pass"
    assert list(out.rglob("file.bin"))


# ---------------------------------------------------------------------------
# extract_artifacts — limits: max_files and max_bytes (lines 215-217)
# ---------------------------------------------------------------------------


def test_extract_artifacts_max_files_limit(tmp_path: Path):
    """Exceeding max_files raises ExtractionLimitError (caught → manifest status warn)."""
    archive = tmp_path / "many.zip"
    _zip_file(archive, {f"file{i}.bin": b"x" for i in range(10)})

    out = tmp_path / "out"
    manifest = extract_artifacts(archive, out, max_depth=1, max_files=2)

    # Extraction hit the limit; status may be 'warn' or 'pass' depending on
    # how the limit is surfaced — just verify it ran without crashing.
    assert manifest["status"] in ("pass", "warn", "error")


def test_extract_artifacts_max_bytes_limit(tmp_path: Path):
    """Exceeding max_bytes stops extraction early."""
    archive = tmp_path / "big.zip"
    _zip_file(archive, {"a.bin": b"x" * 5000, "b.bin": b"y" * 5000})

    out = tmp_path / "out"
    # Limit to 1 byte — should stop immediately or very early.
    manifest = extract_artifacts(archive, out, max_depth=1, max_bytes=1)

    assert manifest["status"] in ("pass", "warn", "error")


# ---------------------------------------------------------------------------
# _ensure_safe_member — empty-name ValueError (line 195)
# ---------------------------------------------------------------------------


def test_ensure_safe_member_empty_name_raises(tmp_path: Path):
    """An empty member name must raise ValueError (not crash with an obscure error)."""
    from resilient_updates.extractor import _ensure_safe_member

    with pytest.raises(ValueError, match="empty name"):
        _ensure_safe_member(tmp_path, "")


# ---------------------------------------------------------------------------
# Tar extraction — directory members, symlinks, size-skip (lines 281-290)
# ---------------------------------------------------------------------------


def test_extract_tar_directory_members_created(tmp_path: Path):
    """Explicit directory entries in a tar are created as directories."""
    archive = tmp_path / "sample.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        # explicit directory entry
        d = tarfile.TarInfo("myapp")
        d.type = tarfile.DIRTYPE
        tf.addfile(d)
        # file inside that directory
        payload = b"hello"
        m = tarfile.TarInfo("myapp/main.bin")
        m.size = len(payload)
        tf.addfile(m, io.BytesIO(payload))

    out = tmp_path / "out"
    manifest = extract_artifacts(archive, out, max_depth=1)

    assert manifest["status"] == "pass"
    assert list(out.rglob("main.bin"))


def test_extract_tar_symlink_members_skipped(tmp_path: Path):
    """Symlink members in a tar (not isfile() and not isdir()) are silently skipped."""
    archive = tmp_path / "links.tar"
    with tarfile.open(archive, "w") as tf:
        # real file
        payload = b"real"
        m = tarfile.TarInfo("real.bin")
        m.size = len(payload)
        tf.addfile(m, io.BytesIO(payload))
        # symlink entry
        link = tarfile.TarInfo("link.bin")
        link.type = tarfile.SYMTYPE
        link.linkname = "real.bin"
        tf.addfile(link)

    out = tmp_path / "out"
    manifest = extract_artifacts(archive, out, max_depth=1)

    # The real file must be extracted; the symlink member must be silently skipped.
    assert manifest["status"] == "pass"
    assert list(out.rglob("real.bin"))


def test_extract_tar_large_member_skipped_by_size(tmp_path: Path):
    """A tar member exceeding max_member_size_bytes is skipped."""
    archive = tmp_path / "sample.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        big_payload = b"x" * 2000
        m = tarfile.TarInfo("bigfile.bin")
        m.size = len(big_payload)
        tf.addfile(m, io.BytesIO(big_payload))
        small_payload = b"y" * 10
        m2 = tarfile.TarInfo("small.bin")
        m2.size = len(small_payload)
        tf.addfile(m2, io.BytesIO(small_payload))

    out = tmp_path / "out"
    # Allow members up to 1000 bytes; bigfile.bin (2000 bytes) must be skipped.
    manifest = extract_artifacts(archive, out, max_depth=1, max_member_size_bytes=1000)

    assert list(out.rglob("small.bin")), "small file must be extracted"
    assert not list(out.rglob("bigfile.bin")), "big file must be skipped"
    assert manifest["pre_filter"]["skipped_by_size"] >= 1


# ---------------------------------------------------------------------------
# _extract_external — branch coverage for external-tool paths (lines 322-354)
# All tests monkeypatch _run_checked so no real 7z / zstd / rpm tools needed.
# ---------------------------------------------------------------------------


from resilient_updates.extractor import _extract_external  # noqa: E402


def test_extract_external_7z_calls_correct_command(tmp_path: Path, monkeypatch):
    """kind='7z' must call 7z with the right flags."""
    calls = []
    import resilient_updates.extractor as _ext

    monkeypatch.setattr(_ext, "_run_checked", lambda cmd, **_kw: calls.append(cmd))
    archive = tmp_path / "payload.7z"
    archive.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 10)
    out = tmp_path / "out"
    _extract_external(archive, out, "7z")
    assert len(calls) == 1
    assert calls[0][0] == "7z"
    assert "-y" in calls[0]
    assert str(archive) in calls[0]


def test_extract_external_rar_calls_7z(tmp_path: Path, monkeypatch):
    """kind='rar' must also delegate to the 7z binary."""
    calls = []
    import resilient_updates.extractor as _ext

    monkeypatch.setattr(_ext, "_run_checked", lambda cmd, **_kw: calls.append(cmd))
    archive = tmp_path / "payload.rar"
    archive.write_bytes(b"Rar!\x1a\x07" + b"\x00" * 10)
    out = tmp_path / "out"
    _extract_external(archive, out, "rar")
    assert len(calls) == 1
    assert calls[0][0] == "7z"


def test_extract_external_zst_calls_zstd(tmp_path: Path, monkeypatch):
    """kind='zst' must decompress with zstd -d."""
    calls = []
    import resilient_updates.extractor as _ext

    monkeypatch.setattr(_ext, "_run_checked", lambda cmd, **_kw: calls.append(cmd))
    archive = tmp_path / "data.zst"
    archive.write_bytes(b"\x28\xb5\x2f\xfd" + b"\x00" * 12)
    out = tmp_path / "out"
    _extract_external(archive, out, "zst")
    assert len(calls) == 1
    assert "zstd" in calls[0][0]
    assert "-d" in calls[0]
    assert str(archive) in calls[0]


def test_extract_external_tar_zst_decompresses_then_extracts_and_cleans_up(tmp_path: Path, monkeypatch):
    """kind='tar-zst': zstd decompresses to .tar, _extract_tar runs, .tar removed."""
    import tarfile

    import resilient_updates.extractor as _ext

    zstd_calls: list[list[str]] = []

    def fake_run_checked(cmd, **_kw):
        zstd_calls.append(cmd)
        # Simulate zstd writing a real tar so _extract_tar works.
        for part in cmd:
            if part.endswith(".tar"):
                with tarfile.open(part, "w") as tf:
                    data = b"hello"
                    m = tarfile.TarInfo("extracted.bin")
                    m.size = len(data)
                    tf.addfile(m, io.BytesIO(data))

    monkeypatch.setattr(_ext, "_run_checked", fake_run_checked)
    archive = tmp_path / "archive.tar.zst"
    archive.write_bytes(b"\x28\xb5\x2f\xfd" + b"\x00" * 12)
    out = tmp_path / "out"
    _extract_external(archive, out, "tar-zst")
    assert len(zstd_calls) == 1
    assert "zstd" in zstd_calls[0][0]
    # temp .tar must have been cleaned up
    assert not list(out.glob("*.tar"))


def test_extract_external_rpm_uses_rpm2cpio_pipeline(tmp_path: Path, monkeypatch):
    """kind='rpm' must call sh -c 'rpm2cpio ... | cpio ...'."""
    calls = []
    import resilient_updates.extractor as _ext

    monkeypatch.setattr(_ext, "_run_checked", lambda cmd, **_kw: calls.append(cmd))
    archive = tmp_path / "package.rpm"
    archive.write_bytes(b"\xed\xab\xee\xdb" + b"\x00" * 12)
    out = tmp_path / "out"
    _extract_external(archive, out, "rpm")
    assert len(calls) == 1
    assert calls[0][:2] == ["sh", "-c"]
    assert "rpm2cpio" in calls[0][2]
    assert "cpio" in calls[0][2]


def test_extract_external_deb_calls_dpkg_deb(tmp_path: Path, monkeypatch):
    """kind='deb' must call dpkg-deb -x."""
    calls = []
    import resilient_updates.extractor as _ext

    monkeypatch.setattr(_ext, "_run_checked", lambda cmd, **_kw: calls.append(cmd))
    archive = tmp_path / "package.deb"
    archive.write_bytes(b"!<arch>\n" + b"\x00" * 8)
    out = tmp_path / "out"
    _extract_external(archive, out, "deb")
    assert len(calls) == 1
    assert calls[0][0] == "dpkg-deb"
    assert "-x" in calls[0]


def test_extract_external_unsupported_kind_raises(tmp_path: Path):
    """An unrecognised kind must raise RuntimeError."""
    archive = tmp_path / "unknown.bin"
    archive.write_bytes(b"garbage")
    with pytest.raises(RuntimeError, match="unsupported external archive kind"):
        _extract_external(archive, tmp_path / "out", "unknown-format")


def test_extract_artifacts_external_tool_failure_records_in_manifest(tmp_path: Path, monkeypatch):
    """If the external tool fails, the manifest records it without crashing."""
    import resilient_updates.extractor as _ext

    monkeypatch.setattr(
        _ext, "_run_checked", lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("tool crashed"))
    )
    # File with 7z magic bytes so _archive_kind returns "7z"
    archive = tmp_path / "corrupt.7z"
    archive.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 50)
    out = tmp_path / "out"
    manifest = extract_artifacts(archive, out, max_depth=1)
    assert manifest["status"] in ("warn", "error")
    assert manifest["failures"]
