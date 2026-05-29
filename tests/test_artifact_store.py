from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from resilient_updates.artifact_store import (
    LastKnownGood,
    build_last_known_good,
    ensure_directory,
    file_sha256,
)

# ---------------------------------------------------------------------------
# ensure_directory
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_ensure_directory_creates_nested(tmp_path: Path):
    target = tmp_path / "a" / "b" / "c"
    result = ensure_directory(target)
    assert result == target
    assert target.is_dir()


def test_ensure_directory_is_idempotent(tmp_path: Path):
    d = tmp_path / "existing"
    d.mkdir()
    (d / "file.txt").write_text("keep me", encoding="utf-8")
    ensure_directory(d)
    assert (d / "file.txt").read_text(encoding="utf-8") == "keep me"


# ---------------------------------------------------------------------------
# file_sha256
# ---------------------------------------------------------------------------


def test_file_sha256_prefix_and_length(tmp_path: Path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"hello world")
    digest = file_sha256(f)
    assert digest.startswith("sha256:")
    # hex part is 64 chars
    assert len(digest) == len("sha256:") + 64


def test_file_sha256_deterministic(tmp_path: Path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"\x00" * 1024)
    assert file_sha256(f) == file_sha256(f)


def test_file_sha256_differs_for_different_content(tmp_path: Path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"aaa")
    b.write_bytes(b"bbb")
    assert file_sha256(a) != file_sha256(b)


def test_file_sha256_accepts_string_path(tmp_path: Path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"data")
    assert file_sha256(str(f)).startswith("sha256:")


# ---------------------------------------------------------------------------
# LastKnownGood
# ---------------------------------------------------------------------------


def test_lkg_missing_path_is_not_usable(tmp_path: Path):
    lkg = LastKnownGood(path=tmp_path / "nonexistent", max_age_hours=24)
    assert lkg.is_usable() is False


def test_lkg_empty_directory_is_not_usable(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    lkg = LastKnownGood(path=empty, max_age_hours=24)
    assert lkg.is_usable() is False


def test_lkg_fresh_file_is_usable(tmp_path: Path):
    f = tmp_path / "db.bin"
    f.write_bytes(b"data")
    lkg = LastKnownGood(path=f, max_age_hours=24)
    assert lkg.is_usable() is True


def test_lkg_stale_file_is_not_usable(tmp_path: Path):
    f = tmp_path / "db.bin"
    f.write_bytes(b"data")
    stale_ts = time.time() - 3 * 3600  # 3 hours old
    os.utime(f, (stale_ts, stale_ts))
    lkg = LastKnownGood(path=f, max_age_hours=2)
    assert lkg.is_usable() is False


def test_lkg_directory_with_files_is_usable(tmp_path: Path):
    d = tmp_path / "db_dir"
    d.mkdir()
    (d / "cve.db").write_bytes(b"data")
    lkg = LastKnownGood(path=d, max_age_hours=24)
    assert lkg.is_usable() is True


# ---------------------------------------------------------------------------
# build_last_known_good
# ---------------------------------------------------------------------------


def test_build_lkg_parses_duration(tmp_path: Path):
    lkg = build_last_known_good(tmp_path / "x", "48h")
    assert lkg.max_age_hours == 48


def test_build_lkg_parses_minutes(tmp_path: Path):
    lkg = build_last_known_good(tmp_path / "x", "120m")
    assert lkg.max_age_hours == 2  # 120m → 2h
