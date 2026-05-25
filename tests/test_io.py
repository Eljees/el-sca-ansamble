"""Tests for resilient_updates._io shared helpers."""
from __future__ import annotations

from pathlib import Path

import pytest

from resilient_updates._io import (
    collect_json,
    first_json,
    hash_pair,
    read_json,
    sha1_file,
    sha256_dir,
    sha256_file,
    sha512_file,
    short_hash,
)


def test_sha256_file_matches_known_digest(tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_bytes(b"abc")
    # SHA-256("abc")
    assert sha256_file(f) == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sha1_and_sha512(tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_bytes(b"abc")
    assert sha1_file(f) == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert sha512_file(f).startswith("ddaf35a193617aba")


def test_hash_pair_streams_file_once(tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_bytes(b"hello")
    out = hash_pair(f)
    assert set(out.keys()) == {"sha1", "sha256"}
    assert out["sha1"] == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    assert out["sha256"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_sha256_dir_stable_across_runs(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"1")
    (tmp_path / "b").write_bytes(b"2")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "c").write_bytes(b"3")
    first = sha256_dir(tmp_path)
    second = sha256_dir(tmp_path)
    assert first == second
    assert len(first) == 64  # hex digest


def test_sha256_dir_sees_content_changes(tmp_path: Path) -> None:
    f = tmp_path / "a"
    f.write_bytes(b"1")
    digest_a = sha256_dir(tmp_path)
    f.write_bytes(b"2")
    digest_b = sha256_dir(tmp_path)
    assert digest_a != digest_b


def test_short_hash_length_default_12(tmp_path: Path) -> None:
    assert len(short_hash("foo", "bar")) == 12


def test_short_hash_deterministic() -> None:
    assert short_hash("a", "b") == short_hash("a", "b")
    assert short_hash("a", "b") != short_hash("b", "a")


def test_short_hash_custom_length() -> None:
    assert len(short_hash("x", length=20)) == 20


def test_read_json_missing_returns_none(tmp_path: Path) -> None:
    assert read_json(tmp_path / "missing.json") is None


def test_read_json_invalid_returns_none(tmp_path: Path) -> None:
    f = tmp_path / "bad.json"
    f.write_text("{not json}")
    assert read_json(f) is None


def test_read_json_directory_returns_none(tmp_path: Path) -> None:
    """A directory at the json path should not crash; returns None."""
    (tmp_path / "x").mkdir()
    assert read_json(tmp_path / "x") is None


def test_read_json_happy_path(tmp_path: Path) -> None:
    f = tmp_path / "ok.json"
    f.write_text('{"k": 1}')
    assert read_json(f) == {"k": 1}


def test_first_json_picks_first_existing(tmp_path: Path) -> None:
    (tmp_path / "b.json").write_text('{"who": "b"}')
    out = first_json(tmp_path, ["a.json", "b.json", "c.json"])
    assert out == {"who": "b"}


def test_first_json_all_missing_returns_none(tmp_path: Path) -> None:
    assert first_json(tmp_path, ["a.json", "b.json"]) is None


def test_collect_json_preserves_order(tmp_path: Path) -> None:
    (tmp_path / "a.json").write_text('{"i": 1}')
    (tmp_path / "b.json").write_text('{"i": 2}')
    out = collect_json(tmp_path, ["b.json", "a.json"])
    assert out == [{"i": 2}, {"i": 1}]
