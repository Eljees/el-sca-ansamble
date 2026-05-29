"""Tests for the file:// URL handler on POSIX-vs-Windows paths.

The Windows fix in fallback.fetch_bytes routes parsed.path through
urllib.request.url2pathname so that '/C:/x/y' becomes a real Windows
path on Windows and stays a POSIX path elsewhere.  See
docs/audit/10-defects.md section 4.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from resilient_updates.fallback import fetch_bytes


def test_file_url_reads_existing_file(tmp_path: Path) -> None:
    f = tmp_path / "payload.bin"
    f.write_bytes(b"hello")
    status, body = fetch_bytes(f.as_uri(), timeout=1)
    assert status == 200
    assert body == b"hello"


def test_file_url_raises_for_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "no-such.bin"
    with pytest.raises(FileNotFoundError):
        fetch_bytes(missing.as_uri(), timeout=1)


def test_file_url_uses_url2pathname(tmp_path: Path, monkeypatch) -> None:
    """Spy that url2pathname is the bridge — protects the Windows fix."""
    f = tmp_path / "p.bin"
    f.write_bytes(b"x")
    seen: list[str] = []
    import resilient_updates.fallback as fb

    real = fb.url2pathname

    def spy(p: str) -> str:
        seen.append(p)
        return real(p)

    monkeypatch.setattr(fb, "url2pathname", spy)
    status, body = fetch_bytes(f.as_uri(), timeout=1)
    assert status == 200
    assert body == b"x"
    assert seen, "url2pathname should have been called for the file:// URL"
