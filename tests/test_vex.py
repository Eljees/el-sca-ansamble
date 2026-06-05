"""Tests for resilient_updates.vex — VEX document acquisition module.

Covers:
  - Pure helper functions: _vex_dir, _format_for, _ext_for, _now_iso
  - Filesystem helpers: _atomic_write_bytes, _fresh_lkg
  - Main acquisition function: fetch_vex (happy path, LKG fallback, no-sources)

The fetch_vex tests patch attempt_sources so no real HTTP calls are made.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

if sys.version_info < (3, 11):
    pytest.skip("vex module requires Python 3.11+ (datetime.UTC)", allow_module_level=True)

from resilient_updates.source_policy import SourceCandidate
from resilient_updates.vex import (
    _atomic_write_bytes,
    _ext_for,
    _format_for,
    _fresh_lkg,
    _now_iso,
    _vex_dir,
    fetch_vex,
)

# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


def _minimal_config(tmp_path: Path, vex_repos: list | None = None) -> dict:
    """Minimal feed_sources-style config for vex tests."""
    return {
        "trivy": {
            "cache_dir": str(tmp_path / "trivy"),
            "vex_repositories": vex_repos or [],
            "vex_policy": {"enabled": True, "require_fresh_hours": 168},
            "retry_backoff_policy": {
                "retry_count": 0,
                "timeout_seconds": 1,
                "backoff_seconds": 0,
                "retry_status_codes": [429, 500],
            },
        }
    }


def _make_source(name: str = "primary", url: str = "http://example.invalid/vex.json") -> SourceCandidate:
    return SourceCandidate(priority=10, name=name, url=url, tool="trivy", layer="trivy-vex")


# ─────────────────────────────────────────────────────────────────────────────
# _vex_dir
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.smoke
def test_vex_dir_uses_cache_dir(tmp_path: Path) -> None:
    cfg = {"trivy": {"cache_dir": str(tmp_path / "cache")}}
    result = _vex_dir(cfg)
    assert result == tmp_path / "cache" / "vex"


def test_vex_dir_default_when_missing() -> None:
    result = _vex_dir({})
    assert result == Path("/var/lib/resilient-db/trivy/vex")


# ─────────────────────────────────────────────────────────────────────────────
# _format_for
# ─────────────────────────────────────────────────────────────────────────────


def test_format_for_matches_source_name() -> None:
    cfg = {
        "trivy": {
            "vex_repositories": [
                {"name": "primary", "format": "csaf"},
                {"name": "secondary", "format": "cyclonedx"},
            ]
        }
    }
    assert _format_for(cfg, "primary") == "csaf"
    assert _format_for(cfg, "secondary") == "cyclonedx"


def test_format_for_returns_default_when_no_match() -> None:
    cfg = {"trivy": {"vex_repositories": []}}
    assert _format_for(cfg, "unknown") == "openvex"


def test_format_for_lowercases_value() -> None:
    cfg = {"trivy": {"vex_repositories": [{"name": "s", "format": "CSAF"}]}}
    assert _format_for(cfg, "s") == "csaf"


# ─────────────────────────────────────────────────────────────────────────────
# _ext_for
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "fmt,expected",
    [
        ("openvex", "openvex.json"),
        ("csaf", "csaf.json"),
        ("cyclonedx", "cdx.json"),
        ("unknown_format", "openvex.json"),  # falls back to default
    ],
)
def test_ext_for(fmt: str, expected: str) -> None:
    assert _ext_for(fmt) == expected


# ─────────────────────────────────────────────────────────────────────────────
# _now_iso
# ─────────────────────────────────────────────────────────────────────────────


def test_now_iso_returns_utc_string() -> None:
    result = _now_iso()
    # Must be a non-empty ISO 8601 string containing timezone info.
    assert isinstance(result, str)
    assert "+" in result or result.endswith("Z") or "+00:00" in result


# ─────────────────────────────────────────────────────────────────────────────
# _atomic_write_bytes
# ─────────────────────────────────────────────────────────────────────────────


def test_atomic_write_bytes_creates_file(tmp_path: Path) -> None:
    target = tmp_path / "doc.json"
    _atomic_write_bytes(target, b'{"vex": true}')
    assert target.read_bytes() == b'{"vex": true}'


def test_atomic_write_bytes_no_temp_file_left(tmp_path: Path) -> None:
    target = tmp_path / "doc.json"
    _atomic_write_bytes(target, b"data")
    leftovers = list(tmp_path.glob("*.new"))
    assert leftovers == [], f"Temp file not cleaned up: {leftovers}"


def test_atomic_write_bytes_overwrites_existing(tmp_path: Path) -> None:
    target = tmp_path / "doc.json"
    target.write_bytes(b"old")
    _atomic_write_bytes(target, b"new")
    assert target.read_bytes() == b"new"


# ─────────────────────────────────────────────────────────────────────────────
# _fresh_lkg
# ─────────────────────────────────────────────────────────────────────────────


def test_fresh_lkg_missing_dir_returns_empty(tmp_path: Path) -> None:
    result = _fresh_lkg(tmp_path / "nonexistent", max_age_hours=24)
    assert result == []


def test_fresh_lkg_returns_recent_files(tmp_path: Path) -> None:
    vex_dir = tmp_path / "vex"
    vex_dir.mkdir()
    recent = vex_dir / "primary.openvex.json"
    recent.write_bytes(b"openvex-doc")
    # mtime is now — well within 24h window
    result = _fresh_lkg(vex_dir, max_age_hours=24)
    assert recent in result


def test_fresh_lkg_excludes_stale_files(tmp_path: Path) -> None:
    vex_dir = tmp_path / "vex"
    vex_dir.mkdir()
    stale = vex_dir / "old.openvex.json"
    stale.write_bytes(b"old")
    # Set mtime to 48 hours ago
    old_mtime = time.time() - 48 * 3600
    import os

    os.utime(stale, (old_mtime, old_mtime))
    result = _fresh_lkg(vex_dir, max_age_hours=24)
    assert stale not in result


def test_fresh_lkg_excludes_dot_new_files(tmp_path: Path) -> None:
    vex_dir = tmp_path / "vex"
    vex_dir.mkdir()
    tmp_file = vex_dir / "doc.openvex.json.new"
    tmp_file.write_bytes(b"partial")
    result = _fresh_lkg(vex_dir, max_age_hours=24)
    assert tmp_file not in result


# ─────────────────────────────────────────────────────────────────────────────
# fetch_vex
# ─────────────────────────────────────────────────────────────────────────────


def _make_attempt_result(source: SourceCandidate, success: bool):
    from resilient_updates.fallback import AttemptResult, FailureReason

    return AttemptResult(
        source=source,
        success=success,
        reason=None if success else FailureReason.DNS_OR_NETWORK,
        message="ok" if success else "connection refused",
        status_code=200 if success else None,
    )


def test_fetch_vex_happy_path(tmp_path: Path) -> None:
    """fetch_vex publishes VEX bytes and returns activation_status='published'."""
    vex_content = b'{"@context": "https://openvex.dev/ns/v0.2.0"}'
    source = _make_source()
    cfg = _minimal_config(
        tmp_path, vex_repos=[{"name": "primary", "url": source.url, "priority": 10, "enabled": True}]
    )

    with (
        patch("resilient_updates.vex.build_sources", return_value=[source]),
        patch(
            "resilient_updates.vex.attempt_sources",
            return_value=(source, vex_content, [_make_attempt_result(source, True)]),
        ),
        patch("resilient_updates.vex.write_provenance"),
    ):
        result = fetch_vex(cfg)

    assert result["activation_status"] == "published"
    assert result["used_last_known_good"] is False
    assert len(result["published"]) == 1
    assert result["published"][0]["source"] == "primary"


def test_fetch_vex_uses_lkg_when_all_sources_fail(tmp_path: Path) -> None:
    """fetch_vex falls back to a recently-cached file when download fails."""
    source = _make_source()
    cfg = _minimal_config(
        tmp_path, vex_repos=[{"name": "primary", "url": source.url, "priority": 10, "enabled": True}]
    )

    # Pre-populate the VEX cache directory with a "fresh" file
    vex_dir = tmp_path / "trivy" / "vex"
    vex_dir.mkdir(parents=True)
    lkg_file = vex_dir / "cached.openvex.json"
    lkg_file.write_bytes(b"old-but-valid")

    with (
        patch("resilient_updates.vex.build_sources", return_value=[source]),
        patch(
            "resilient_updates.vex.attempt_sources",
            return_value=(None, None, [_make_attempt_result(source, False)]),
        ),
        patch("resilient_updates.vex.write_provenance"),
    ):
        result = fetch_vex(cfg)

    assert result["used_last_known_good"] is True
    assert result["activation_status"] == "published"
    assert any(p["source"] == "last-known-good" for p in result["published"])


def test_fetch_vex_no_sources_configured(tmp_path: Path) -> None:
    """fetch_vex with no vex_repositories returns all-sources-failed without crashing."""
    cfg = _minimal_config(tmp_path, vex_repos=[])

    with (
        patch("resilient_updates.vex.build_sources", return_value=[]),
        patch("resilient_updates.vex.write_provenance"),
    ):
        result = fetch_vex(cfg)

    assert result["activation_status"] == "all-sources-failed"
    assert result["published"] == []
    assert result["used_last_known_good"] is False
