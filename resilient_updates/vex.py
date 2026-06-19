"""VEX document acquisition for Trivy (ADR-0003).

Fetches the configured VEX document(s) through the same resilient fallback
pipeline used for DB layers, publishes them atomically into
``<trivy cache_dir>/vex/``, and records provenance.  ``cli render-flags trivy``
then passes the published files to Trivy via ``--vex`` (see
``cli._render_trivy_flags``).

Design notes live in ``docs/adr/0003-vex-feed.md``.  Acquisition is a no-op for
callers that have not configured ``trivy.vex_repositories`` — ``build_sources``
returns an empty list and the run is reported as ``all-sources-failed`` without
touching the cache.
"""

from __future__ import annotations

import os

try:
    from datetime import UTC  # py3.11+
except ImportError:
    from datetime import timezone as _tz

    UTC = _tz.utc  # noqa: UP017
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

from ._io import hash_pair
from ._retry import RetryPolicy
from .artifact_store import ensure_directory
from .fallback import attempt_sources
from .provenance import write_provenance
from .source_policy import build_sources

# VEX format -> published filename extension.  Trivy sniffs the actual format
# from the document content; the extension is only for human/provenance clarity.
_FORMAT_EXT = {
    "openvex": "openvex.json",
    "csaf": "csaf.json",
    "cyclonedx": "cdx.json",
}
_DEFAULT_FORMAT = "openvex"

VEX_PROVENANCE_PATH = Path("artifacts/provenance/trivy-vex.json")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _vex_dir(config: dict[str, Any]) -> Path:
    cache_dir = config.get("trivy", {}).get("cache_dir", "/var/lib/resilient-db/trivy")
    return Path(cache_dir) / "vex"


def _format_for(config: dict[str, Any], source_name: str) -> str:
    for entry in config.get("trivy", {}).get("vex_repositories", []) or []:
        if entry.get("name") == source_name:
            return str(entry.get("format", _DEFAULT_FORMAT)).lower()
    return _DEFAULT_FORMAT


def _ext_for(fmt: str) -> str:
    return _FORMAT_EXT.get(fmt, _FORMAT_EXT[_DEFAULT_FORMAT])


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` via a temp file + ``os.replace`` (atomic on
    one volume, on POSIX and Windows alike)."""
    tmp = path.with_name(path.name + ".new")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _fresh_lkg(vex_dir: Path, max_age_hours: float) -> list[Path]:
    """Previously-published VEX files still within the freshness window.

    Tolerant of an unreadable cache dir (``OSError``/``PermissionError`` under a
    non-root container user): treated as "no LKG available" rather than raising.
    """
    cutoff = datetime.now(UTC).timestamp() - max_age_hours * 3600
    try:
        if not vex_dir.is_dir():
            return []
        candidates = sorted(vex_dir.glob("*"))
        return [
            p
            for p in candidates
            if p.is_file() and not p.name.endswith(".new") and p.stat().st_mtime >= cutoff
        ]
    except OSError:
        return []


def fetch_vex(config: dict[str, Any], *, session: requests.Session | None = None) -> dict[str, Any]:
    """Fetch + atomically publish VEX docs for Trivy and write provenance.

    Returns the provenance payload.  The caller maps it to an exit code
    (``published``/``used_last_known_good`` => success).
    """
    policy = config.get("trivy", {}).get("vex_policy", {}) or {}
    require_fresh_hours = float(policy.get("require_fresh_hours", 168))
    retry = RetryPolicy.from_tool_config(config, "trivy")
    sources = build_sources(config, "trivy", "trivy-vex")
    vex_dir = ensure_directory(_vex_dir(config))

    published: list[dict[str, Any]] = []
    attempted: list[dict[str, Any]] = []
    selected_source: dict[str, Any] | None = None

    for source in sources:
        candidate, payload, attempts = attempt_sources(
            [source],
            **retry.as_attempt_kwargs(),
            session=session,
        )
        for a in attempts:
            attempted.append(
                {
                    "source": a.source.name,
                    "success": a.success,
                    "reason": a.reason.value if a.reason else None,
                    "message": a.message,
                    "status_code": a.status_code,
                }
            )
        if candidate and payload:
            fmt = _format_for(config, candidate.name)
            target = vex_dir / f"{candidate.name}.{_ext_for(fmt)}"
            _atomic_write_bytes(target, payload)
            published.append(
                {
                    "source": candidate.name,
                    "format": fmt,
                    "path": str(target),
                    "hashes": hash_pair(target),
                }
            )
            if selected_source is None:
                selected_source = candidate.to_dict()

    used_last_known_good = False
    if not published:
        for stale_safe in _fresh_lkg(vex_dir, require_fresh_hours):
            used_last_known_good = True
            published.append(
                {
                    "source": "last-known-good",
                    "path": str(stale_safe),
                    "hashes": hash_pair(stale_safe),
                }
            )

    payload = {
        "tool": "trivy",
        "artifact_type": "trivy-vex",
        "selected_source": selected_source,
        "published": published,
        "attempted_sources": attempted,
        "used_last_known_good": used_last_known_good,
        "policy_enabled": bool(policy.get("enabled")),
        "activation_status": "published" if published else "all-sources-failed",
        "timestamp_utc": _now_iso(),
    }
    write_provenance(VEX_PROVENANCE_PATH, payload)
    return payload
