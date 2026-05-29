"""Internal shared low-level helpers.

This module exists to remove duplicated `_sha256_file` / `_read_json`
implementations from `reporting.py`, `run_summary.py`, `extractor.py`,
and `scanner_diff.py` (see `docs/audit/20-architecture.md` §1).

The functions are deliberately conservative:

- file hashing reads in 1 MiB chunks for memory-bounded operation on
  cve-bin-tool DB caches that can exceed 6 GiB;
- JSON loaders return ``None`` on missing-file / decode-error so callers
  can use ``if data is None`` instead of try/except at every call site;
- nothing here imports any heavy dependency, so this module is safe to
  import from any other module in the package.

If you need a new low-level helper that two modules already inline —
add it here rather than copy-pasting.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from hashlib import sha1, sha256, sha512
from pathlib import Path
from typing import Any

_CHUNK = 1024 * 1024  # 1 MiB read buffer; safe for ~6 GiB DB caches.


# ---------------------------------------------------------------------------
# File hashing
# ---------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    """Hex-encoded SHA-256 of ``path``.  Streams the file in 1 MiB chunks."""
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha1_file(path: Path) -> str:
    """Hex-encoded SHA-1 of ``path``.  Streams in 1 MiB chunks.

    SHA-1 is kept only for compatibility with existing provenance schemas
    that already include both sha1 and sha256 of input archives.
    """
    digest = sha1()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha512_file(path: Path) -> str:
    """Hex-encoded SHA-512 of ``path``.  Streams in 1 MiB chunks."""
    digest = sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_pair(path: Path) -> dict[str, str]:
    """Return ``{"sha1": ..., "sha256": ...}`` in a single file pass.

    Cheaper than calling ``sha1_file(p)`` + ``sha256_file(p)`` because
    the file bytes are streamed once and fed to both hashers.
    """
    sha1_digest = sha1()
    sha256_digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            sha1_digest.update(chunk)
            sha256_digest.update(chunk)
    return {"sha1": sha1_digest.hexdigest(), "sha256": sha256_digest.hexdigest()}


def sha256_dir(path: Path) -> str:
    """Stable content-hash of a directory tree.

    Files are visited in sorted relative-path order; both the path and
    the contents are folded into the hash.  Forward slashes are used in
    the path even on Windows so the same tree hashes identically across
    platforms.
    """
    digest = sha256()
    for item in sorted(p for p in path.rglob("*") if p.is_file()):
        digest.update(str(item.relative_to(path)).replace("\\", "/").encode("utf-8"))
        digest.update(b"\0")
        with item.open("rb") as handle:
            for chunk in iter(lambda: handle.read(_CHUNK), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def short_hash(*parts: str, length: int = 12) -> str:
    """Short stable identifier from a tuple of strings.

    Used for ``run_id`` and ``db_snapshot_id`` style identifiers where a
    full hex digest would be unwieldy.  Collisions are theoretically
    possible (1 in 2^48 for the default length) but acceptable for
    human-readable run identifiers.
    """
    digest = sha256()
    for part in parts:
        digest.update(part.encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()[:length]


# ---------------------------------------------------------------------------
# JSON loaders
# ---------------------------------------------------------------------------


def read_json(path: Path) -> Any:
    """Read JSON from ``path`` returning ``None`` on missing / invalid input.

    The contract is "if you can't read it, behave like the file was absent",
    which matches what every existing caller already wants.  Logs are kept
    out of this helper on purpose; the caller decides whether a missing
    file is interesting.
    """
    try:
        if not path.exists() or path.is_dir():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def first_json(root: Path, relpaths: Iterable[str]) -> Any:
    """First non-``None`` ``read_json(root / rel)`` for the given relpaths."""
    for rel in relpaths:
        data = read_json(root / rel)
        if data is not None:
            return data
    return None


def collect_json(root: Path, names: Iterable[str]) -> list[Any]:
    """All non-``None`` ``read_json(root / name)`` results, preserving order."""
    payloads: list[Any] = []
    for name in names:
        data = read_json(root / name)
        if data is not None:
            payloads.append(data)
    return payloads
