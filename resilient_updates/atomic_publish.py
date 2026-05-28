from __future__ import annotations

import errno
import os
from pathlib import Path
import shutil


def _replace_tree(src: Path, dst: Path) -> None:
    """Move directory tree src -> dst, using an atomic rename wherever possible.

    Same-volume (normal case)
    -------------------------
    ``Path.replace()`` maps to a single ``os.rename()`` / ``MoveFileExW``
    syscall, which is atomic on both NTFS and ext4.  *dst must not exist*
    before this call -- the caller (``publish_directory``) guarantees that.

    Cross-device (EXDEV)
    --------------------
    When src and dst live on different block devices (e.g. a Docker named
    volume for staging, and a bind-mounted NTFS path for the active tree)
    ``os.rename`` raises ``EXDEV``.  The naive fix -- ``rmtree(dst) +
    copytree(src, dst)`` -- is dangerous: if the copy is interrupted, dst
    is left partially written with no rollback path.

    Instead we:
      1. Copy src into a *sibling* staging directory (``dst.parent/
         .staging_<name>_<pid>``).  Because staging lives on the same
         volume as dst, the next step is an intra-volume rename.
      2. Rename staging -> dst atomically.
      3. Remove src (best-effort; an orphaned src is harmless).

    The "dst absent" window is now a single rename syscall rather than the
    full duration of a potentially large copy.
    """
    try:
        src.replace(dst)
        return
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise

    # Stage on dst's own volume so the final activation is an intra-volume
    # (atomic) rename.
    dst.parent.mkdir(parents=True, exist_ok=True)
    staging = dst.parent / f".staging_{dst.name}_{os.getpid()}"
    if staging.exists():
        shutil.rmtree(staging)
    try:
        shutil.copytree(src, staging)
        staging.replace(dst)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    # src removal is best-effort: dst is already safely in place.
    shutil.rmtree(src, ignore_errors=True)


def publish_directory(
    temp_dir: str | Path,
    active_dir: str | Path,
    previous_dir: str | Path,
) -> None:
    """Atomically promote *temp_dir* to *active_dir*, archiving the current
    active tree as *previous_dir*.

    Sequence
    --------
    1. Remove *previous_dir* if it exists (stale snapshot).
    2. Rename *active_dir* -> *previous_dir* (archive current state).
    3. Rename *temp_dir* -> *active_dir* (activate new state).

    If step 3 fails and step 2 already succeeded, the original active tree
    is restored from *previous_dir* so the directory is never left absent.

    All renames go through ``_replace_tree`` which handles EXDEV by staging
    the copy on the destination volume before the final rename.
    """
    temp_path = Path(temp_dir)
    active_path = Path(active_dir)
    previous_path = Path(previous_dir)
    active_path.parent.mkdir(parents=True, exist_ok=True)
    previous_path.parent.mkdir(parents=True, exist_ok=True)
    if previous_path.exists():
        shutil.rmtree(previous_path)
    moved_active = False
    try:
        if active_path.exists():
            _replace_tree(active_path, previous_path)
            moved_active = True
        _replace_tree(temp_path, active_path)
    except Exception:
        # Roll back: restore active from previous so callers never see an
        # absent active_dir.
        if moved_active and not active_path.exists() and previous_path.exists():
            _replace_tree(previous_path, active_path)
        raise
