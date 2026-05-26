from __future__ import annotations

import errno
from pathlib import Path
import shutil


def _replace_tree(src: Path, dst: Path) -> None:
    """Move directory tree src -> dst, with EXDEV-safe copy fallback."""
    try:
        src.replace(dst)
        return
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    shutil.rmtree(src)


def publish_directory(temp_dir: str | Path, active_dir: str | Path, previous_dir: str | Path) -> None:
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
        if moved_active and not active_path.exists() and previous_path.exists():
            _replace_tree(previous_path, active_path)
        raise
