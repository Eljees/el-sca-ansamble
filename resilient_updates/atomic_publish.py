from __future__ import annotations

from pathlib import Path
import shutil


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
            active_path.replace(previous_path)
            moved_active = True
        temp_path.replace(active_path)
    except Exception:
        if moved_active and not active_path.exists() and previous_path.exists():
            previous_path.replace(active_path)
        raise
