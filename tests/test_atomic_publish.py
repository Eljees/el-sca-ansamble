import contextlib
import errno
from pathlib import Path

import pytest

from resilient_updates.atomic_publish import _replace_tree, publish_directory


def test_atomic_publish_preserves_previous(tmp_path: Path):
    active = tmp_path / "active"
    previous = tmp_path / "previous"
    temp = tmp_path / "temp"
    active.mkdir()
    temp.mkdir()
    (active / "old.txt").write_text("old", encoding="utf-8")
    (temp / "new.txt").write_text("new", encoding="utf-8")

    publish_directory(temp, active, previous)

    assert (active / "new.txt").read_text(encoding="utf-8") == "new"
    assert (previous / "old.txt").read_text(encoding="utf-8") == "old"


def test_atomic_publish_rolls_back_when_activation_fails(tmp_path: Path, monkeypatch):
    active = tmp_path / "active"
    previous = tmp_path / "previous"
    temp = tmp_path / "temp"
    active.mkdir()
    temp.mkdir()
    (active / "old.txt").write_text("old", encoding="utf-8")
    (temp / "new.txt").write_text("new", encoding="utf-8")
    original_replace = Path.replace
    calls = {"count": 0}

    def flaky_replace(self, target):
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError("activation failed")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", flaky_replace)

    with contextlib.suppress(Exception):
        publish_directory(temp, active, previous)

    assert (active / "old.txt").read_text(encoding="utf-8") == "old"


def test_atomic_publish_handles_cross_device_replace(tmp_path: Path, monkeypatch):
    active = tmp_path / "active"
    previous = tmp_path / "previous"
    temp = tmp_path / "temp"
    active.mkdir()
    temp.mkdir()
    (active / "old.txt").write_text("old", encoding="utf-8")
    (temp / "new.txt").write_text("new", encoding="utf-8")

    def exdev_replace(self, target):
        raise OSError(errno.EXDEV, "Invalid cross-device link")

    monkeypatch.setattr(Path, "replace", exdev_replace)
    publish_directory(temp, active, previous)

    assert (active / "new.txt").read_text(encoding="utf-8") == "new"
    assert (previous / "old.txt").read_text(encoding="utf-8") == "old"


def test_replace_tree_exdev_cleans_staging_on_copy_failure(tmp_path: Path, monkeypatch):
    """If the copy into staging fails, staging dir is removed and dst is untouched."""
    src = tmp_path / "src"
    dst = tmp_path / "dst_absent"
    src.mkdir()
    (src / "data.txt").write_text("payload", encoding="utf-8")

    original_replace = Path.replace
    original_copytree = __import__("shutil").copytree

    def exdev_replace(self, target):
        raise OSError(errno.EXDEV, "cross-device")

    def failing_copytree(s, d, **kwargs):
        # Simulate a partial write then failure.
        Path(d).mkdir(parents=True, exist_ok=True)
        (Path(d) / "partial.txt").write_text("partial")
        raise OSError("disk full")

    monkeypatch.setattr(Path, "replace", exdev_replace)
    monkeypatch.setattr("shutil.copytree", failing_copytree)

    with pytest.raises(OSError, match="disk full"):
        _replace_tree(src, dst)

    # dst must not exist — copy never completed.
    assert not dst.exists()
    # No orphaned staging dirs should remain in dst.parent.
    staging_leftovers = list(tmp_path.glob(".staging_*"))
    assert staging_leftovers == [], f"orphaned staging dirs: {staging_leftovers}"

    monkeypatch.setattr(Path, "replace", original_replace)
    monkeypatch.setattr("shutil.copytree", original_copytree)


@pytest.mark.smoke
def test_atomic_publish_no_active_dir(tmp_path: Path):
    """publish_directory works when active_dir doesn't exist yet (first run)."""
    previous = tmp_path / "previous"
    temp = tmp_path / "temp"
    active = tmp_path / "active"
    temp.mkdir()
    (temp / "data.txt").write_text("first", encoding="utf-8")

    publish_directory(temp, active, previous)

    assert (active / "data.txt").read_text(encoding="utf-8") == "first"
    assert not previous.exists()
