import errno
from pathlib import Path

from resilient_updates.atomic_publish import publish_directory


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

    try:
        publish_directory(temp, active, previous)
    except Exception:
        pass

    assert (active / "old.txt").read_text(encoding="utf-8") == "old"


def test_atomic_publish_handles_cross_device_replace(tmp_path: Path, monkeypatch):
    active = tmp_path / "active"
    previous = tmp_path / "previous"
    temp = tmp_path / "temp"
    active.mkdir()
    temp.mkdir()
    (active / "old.txt").write_text("old", encoding="utf-8")
    (temp / "new.txt").write_text("new", encoding="utf-8")

    original_replace = Path.replace

    def exdev_replace(self, target):
        raise OSError(errno.EXDEV, "Invalid cross-device link")

    monkeypatch.setattr(Path, "replace", exdev_replace)
    publish_directory(temp, active, previous)

    assert (active / "new.txt").read_text(encoding="utf-8") == "new"
    assert (previous / "old.txt").read_text(encoding="utf-8") == "old"
    monkeypatch.setattr(Path, "replace", original_replace)
