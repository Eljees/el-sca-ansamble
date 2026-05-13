from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

from .config import parse_duration_hours


def ensure_directory(path: str | Path) -> Path:
    resolved = Path(path)
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def file_sha256(path: str | Path) -> str:
    digest = sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


@dataclass
class LastKnownGood:
    path: Path
    max_age_hours: int

    def is_usable(self) -> bool:
        if not self.path.exists():
            return False
        if self.path.is_dir() and not any(self.path.iterdir()):
            return False
        modified = datetime.fromtimestamp(self.path.stat().st_mtime, tz=timezone.utc)
        return datetime.now(timezone.utc) - modified <= timedelta(hours=self.max_age_hours)


def build_last_known_good(path: str | Path, max_age: str) -> LastKnownGood:
    return LastKnownGood(Path(path), parse_duration_hours(max_age))
