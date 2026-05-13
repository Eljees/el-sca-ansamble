from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
from typing import Any


def _normalize(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize(item) for key, item in value.items()}
    return value


def write_provenance(path: str | Path, payload: dict[str, Any]) -> None:
    resolved = Path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    normalized = _normalize(payload)
    normalized.setdefault("timestamp_utc", datetime.now(timezone.utc).isoformat())
    resolved.write_text(json.dumps(normalized, indent=2, sort_keys=True), encoding="utf-8")
