from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass

try:
    from datetime import UTC  # py3.11+
except ImportError:
    from datetime import timezone as _tz

    UTC = _tz.utc  # noqa: UP017
from datetime import datetime
from pathlib import Path
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
    normalized.setdefault("timestamp_utc", datetime.now(UTC).isoformat())
    resolved.write_text(json.dumps(normalized, indent=2, sort_keys=True), encoding="utf-8")
