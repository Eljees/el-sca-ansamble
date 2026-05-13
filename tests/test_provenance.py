import json
from pathlib import Path

from resilient_updates.provenance import write_provenance


def test_provenance_contains_attempted_sources(tmp_path: Path):
    target = tmp_path / "prov.json"
    payload = {
        "tool": "grype",
        "artifact_type": "grype-db",
        "attempted_sources": [{"name": "primary"}, {"name": "secondary"}],
    }
    write_provenance(target, payload)
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["attempted_sources"][0]["name"] == "primary"
    assert "timestamp_utc" in data
