"""Extended tests for resilient_updates.provenance.

test_provenance.py has one test: write + read back.  This file covers
_normalize (dataclasses, nested dicts/lists) and the auto-mkdir behaviour.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from resilient_updates.provenance import write_provenance


@dataclass
class _SampleDC:
    name: str
    value: int


def test_write_provenance_creates_parent_dirs(tmp_path: Path):
    target = tmp_path / "deep" / "nested" / "prov.json"
    write_provenance(target, {"tool": "grype"})
    assert target.exists()


def test_write_provenance_normalizes_dataclass(tmp_path: Path):
    target = tmp_path / "prov.json"
    payload = {"tool": "grype", "source": _SampleDC(name="primary", value=10)}
    write_provenance(target, payload)
    data = json.loads(target.read_text(encoding="utf-8"))
    # dataclass should be serialised as a plain dict
    assert data["source"] == {"name": "primary", "value": 10}


def test_write_provenance_normalizes_nested_list_of_dataclasses(tmp_path: Path):
    target = tmp_path / "prov.json"
    payload = {
        "sources": [_SampleDC("a", 1), _SampleDC("b", 2)],
    }
    write_provenance(target, payload)
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["sources"] == [{"name": "a", "value": 1}, {"name": "b", "value": 2}]


def test_write_provenance_adds_timestamp_utc(tmp_path: Path):
    target = tmp_path / "prov.json"
    write_provenance(target, {"tool": "trivy"})
    data = json.loads(target.read_text(encoding="utf-8"))
    assert "timestamp_utc" in data
    assert data["timestamp_utc"].endswith("+00:00") or "T" in data["timestamp_utc"]


def test_write_provenance_does_not_overwrite_existing_timestamp(tmp_path: Path):
    target = tmp_path / "prov.json"
    write_provenance(target, {"tool": "trivy", "timestamp_utc": "2000-01-01T00:00:00+00:00"})
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["timestamp_utc"] == "2000-01-01T00:00:00+00:00"


def test_write_provenance_output_is_sorted_keys(tmp_path: Path):
    target = tmp_path / "prov.json"
    write_provenance(target, {"z_key": 1, "a_key": 2})
    raw = target.read_text(encoding="utf-8")
    pos_a = raw.index("a_key")
    pos_z = raw.index("z_key")
    assert pos_a < pos_z, "keys should be sorted"
