"""Contract: cve-bin-tool mini-barrels honour the audit's file-based
source_status (OSV/EPSS/PURL2CPE/RSD ship as files, never cve_range rows)."""

from __future__ import annotations

import json
from pathlib import Path

from resilient_updates.dashboard import tool_status


def _write_prov(tmp_path: Path, payload: dict) -> Path:
    prov = tmp_path / "provenance"
    prov.mkdir(parents=True, exist_ok=True)
    (prov / "cve-bin-tool-db.json").write_text(json.dumps(payload), encoding="utf-8")
    return tmp_path


def _sources(result: dict) -> dict[str, dict]:
    cbt = next(t for t in result["tools"] if t["name"] == "cve-bin-tool")
    return {s["name"]: s for s in cbt["sources"]}


def test_file_based_sources_fill_from_audit_source_status(tmp_path: Path) -> None:
    artifacts = _write_prov(
        tmp_path,
        {
            "activation_status": "degraded",
            "selected_audit": {
                "counts": {"cve_range_by_source": {"NVD": 1000, "Curl": 5}},
                "source_status": {
                    "OSV": {"status": "ok", "count": 388224},
                    "EPSS": {"status": "ok", "count": 1},
                    "PURL2CPE": {"status": "ok", "count": 1},
                    "RSD": {"status": "ok", "count": 372416},
                    "GAD": {"status": "failed", "count": 0},
                },
            },
        },
    )
    src = _sources(tool_status(artifacts))
    assert src["OSV"]["fill"] == 100 and src["OSV"]["count"] == 388224
    assert src["EPSS"]["fill"] == 100
    assert src["PURL2CPE"]["fill"] == 100
    assert src["RSD"]["fill"] == 100
    # row-based sources still work from cve_range_by_source
    assert src["NVD"]["fill"] == 100 and src["NVD"]["count"] == 1000
    assert src["CURL"]["fill"] == 100
    # failed audit + no rows -> empty barrel
    assert src["GAD"]["fill"] == 0


def test_rows_win_over_missing_audit(tmp_path: Path) -> None:
    artifacts = _write_prov(
        tmp_path,
        {
            "activation_status": "active",
            "selected_audit": {"counts": {"cve_range_by_source": {"OSV": 77}}},
        },
    )
    src = _sources(tool_status(artifacts))
    assert src["OSV"]["fill"] == 100 and src["OSV"]["count"] == 77
    assert src["EPSS"]["fill"] == 0
