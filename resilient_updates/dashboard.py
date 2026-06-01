"""Read-only FastAPI dashboard over ``artifacts/`` (ADR-0006, Phase 1).

P1 ships a JSON API only — no UI, no compose service.  The app **reads**
already-written artifacts (provenance, MANIFEST, reports) and never scans or
mutates anything, mirroring ``scripts/report_html.py``.

FastAPI is imported lazily inside :func:`create_app`, so importing this module
(and unit-testing the pure helpers below) does not require fastapi to be
installed; only launching the app does.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _safe_read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _provenance(artifacts_dir: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    pdir = artifacts_dir / "provenance"
    if pdir.is_dir():
        for p in sorted(pdir.glob("*.json")):
            data = _safe_read_json(p)
            if data is not None:
                out[p.stem] = data
    return out


def _reports(artifacts_dir: Path) -> list[str]:
    rdir = artifacts_dir / "reports"
    if not rdir.is_dir():
        return []
    return sorted(
        str(p.relative_to(artifacts_dir)).replace("\\", "/")
        for p in rdir.rglob("*")
        if p.is_file()
    )


def list_runs(artifacts_dir: Path) -> list[dict[str, Any]]:
    """Return the available runs.

    The on-disk layout holds a single current run (``artifacts/provenance``,
    ``MANIFEST.json``, ``reports/``); P1 surfaces it as one logical run with
    ``id="current"``.  Empty list when nothing has been produced yet.
    """
    prov = _provenance(artifacts_dir)
    manifest = _safe_read_json(artifacts_dir / "MANIFEST.json")
    reports = _reports(artifacts_dir)
    if not prov and manifest is None and not reports:
        return []
    return [
        {
            "id": "current",
            "manifest_present": manifest is not None,
            "provenance_tools": sorted(prov.keys()),
            "report_count": len(reports),
        }
    ]


def run_detail(artifacts_dir: Path, run_id: str) -> dict[str, Any] | None:
    """Full detail for a run, or ``None`` if unknown/absent."""
    if run_id != "current" or not list_runs(artifacts_dir):
        return None
    return {
        "id": "current",
        "manifest": _safe_read_json(artifacts_dir / "MANIFEST.json"),
        "provenance": _provenance(artifacts_dir),
        "reports": _reports(artifacts_dir),
    }


def create_app(artifacts_dir: Path | str):
    """Build the read-only FastAPI app bound to ``artifacts_dir``."""
    from fastapi import FastAPI, HTTPException

    root = Path(artifacts_dir)
    app = FastAPI(title="el-sca-ansamble dashboard", version="0.1.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/runs")
    def runs() -> dict[str, Any]:
        return {"runs": list_runs(root)}

    @app.get("/api/runs/{run_id}")
    def run_detail_endpoint(run_id: str) -> dict[str, Any]:
        detail = run_detail(root, run_id)
        if detail is None:
            raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
        return detail

    @app.get("/api/freshness")
    def freshness() -> dict[str, Any]:
        from .enrichment import evaluate_enrichment_policy

        return evaluate_enrichment_policy(None)

    return app
