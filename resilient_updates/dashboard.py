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


def _provenance_status(payload: Any) -> str:
    if isinstance(payload, dict):
        return str(payload.get("activation_status") or payload.get("status") or "?")
    return "?"


def render_index(artifacts_dir: Path) -> str:
    """Server-side HTML index of runs (plain stdlib rendering, no template engine)."""
    import html

    runs = list_runs(artifacts_dir)
    if runs:
        items = "".join(
            "<li><a href='/runs/{id}'>{id}</a> — tools: {tools}; reports: {rc}; manifest: {mp}</li>".format(
                id=html.escape(r["id"]),
                tools=html.escape(", ".join(r["provenance_tools"]) or "—"),
                rc=r["report_count"],
                mp=r["manifest_present"],
            )
            for r in runs
        )
    else:
        items = "<li>No runs yet.</li>"
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>el-sca-ansamble dashboard</title></head><body>"
        "<h1>Runs</h1><ul>" + items + "</ul>"
        "<p><a href='/api/runs'>runs JSON</a> · <a href='/api/freshness'>freshness JSON</a></p>"
        "</body></html>"
    )


def render_run(artifacts_dir: Path, run_id: str) -> str | None:
    """Server-side HTML for one run, or ``None`` when the run is unknown."""
    import html

    detail = run_detail(artifacts_dir, run_id)
    if detail is None:
        return None
    prov = (
        "".join(
            f"<li>{html.escape(k)}: {html.escape(_provenance_status(v))}</li>"
            for k, v in detail["provenance"].items()
        )
        or "<li>none</li>"
    )
    reports = "".join(f"<li>{html.escape(p)}</li>" for p in detail["reports"]) or "<li>none</li>"
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>run {html.escape(run_id)}</title></head><body>"
        f"<p><a href='/'>&larr; runs</a></p><h1>Run {html.escape(run_id)}</h1>"
        "<h2>Provenance</h2><ul>" + prov + "</ul>"
        "<h2>Reports</h2><ul>" + reports + "</ul>"
        f"<p><a href='/api/runs/{html.escape(run_id)}'>this run as JSON</a></p>"
        "</body></html>"
    )


def create_app(artifacts_dir: Path | str):
    """Build the read-only FastAPI app bound to ``artifacts_dir``."""
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse

    root = Path(artifacts_dir)
    app = FastAPI(title="el-sca-ansamble dashboard", version="0.1.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return render_index(root)

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_page(run_id: str) -> str:
        page = render_run(root, run_id)
        if page is None:
            raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
        return page

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
