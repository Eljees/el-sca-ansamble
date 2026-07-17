"""FastAPI dashboard over ``artifacts/`` (ADR-0006).

The app has a read-only run browser and a host-active GUI.  Host-active mode
starts scan/update jobs through :mod:`resilient_updates.orchestrator`; compose
dashboard mode disables those POST endpoints and only browses saved artefacts.

FastAPI is imported lazily inside :func:`create_app`, so importing this module
(and unit-testing the pure helpers below) does not require fastapi to be
installed; only launching the app does.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

# fastapi stays an optional runtime dependency (pure helpers + their tests run
# without it).  But ``from __future__ import annotations`` turns the route
# signatures into strings that FastAPI resolves against THIS module's globals —
# so ``UploadFile`` must be importable at module scope, not only inside
# create_app().  Guard the import so the module still loads when fastapi is absent.
try:  # pragma: no cover - exercised indirectly via create_app
    from fastapi import File, UploadFile
except ImportError:  # pragma: no cover
    File = None  # type: ignore[assignment]
    UploadFile = None  # type: ignore[assignment]

from .artifact_catalog import ArtifactCatalog, is_valid_case_id


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
        str(p.relative_to(artifacts_dir)).replace("\\", "/") for p in rdir.rglob("*") if p.is_file()
    )


def list_runs(artifacts_dir: Path) -> list[dict[str, Any]]:
    """Return the available runs.

    The live layout exposes ``id="current"``.  Saved runs live under
    ``_SCA_reports/<run-name>/`` by default, with legacy snapshots still
    discoverable under ``artifacts/runs/<run-name>/``.
    """
    out: list[dict[str, Any]] = []
    hidden_runs = ArtifactCatalog(artifacts_dir).deleted_run_ids()
    prov = _provenance(artifacts_dir)
    manifest = _safe_read_json(artifacts_dir / "MANIFEST.json")
    reports = _reports(artifacts_dir)
    if prov or manifest is not None or reports:
        out.append(
            {
                "id": "current",
                "path": str(artifacts_dir),
                "manifest_present": manifest is not None,
                "provenance_tools": sorted(prov.keys()),
                "report_count": len(reports),
                "markdown_report_path": _markdown_report(artifacts_dir),
            }
        )

    for run_dir in _saved_run_dirs(artifacts_dir):
        if run_dir.name in hidden_runs:
            continue
        run_prov = _provenance(run_dir)
        run_manifest = _safe_read_json(run_dir / "MANIFEST.json")
        run_reports = _reports(run_dir)
        out.append(
            {
                "id": run_dir.name,
                "path": str(run_dir),
                "manifest_present": run_manifest is not None,
                "provenance_tools": sorted(run_prov.keys()),
                "report_count": len(run_reports),
                "markdown_report_path": _markdown_report(run_dir),
            }
        )
    return out


# Run ids end in a "<name>-YYYYMMDD-HHMMSS" stamp; pull it out so runs sort by
# actual time (newest first) instead of alphabetically by name — otherwise
# different name prefixes (CYBERSEC-… / PIX_… / avandoc-…) interleave by letter.
_RUN_TS_RE = re.compile(r"(?P<date>\d{8})-(?P<time>\d{6})\b")


def _run_timestamp(run_id: str) -> str:
    """Sortable ``YYYYMMDDHHMMSS`` extracted from a run id, or ``""`` if absent."""
    m = _RUN_TS_RE.search(run_id)
    return (m.group("date") + m.group("time")) if m else ""


def _run_date(run_id: str) -> str:
    """``YYYY-MM-DD`` extracted from a run id, or ``""`` when it has no stamp."""
    ts = _run_timestamp(run_id)
    return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}" if ts else ""


def _saved_run_dirs(artifacts_dir: Path) -> list[Path]:
    roots = (artifacts_dir.parent / "_SCA_reports", artifacts_dir / "runs")
    candidates: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for run_dir in root.iterdir():
            if not run_dir.is_dir():
                continue
            key = run_dir.resolve()
            if key in seen:
                continue
            seen.add(key)
            candidates.append(run_dir)
    # Newest first by parsed timestamp; runs without a stamp fall to the bottom
    # (still deterministic via the name tie-breaker).
    return sorted(
        candidates,
        key=lambda p: (_run_timestamp(p.name) != "", _run_timestamp(p.name), p.name),
        reverse=True,
    )


def _resolve_run_dir(artifacts_dir: Path, run_id: str) -> Path | None:
    if run_id == "current":
        return artifacts_dir
    for run_dir in _saved_run_dirs(artifacts_dir):
        if run_dir.name == run_id:
            return run_dir
    return None


def run_detail(artifacts_dir: Path, run_id: str) -> dict[str, Any] | None:
    """Full detail for a run, or ``None`` if unknown/absent."""
    root = _resolve_run_dir(artifacts_dir, run_id)
    if (
        root is None
        or not root.is_dir()
        or not any(item["id"] == run_id for item in list_runs(artifacts_dir))
    ):
        return None
    return {
        "id": run_id,
        "path": str(root),
        "manifest": _safe_read_json(root / "MANIFEST.json"),
        "checkpoint": _safe_read_json(root / "checkpoint.json"),
        "provenance": _provenance(root),
        "reports": _reports(root),
        "markdown_report_path": _markdown_report(root),
    }


def _report_candidates(run_dir: Path) -> list[str]:
    reports_root = run_dir / "reports" / "final"
    if not reports_root.is_dir():
        return []
    preferred: list[Path] = []
    for pattern in ("index.html", "*.html", "*.md"):
        preferred.extend(sorted(reports_root.rglob(pattern)))
    seen: set[Path] = set()
    out: list[str] = []
    for path in preferred:
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        out.append(str(path.relative_to(run_dir)).replace("\\", "/"))
    return out


def _markdown_report(run_dir: Path) -> str:
    """Run-relative path of the final Markdown report, or ``""`` when absent.

    This is the artefact operators hand over ("вот отчёт"), so it gets a
    first-class link/endpoint instead of being buried in ``report_paths``.
    """
    reports_root = run_dir / "reports" / "final"
    if not reports_root.is_dir():
        return ""
    for path in sorted(reports_root.rglob("*.md")):
        if path.is_file():
            return str(path.relative_to(run_dir)).replace("\\", "/")
    return ""


def _provenance_status(payload: Any) -> str:
    if isinstance(payload, dict):
        return str(payload.get("activation_status") or payload.get("status") or "?")
    return "?"


def render_index(artifacts_dir: Path) -> str:
    """Server-side HTML index of runs, grouped by date (newest first).

    Runs are sorted by their ``YYYYMMDD-HHMMSS`` stamp; each date gets its own
    header so a long history stays scannable and reports are easy to find.
    """
    import html
    from itertools import groupby
    from urllib.parse import quote

    runs = list_runs(artifacts_dir)

    def _group_label(r: dict[str, Any]) -> str:
        if r["id"] == "current":
            return "⏵ активный прогон (current)"
        return _run_date(r["id"]) or "без даты"

    def _row(r: dict[str, Any]) -> str:
        md = (
            f" · <a href='/api/runs/{quote(r['id'], safe='')}/report.md'>report.md</a>"
            if r.get("markdown_report_path")
            else ""
        )
        return (
            "<li><a href='/runs/{id}'>{id}</a> — tools: {tools}; reports: {rc}; manifest: {mp}{md}</li>"
        ).format(
            id=html.escape(r["id"]),
            tools=html.escape(", ".join(r["provenance_tools"]) or "—"),
            rc=r["report_count"],
            mp=r["manifest_present"],
            md=md,
        )

    if runs:
        sections = []
        for label, group in groupby(runs, key=_group_label):
            rows = list(group)
            sections.append(
                "<section class='run-group'><h2>{lbl} <span class='count'>({n})</span></h2>"
                "<ul>{items}</ul></section>".format(
                    lbl=html.escape(label),
                    n=len(rows),
                    items="".join(_row(r) for r in rows),
                )
            )
        body = "".join(sections)
    else:
        body = "<p>No runs yet.</p>"

    style = (
        "<style>body{font:14px system-ui,Segoe UI,sans-serif;margin:24px;max-width:960px;"
        "color:#1a2027}h1{font-size:20px}h2{font-size:13px;text-transform:uppercase;"
        "letter-spacing:.04em;margin:22px 0 6px;padding-bottom:4px;border-bottom:1px solid #cbd2d9;"
        "color:#3b4b57}.count{color:#8b98a5;font-weight:400}ul{margin:0 0 4px;padding-left:20px}"
        "li{margin:3px 0}a{color:#2563eb;text-decoration:none}a:hover{text-decoration:underline}</style>"
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>el-sca-ansamble dashboard</title>" + style + "</head><body>"
        "<h1>Runs</h1>" + body + "<p><a href='/api/runs'>runs JSON</a> · "
        "<a href='/api/freshness'>freshness JSON</a></p>"
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


# ── Tool DB status (last update + versions) ─────────────────────────────────

# Compose image-tag defaults (mirror docker-compose.yml ${VAR:-default}).
COMPOSE_VERSION_DEFAULTS = {
    "TRIVY_VERSION": "0.64.1",
    "GRYPE_VERSION": "v0.112.0",
    "SYFT_VERSION": "v1.20.0",
}


def _deep_find(obj: Any, key: str) -> Any | None:
    """Depth-first search for the first value under ``key`` anywhere in ``obj``."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            found = _deep_find(v, key)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _deep_find(v, key)
            if found is not None:
                return found
    return None


def _read_env_versions(repo_root: Path) -> dict[str, str]:
    """Read ``*_VERSION`` keys from .env (falling back to .env.example, then
    the compose defaults) so tool cards show the version that will actually run.
    """
    versions = dict(COMPOSE_VERSION_DEFAULTS)
    env_path = repo_root / ".env"
    if env_path.is_file():
        for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip()
            if k.endswith("_VERSION") and v:
                versions[k] = v

    example_path = repo_root / ".env.example"
    if example_path.is_file():
        for raw in example_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip()
            if k.endswith("_VERSION") and v:
                versions.setdefault(k, v)
    return versions


def tool_status(artifacts_dir: Path | str, repo_root: Path | str | None = None) -> dict[str, Any]:
    """Per-tool DB freshness + version, for the GUI resource cards.

    Returns ``{"db_update_enabled_by_default": False, "tools": [...]}`` where
    each tool carries its engine version, DB activation status, and the last
    DB update timestamp (best-effort, parsed from ``artifacts/provenance``).
    """
    root = Path(artifacts_dir)
    rroot = Path(repo_root) if repo_root is not None else root.resolve().parent
    versions = _read_env_versions(rroot)
    prov = _provenance(root)

    def _status(name: str) -> str | None:
        payload = prov.get(name)
        if isinstance(payload, dict):
            return str(payload.get("activation_status") or payload.get("status") or "?")
        return None

    def _updated(*names: str) -> str | None:
        for name in names:
            payload = prov.get(name)
            if not isinstance(payload, dict):
                continue
            ts = _deep_find(payload, "timestamp_utc") or _deep_find(payload, "mtime_utc")
            if ts:
                return str(ts)
        return None

    grype_payload = prov.get("grype") or {}
    cbt_db = prov.get("cve-bin-tool-db") or {}
    cbt_counts = _deep_find(cbt_db, "cve_range_total")
    grype_checksum = _deep_find(grype_payload, "checksum")

    # "fill" 0-100 drives the radioactive-barrel level in the GUI.
    _full = {"active", "fresh", "cached-present", "ok", "healthcheck-only"}

    def _fill(status: str | None) -> int:
        if status in _full:
            return 100
        if status == "degraded":
            # Activated but with optional sources missing (e.g. cve-bin-tool on
            # NVD-only via the feed import) — usable DB, show mostly full.
            return 80
        if status in ("lkg", "last-known-good"):
            return 55
        if status in (None, "", "n/a", "failed", "missing", "?"):
            return 0
        return 35

    # cve-bin-tool per-source fill (from the provenance CVE counts by source).
    cbt_by_source = _deep_find(cbt_db, "cve_range_by_source")
    if not isinstance(cbt_by_source, dict):
        cbt_by_source = {}
    # cve-bin-tool stores its own SOURCE spelling in cve.db (curl_source.py uses
    # "Curl", not "CURL"), so match case-insensitively — otherwise the Curl
    # barrel reads 0% even when the source imported rows.
    cbt_by_source = {str(k).upper(): v for k, v in cbt_by_source.items()}
    cbt_source_names = ["NVD", "OSV", "GAD", "REDHAT", "CURL", "EPSS", "PURL2CPE", "RSD"]
    # Sources known not to load in this contour (e.g. GAD/REDHAT behind a 403)
    # are marked unavailable → the GUI shows them with a red ✕ ("not working
    # yet") instead of an empty barrel.  Driven by CVE_BIN_TOOL_ENRICH_DISABLE.
    cbt_unavailable = {
        s.strip().upper()
        for s in (os.environ.get("CVE_BIN_TOOL_ENRICH_DISABLE") or "").replace(",", " ").split()
        if s.strip()
    }
    # File-based sources (OSV/EPSS/PURL2CPE/RSD) never write cve_range rows -
    # their presence lives in the audit's source_status (counted by files in
    # db_root). Prefer that; fall back to the row counts for NVD/GAD/etc.
    cbt_source_status = _deep_find(cbt_db, "source_status")
    if not isinstance(cbt_source_status, dict):
        cbt_source_status = {}
    cbt_source_status = {str(k).upper(): v for k, v in cbt_source_status.items()}
    cbt_sources = []
    for s in cbt_source_names:
        cnt = cbt_by_source.get(s)
        rows_present = isinstance(cnt, (int, float)) and cnt > 0
        audit_entry = cbt_source_status.get(s)
        audit_ok = isinstance(audit_entry, dict) and audit_entry.get("status") == "ok"
        audit_count = audit_entry.get("count") if isinstance(audit_entry, dict) else None
        has = rows_present or audit_ok
        shown = cnt if rows_present else audit_count
        cbt_sources.append(
            {
                "name": s,
                "fill": 100 if has else 0,
                "count": int(shown) if has and isinstance(shown, (int, float)) else 0,
                "unavailable": (s in cbt_unavailable) and not has,
                "update_target": f"cve-bin-tool:{s}",
            }
        )

    grype_status = _status("grype")
    trivy_status = _status("trivy")
    cbt_status = _status("cve-bin-tool-db") or _status("cve-bin-tool-update-status")

    # The three scanners do NOT mean the same thing by "db_updated":
    #   built    — when upstream built the DB (Grype `built`, Trivy `UpdatedAt`)
    #   imported — when *we* ran the import (cve-bin-tool: the NVD JSON feeds
    #              carry no build date, so the wall clock is all we have)
    # Expose which one it is instead of silently mixing them in one column.
    trivy_payload = prov.get("trivy") or {}
    grype_built = _deep_find(grype_payload, "built")
    trivy_built = _deep_find(trivy_payload, "db_updated_at")
    grype_updated = grype_built or _updated("grype")
    trivy_updated = trivy_built or _updated("trivy")
    cbt_updated = _updated("cve-bin-tool-db", "cve-bin-tool-update-status")

    def _kind(built: Any, updated: Any) -> str | None:
        if not updated:
            return None
        return "built" if built else "imported"

    tools = [
        {
            "name": "Syft",
            "role": "SBOM generator",
            "version": versions.get("SYFT_VERSION", "—"),
            "db_status": "n/a",
            "db_updated": None,
            "db_updated_kind": None,
            "detail": "no vulnerability DB (produces SBOM)",
            "fill": None,
            "update_target": None,
        },
        {
            "name": "Grype",
            "role": "SBOM → CVE scanner",
            "version": versions.get("GRYPE_VERSION", "—"),
            "db_status": grype_status,
            "db_updated": grype_updated,
            "db_updated_kind": _kind(grype_built, grype_updated),
            "detail": (f"checksum {str(grype_checksum)[:23]}…" if grype_checksum else "anchore DB"),
            "fill": _fill(grype_status),
            "update_target": "grype",
        },
        {
            "name": "Trivy",
            "role": "filesystem/CVE scanner",
            "version": versions.get("TRIVY_VERSION", "—"),
            "db_status": trivy_status,
            # Prefer the DB's own build time (written by scripts/update_trivy.sh
            # from db/metadata.json -> UpdatedAt), mirroring Grype's "built".
            # Fall back to the update-run wall clock when it is absent.
            "db_updated": trivy_updated,
            "db_updated_kind": _kind(trivy_built, trivy_updated),
            "detail": "aquasec trivy-db",
            "fill": _fill(trivy_status),
            "update_target": "trivy",
        },
        {
            "name": "cve-bin-tool",
            "role": "binary CVE scanner",
            "version": "local build",
            "db_status": cbt_status,
            # The NVD JSON feeds carry no build date -> this is always an import time.
            "db_updated": cbt_updated,
            "db_updated_kind": _kind(None, cbt_updated),
            "detail": (
                f"{int(cbt_counts):,} CVE rows" if isinstance(cbt_counts, (int, float)) else "NVD feed DB"
            ),
            # Main barrel reflects activation HEALTH (active/degraded/failed) —
            # NVD-only is a fully usable degraded DB, not "13% full".  The
            # per-source presence is shown by the mini-barrels below.
            "fill": _fill(cbt_status),
            "update_target": "cve-bin-tool",
            "sources": cbt_sources,
        },
    ]
    return {"db_update_enabled_by_default": False, "tools": tools}


# ── Active GUI (drag-drop scan + live pipeline + DB cards) ───────────────────

_GUI_HTML = """<!doctype html>
<html lang="ru" data-theme="__THEME__" data-edge="__EDGE__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>el-sca-ansamble — анализ артефактов</title>
<style>
  /* ── Rose Phosphor ─────────────────────────────────────────────────────
     Текст остаётся фосфорно-зелёным, хром — розовый.  Красный НЕ занят под
     украшение: он держит смысл (упавший этап, ✕ на недоступном источнике,
     «Удалить навсегда»), поэтому акцент — розовый, а ошибка — алая.

     Фон-эффекты — слои background у body, поэтому физически под контентом.
     Прошлая ревизия рисовала сканлайны и виньетку в fixed-псевдоэлементах
     поверх всего интерфейса: текст рябил, а панель выглядела мрачной.     */
  :root { --bg:#0f0a10; --panel:#1a1019; --surface:#211426; --line:#40203a; --line2:#5a2c50;
          --fg:#c9ffd9; --muted:#a37fa0; --accent:#ff77c8; --ok:#4dffa0; --active:#ffd166;
          --err:#ff5f56; --glow:#ff77c866;
          --mono:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace; }
  * { box-sizing:border-box; }
  /* Фон-эффекты — слои самого body, а не оверлей: диагональный розово-мятный
     градиент и очень слабые сканлайны.  Так они физически не могут оказаться
     поверх текста — в отличие от предыдущего fixed-оверлея поверх интерфейса. */
  body { margin:0; color:var(--fg); font:14px/1.5 var(--mono);
         background-color:var(--bg);
         background-image:linear-gradient(120deg,#ff77c81f,transparent 50%,#4dffa01a 100%),
                          repeating-linear-gradient(0deg,rgba(0,0,0,.16) 0 1px,transparent 1px 4px);
         background-attachment:fixed; }
  h1,h2 { text-shadow:0 0 10px var(--glow); }
  a, button, .stage, .pill, .barrel { transition:color .2s ease, border-color .2s ease,
                                      box-shadow .25s ease, background-color .2s ease; }
  header { padding:16px 24px; border-bottom:1px solid var(--line);
           display:flex; align-items:center; gap:16px; flex-wrap:wrap; }
  h1 { font-size:18px; margin:0; }
  .badge { font-size:12px; padding:3px 10px; border-radius:999px;
           background:#3a2a14; color:#f0c674; border:1px solid #5c4420; }
  main { max-width:1100px; margin:0 auto; padding:24px; }
  .grid { display:grid; gap:20px; }
  /* Панели держат неон сдержаннее карточек — иначе всё светится одинаково
     и обводка перестаёт что-либо выделять. */
  .panel { box-shadow:0 0 20px -12px var(--glow), inset 0 1px 0 #ffffff08;
           background:var(--panel); border:1px solid var(--line);
           border-radius:12px; padding:18px; }
  h2 { font-size:14px; text-transform:uppercase; letter-spacing:.04em;
       color:var(--muted); margin:0 0 14px; }
  #drop { border:2px dashed var(--line); border-radius:12px; padding:36px;
          text-align:center; color:var(--muted); cursor:pointer; transition:.15s; }
  #drop.hot { border-color:var(--accent); background:#2b1128; color:var(--fg);
              box-shadow:0 0 24px var(--glow) inset; }
  #drop b { color:var(--fg); }
  .pipeline { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .stage { flex:1 1 120px; min-width:110px; padding:10px 12px; border-radius:10px;
           border:1px solid var(--line); background:var(--surface); position:relative; }
  .stage .lbl { font-weight:600; }
  .stage .st { font-size:12px; color:var(--muted); margin-top:2px; }
  .stage.pending { opacity:.55; }
  .stage.active { border-color:var(--active); box-shadow:0 0 0 1px var(--active) inset;
                  animation:pulse-border 1.8s ease-in-out infinite; }
  @keyframes pulse-border {
    0%,100% { box-shadow:0 0 0 1px var(--active) inset,0 0 6px #ffd16644; }
    50%      { box-shadow:0 0 0 1px var(--active) inset,0 0 18px #ffd16699; }
  }
  .stage.active .st { color:var(--active); }
  .stage .timer { font-size:11px; color:var(--muted); margin-top:3px; min-height:14px; }
  .stage.active .timer { color:var(--active); }
  .stage.done { border-color:var(--ok); }
  .stage.done .st { color:var(--ok); }
  .stage.error { border-color:var(--err); }
  .stage.error .st { color:var(--err); }
  pre#log { background:#140d15; border:1px solid var(--line); border-radius:10px;
            padding:12px; height:300px; overflow:auto; margin:0; white-space:pre-wrap;
            font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace; color:#c8d3de; }
  .tools { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:12px; }
  .tool { border:1px solid var(--line); border-radius:10px; padding:12px; background:var(--surface); }
  .tool .tn { font-weight:600; display:flex; justify-content:space-between; gap:8px; }
  .tool .role { color:var(--muted); font-size:12px; }
  .tool dl { margin:10px 0 0; display:grid; grid-template-columns:auto 1fr; gap:2px 10px; }
  .tool dt { color:var(--muted); font-size:12px; }
  .tool dd { margin:0; font-size:12px; word-break:break-word; }
  .pill { font-size:11px; padding:1px 7px; border-radius:999px; border:1px solid var(--line); }
  .pill.fresh,.pill.active,.pill.ok { color:var(--ok); border-color:#1c3a24; }
  .pill.healthcheckonly,.pill.failed { color:var(--active); border-color:#3a3214; }
  button { font:inherit; border:1px solid var(--line); background:#231020; color:var(--fg);
           padding:9px 16px; border-radius:9px; cursor:pointer; }
  button:hover { border-color:var(--accent); color:var(--accent);
                 box-shadow:0 0 14px var(--glow); transform:translateY(-1px); }
  button:disabled { opacity:.5; cursor:not-allowed; box-shadow:none; }
  /* Необратимое действие подсвечено красным — единственный не-зелёный акцент. */
  button.danger { border-color:#5c1a18; background:#1e0806; color:#ff8a80; }
  button.danger:hover:not(:disabled) { border-color:var(--err); box-shadow:0 0 10px #ff5f5644; }
  .row { display:flex; gap:12px; align-items:center; flex-wrap:wrap; }
  a { color:var(--accent); }
  .muted { color:var(--muted); }
  .tools-select { display:flex; gap:16px; flex-wrap:wrap; align-items:center; margin-top:12px; }
  .tools-select label { display:flex; gap:6px; align-items:center; cursor:pointer; }
  .artifact-list { display:grid; gap:12px; }
  /* Базовая карточка проекта.  Сам НЕОН рисует выбранная обводка (data-edge):
     см. resilient_updates/themes.py — там десять пресетов, цвет края берётся
     из --edge и задаётся статусом, а не пресетом. */
  .artifact-card { position:relative; overflow:hidden; padding:14px; border-radius:10px;
                   background:var(--surface); border:1px solid var(--line);
                   transition:border-color .25s ease, box-shadow .3s ease, transform .2s ease; }
  .artifact-card:hover { transform:translateY(-1px); }
  .artifact-card.deleted:hover { transform:none; }
  .artifact-head { display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; align-items:flex-start; }
  .artifact-name { font-size:15px; font-weight:700; }
  .artifact-meta { font-size:12px; color:var(--muted); word-break:break-word; }
  .artifact-actions { display:flex; gap:8px; flex-wrap:wrap; }
  .artifact-fields { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:10px; margin-top:12px; }
  .artifact-fields label { display:grid; gap:6px; font-size:12px; color:var(--muted); }
  .artifact-fields input { width:100%; padding:8px 10px; border-radius:8px; border:1px solid var(--line);
                           background:#140d15; color:var(--fg); }
  .artifact-fields input:focus { outline:none; border-color:var(--accent); box-shadow:0 0 10px var(--glow); }
  /* ── Превью тем: раскрывается, но выбрать нельзя ─────────────────────── */
  .theme-picker { position:relative; }
  .theme-picker > summary { list-style:none; cursor:pointer; user-select:none;
        font-size:12px; color:var(--muted); padding:5px 12px; border-radius:9px;
        border:1px dashed var(--line2); background:var(--surface); }
  .theme-picker > summary::-webkit-details-marker { display:none; }
  .theme-picker > summary:hover { border-color:var(--accent); color:var(--accent); }
  .theme-picker .soon { font-size:10px; padding:1px 6px; border-radius:999px;
        border:1px solid var(--line2); margin-left:6px; opacity:.8; }
  .theme-panel { position:absolute; top:calc(100% + 8px); left:0; z-index:50; width:min(760px,86vw);
        background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:14px;
        box-shadow:0 12px 40px #000a, 0 0 24px var(--glow); }
  .theme-note { margin:0 0 10px; font-size:12px; color:var(--muted); }
  .theme-grid { list-style:none; margin:0; padding:0; display:grid; gap:10px;
        grid-template-columns:repeat(auto-fill,minmax(170px,1fr)); }
  .theme-card { border:1px solid var(--line); border-radius:10px; padding:10px; background:var(--surface); }
  .theme-chips { display:flex; gap:3px; margin-bottom:8px; }
  .theme-chips i { flex:1; height:16px; border-radius:3px; border:1px solid #0006; }
  .theme-name { font-size:12px; font-weight:700; display:flex; align-items:center; gap:6px; }
  .theme-active { font-size:9px; padding:1px 6px; border-radius:999px;
        border:1px solid var(--accent); color:var(--accent); font-weight:400; }
  .theme-tag { font-size:11px; color:var(--muted); margin:3px 0 8px; min-height:28px; }
  .theme-card button { width:100%; padding:5px 8px; font-size:11px; }
  .theme-panel h3 { font-size:11px; text-transform:uppercase; letter-spacing:.06em;
        color:var(--muted); margin:14px 0 8px; }
  .theme-panel h3:first-of-type { margin-top:4px; }
  .theme-anim { font-size:9px; color:var(--active); border:1px solid var(--line2);
        border-radius:999px; padding:0 5px; margin-left:4px; }
  .theme-card.chosen { border-color:var(--accent); box-shadow:0 0 14px -4px var(--glow); }
  #skin-reset { margin-top:12px; font-size:11px; padding:5px 10px; }
  .artifact-runs { display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }
  .artifact-runs button { padding:5px 10px; font-size:12px; }
  /* analysis map */
  #map { display:flex; align-items:center; gap:18px; flex-wrap:wrap; }
  .map-col { display:flex; flex-direction:column; gap:8px; }
  .map-node { padding:8px 12px; border:1px solid var(--line); border-radius:10px;
              background:var(--surface); min-width:120px; text-align:center; font-size:13px; }
  .map-node .ms { font-size:11px; color:var(--muted); }
  .map-node.active { border-color:var(--active); box-shadow:0 0 0 1px var(--active) inset; }
  .map-node.active .ms { color:var(--active); }
  .map-node.done { border-color:var(--ok); } .map-node.done .ms { color:var(--ok); }
  .map-node.error { border-color:var(--err); } .map-node.error .ms { color:var(--err); }
  .map-node.skip { opacity:.45; }
  .map-arrow { color:var(--muted); font-size:20px; }
  iframe#report-frame { width:100%; height:600px; border:1px solid var(--line);
                        border-radius:10px; background:#fff; }
  /* ☢ radioactive mutagen barrels */
  .barrels { display:flex; gap:22px; flex-wrap:wrap; }
  .barrel-box { width:160px; display:flex; flex-direction:column; align-items:center; gap:6px; }
  .barrel { position:relative; width:96px; height:130px; border-radius:14px/10px;
            border:2px solid #3a4753; background:#0a0e12; overflow:hidden;
            box-shadow:inset 0 0 12px #000; }
  .barrel::before, .barrel::after { content:""; position:absolute; left:0; right:0; height:8px;
            background:linear-gradient(#ffffff22,#00000044); z-index:3; pointer-events:none; }
  .barrel::before { top:30px; } .barrel::after { bottom:30px; }
  .barrel-fill { position:absolute; left:0; right:0; bottom:0; height:0%;
            background:linear-gradient(#b6ff3a,#39ff14 55%,#10b000);
            box-shadow:0 0 18px #7CFC00, 0 -4px 14px #b6ff3a inset;
            transition:height 1s cubic-bezier(.4,0,.2,1); z-index:1; }
  .barrel-fill::after { content:""; position:absolute; top:-6px; left:0; right:0; height:10px;
            background:radial-gradient(circle, #eaffce 0%, #b6ff3a 60%, transparent 70%) repeat-x;
            background-size:18px 12px; opacity:.8; animation:slosh 2.2s linear infinite; }
  @keyframes slosh { from { background-position:0 0; } to { background-position:18px 0; } }
  .bubble { position:absolute; bottom:4px; width:6px; height:6px; border-radius:50%;
            background:#eaffce; opacity:.0; z-index:2; animation:rise linear infinite; }
  @keyframes rise { 0%{ transform:translateY(0); opacity:0; } 15%{ opacity:.9; }
                    100%{ transform:translateY(-120px); opacity:0; } }
  .barrel .rad { position:absolute; inset:0; display:flex; align-items:center; justify-content:center;
            font-size:34px; color:#0a0e12; opacity:.30; z-index:2; pointer-events:none;
            text-shadow:0 0 2px #000; }
  .barrel.lit { border-color:#7CFC00; box-shadow:0 0 16px #39ff1466, inset 0 0 12px #000; }
  /* Base that can't be loaded yet (e.g. GAD/REDHAT 403) → red cross. */
  .barrel.broken { border-color:#ff4d4f; box-shadow:0 0 14px #ff4d4f55, inset 0 0 12px #000; }
  .barrel.broken .rad { color:#ff4d4f; opacity:.85; font-weight:900;
            text-shadow:0 0 8px #ff4d4faa; }
  .barrel.broken .barrel-pct { color:#ff7a7c; text-shadow:none; }
  .barrel-pct { position:absolute; top:6px; left:0; right:0; text-align:center; z-index:4;
            font-weight:700; font-size:13px; color:#0a0e12; text-shadow:0 0 3px #b6ff3a; }
  .barrel-pct.low { color:var(--fg); text-shadow:none; }
  .barrel-box .bt { font-weight:600; }
  .barrel-box .bsub { font-size:11px; color:var(--muted); text-align:center; }
  .barrel-box button { padding:5px 10px; font-size:12px; width:100%; }
  .cbt-sources { display:flex; gap:8px; flex-wrap:wrap; justify-content:center; margin-top:6px; }
  .mini { width:60px; display:flex; flex-direction:column; align-items:center; gap:3px; }
  .mini .barrel { width:42px; height:58px; border-radius:8px/6px; }
  .mini .rad { font-size:16px; }
  .mini .barrel-pct { font-size:9px; top:2px; }
  .mini .bsub { font-size:10px; }
  .mini button { padding:2px 4px; font-size:10px; width:100%; }
  /* proxy toggle */
  .proxy-ctl { display:flex; align-items:center; gap:8px; background:var(--surface);
               border:1px solid var(--line); border-radius:9px; padding:5px 12px; }
  .proxy-ctl span { font-size:12px; color:var(--muted); }
  .proxy-btn { padding:3px 10px; font-size:12px; border-radius:6px; min-width:90px; transition:.15s; }
  .proxy-btn.direct  { border-color:#22c55e; color:#22c55e; }
  .proxy-btn.corp    { border-color:#eab308; color:#eab308; }
  .proxy-btn.via-vpn { border-color:#a855f7; color:#a855f7; }
</style>
<!--SKIN_STYLES--></head>
<body>
<header>
  <h1>el-sca-ansamble</h1>
  <span class="badge" id="upd-badge">обновление баз отключено по умолчанию</span>
  <div class="proxy-ctl" title="Переключить цепочку прокси (configs/feed_sources.runtime.yaml)">
    <span>🌐 Прокси</span>
    <button class="proxy-btn" id="btn-proxy" onclick="cycleProxy()">…</button>
  </div>
  <div class="proxy-ctl" title="Авто-маршрут обновлений: route-doctor зондирует egress изнутри docker-сети и выбирает рабочий путь для каждого инструмента">
    <span>🛰 Маршрут</span>
    <span id="route-info" class="muted" style="font-size:12px">—</span>
    <button class="proxy-btn" id="btn-route" onclick="refreshRoute()" title="Перепроверить сеть">🔄</button>
  </div>
  <!--THEME_PICKER-->
  <span class="muted" style="margin-left:auto" id="conn"></span>
</header>
<main class="grid">
  <section class="panel">
    <h2>Анализ артефакта</h2>
    <div id="drop">
      <p><b>Перетащите сюда артефакт</b> (.tar.gz / .zip / .apk / .exe)<br>
      или нажмите, чтобы выбрать файл — загрузка в каталог начнётся автоматически.</p>
      <input type="file" id="file" hidden>
    </div>
    <div class="tools-select" id="tools-select">
      <span class="muted">Инструменты:</span>
      <label><input type="checkbox" value="syft" checked> Syft (SBOM)</label>
      <label><input type="checkbox" value="grype" checked> Grype</label>
      <label><input type="checkbox" value="trivy" checked> Trivy</label>
      <label><input type="checkbox" value="cve-bin-tool" checked> cve-bin-tool</label>
    </div>
    <div class="row" style="margin-top:12px">
      <span class="muted" id="upload-status">Новый drop/upload появится ниже в каталоге артефактов.</span>
    </div>
    <div class="row" id="resume-row" style="display:none; margin-top:12px">
      <button id="btn-resume">⏯ Продолжить с чекпоинта</button>
      <span class="muted" id="resume-info"></span>
    </div>
  </section>

  <section class="panel">
    <h2>Артефакты</h2>
    <div class="row" style="margin-bottom:12px">
      <span class="muted">Загруженные и исторические артефакты. Здесь можно задать `CYBERSEC-XXXXX`, переименовать, запустить scan, открыть отчёты и скрыть лишнее.</span>
    </div>
    <div id="artifact-list" class="artifact-list">
      <div class="muted">Каталог загружается…</div>
    </div>
  </section>

  <section class="panel">
    <h2>Монитор · контейнеры и прогресс</h2>
    <div id="mon-pipeline" class="muted">загрузка…</div>
    <div id="mon-snapshot" style="margin-top:10px"></div>
    <div id="mon-containers" style="margin-top:10px"></div>
  </section>

  <section class="panel">
    <h2>Процесс анализа</h2>
    <div class="pipeline" id="pipeline"></div>
    <div class="row" style="margin:14px 0 10px">
      <strong id="job-status" class="muted">ожидание</strong>
      <span id="run-info" class="muted"></span>
    </div>
    <pre id="log">Лог появится здесь после запуска…</pre>
  </section>

  <section class="panel" id="map-panel">
    <h2>Карта анализа</h2>
    <div id="map"></div>
  </section>

  <section class="panel" id="report-panel" style="display:none">
    <h2>Отчёт</h2>
    <div class="row" id="report-links" style="margin-bottom:12px"></div>
    <iframe id="report-frame" title="report"></iframe>
  </section>

  <section class="panel">
    <h2>☢ Базы инструментов — бочки с мутагеном</h2>
    <div class="row" style="margin-bottom:14px">
      <button id="btn-update">☢ Обновить ВСЁ</button>
      <button id="btn-refresh">Обновить статус</button>
      <span class="muted">Уровень мутагена = заполненность базы. Скан НЕ обновляет базы — только по кнопке.</span>
    </div>
    <div class="barrels" id="tools"></div>
  </section>

  <section class="panel">
    <h2>Runs · прошлые прогоны</h2>
    <p class="muted">История артефактов и отчётов:
      <a href="/runs">список прогонов</a> ·
      <a href="/runs/current">текущий прогон</a> ·
      <a href="/api/runs">runs JSON</a> ·
      <a href="/api/freshness">freshness JSON</a></p>
  </section>
</main>
<script>
const $ = s => document.querySelector(s);
const logEl = $("#log"), pipeEl = $("#pipeline"), statusEl = $("#job-status"), connEl = $("#conn"), mapEl = $("#map"), runInfoEl = $("#run-info");
let es = null;
let stagesByKey = {};
// key → timestamp (ms) when the stage became active; cleared on done/error
const stageStartMs = {};

function fmtElapsed(ms){
  const s = Math.round(ms / 1000);
  if(s < 60) return s + "s";
  return Math.floor(s/60) + "m " + (s%60) + "s";
}

function renderStages(stages){
  pipeEl.innerHTML = "";
  (stages||[]).forEach(s => {
    const prev = stagesByKey[s.key];
    const st = s.status || "pending";
    // track when stage went active
    if(st === "active" && prev !== "active") stageStartMs[s.key] = Date.now();
    if(st !== "active") delete stageStartMs[s.key];
    const d = document.createElement("div");
    d.id = "stage-" + s.key;
    d.className = "stage " + st;
    const timerTxt = st === "active" ? "▶ выполняется" : "";
    d.innerHTML = `<div class="lbl">${s.label}</div><div class="st">${st}</div><div class="timer">${timerTxt}</div>`;
    pipeEl.appendChild(d);
  });
  stagesByKey = {}; (stages||[]).forEach(s => stagesByKey[s.key] = s.status||"pending");
  renderMap();
}

// Live elapsed-time ticker on active stages
setInterval(() => {
  const now = Date.now();
  Object.entries(stageStartMs).forEach(([key, t]) => {
    const el = document.getElementById("stage-" + key);
    if(el) {
      const timer = el.querySelector(".timer");
      if(timer) timer.textContent = "▶ " + fmtElapsed(now - t);
    }
  });
}, 1000);
function mapNode(key, label){
  const st = stagesByKey[key] || "pending";
  return `<div class="map-node ${st}"><div>${label}</div><div class="ms">${st}</div></div>`;
}
function renderMap(){
  // Артефакт → Extract → веер инструментов → Отчёт.
  // Для Windows-инсталляторов SBOM собирает win-analyzer (стадия "win-analyzer"),
  // а не syft — показываем соответствующий узел, иначе "Syft" висел бы серым
  // pending, хотя SBOM реально построен (CYBERSEC-13388).
  const sbomNode = ("win-analyzer" in stagesByKey)
    ? mapNode("win-analyzer","Win-analyzer")
    : mapNode("sbom","Syft");
  mapEl.innerHTML =
    `<div class="map-col"><div class="map-node">Артефакт</div></div>` +
    `<div class="map-arrow">→</div>` +
    `<div class="map-col">${mapNode("extract","Extract")}</div>` +
    `<div class="map-arrow">→</div>` +
    `<div class="map-col">${sbomNode}${mapNode("grype","Grype")}${mapNode("trivy","Trivy")}${mapNode("cve-bin-tool","cve-bin-tool")}</div>` +
    `<div class="map-arrow">→</div>` +
    `<div class="map-col">${mapNode("report","Отчёт")}</div>`;
}
// Clipboard API needs a secure context; the dashboard is plain http, so keep a
// textarea+execCommand fallback or "Скопировать" silently does nothing.
async function copyToClipboard(text){
  if(window.isSecureContext && navigator.clipboard){
    await navigator.clipboard.writeText(text);
    return true;
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed"; ta.style.left = "-9999px";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch(e) { ok = false; }
  document.body.removeChild(ta);
  return ok;
}
async function copyReportMarkdown(mdUrl){
  const st = $("#md-status");
  st.textContent = "загружаю…";
  try {
    const r = await fetch(mdUrl);
    if(!r.ok){
      st.textContent = r.status === 404 ? "у этого прогона нет .md" : ("ошибка " + r.status);
      return;
    }
    const text = await r.text();
    const ok = await copyToClipboard(text);
    st.textContent = ok
      ? ("✓ скопировано (" + text.length.toLocaleString("ru-RU") + " симв.)")
      : "не удалось скопировать — открой .md и скопируй вручную";
  } catch(e){ st.textContent = "ошибка: " + e; }
}
function setReportLinks(runId, htmlUrl){
  const box = $("#report-links");
  if(!runId){ box.innerHTML = ""; return; }
  const md = `/api/runs/${encodeURIComponent(runId)}/report.md`;
  box.innerHTML =
    `<button type="button" id="btn-copy-md">📋 Скопировать Markdown</button>` +
    `<a href="${md}" target="_blank" rel="noopener">📄 Открыть .md</a>` +
    `<a href="${md}" download="${esc(runId)}.md">⬇ Скачать .md</a>` +
    (htmlUrl ? `<a href="${htmlUrl}" target="_blank" rel="noopener">🌐 HTML в новой вкладке</a>` : "") +
    `<span class="muted" id="md-status"></span>`;
  $("#btn-copy-md").addEventListener("click", () => copyReportMarkdown(md));
}
function showReport(url, runId){
  const f = $("#report-frame");
  const target = url || "/api/report/index.html";
  f.src = target + (target.includes("?") ? "&" : "?") + "t=" + Date.now();
  setReportLinks(runId || "current", target);
  $("#report-panel").style.display = "";
}
renderMap();
function appendLog(line){
  if(line==null) return;
  const atBottom = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 4;
  logEl.textContent += (logEl.textContent ? "\\n" : "") + line;
  if(atBottom) logEl.scrollTop = logEl.scrollHeight;
}
function follow(jobId, kind){
  kind = kind || "scan";
  const isScan = (kind === "scan");
  if(es) es.close();
  logEl.textContent = "";
  runInfoEl.textContent = "";
  statusEl.textContent = "выполняется…"; statusEl.className = "";
  // Карта анализа и панель отчёта относятся к скану; при обновлении баз скрываем.
  $("#map-panel").style.display = isScan ? "" : "none";
  if(!isScan) $("#report-panel").style.display = "none";
  es = new EventSource(`/api/jobs/${jobId}/stream`);
  connEl.textContent = "● подключено";
  es.onmessage = ev => {
    const m = JSON.parse(ev.data);
    if(m.type === "snapshot"){
      renderStages(m.stages); (m.log||[]).forEach(appendLog);
      statusEl.textContent = m.status;
      if(m.run_dir) runInfoEl.textContent = "run: " + m.run_dir;
      if(m.log_path) appendLog("# лог: " + m.log_path);
    } else {
      if("line" in m) appendLog(m.line);
      if(m.progress) setProgress(m.progress.stage, m.progress.pct);
      if(m.stages) renderStages(m.stages);
      if(m.status) statusEl.textContent = m.status;
    }
    if(m.final || m.status === "done" || m.status === "error"){
      const ok = (m.returncode === 0) || m.status === "done";
      statusEl.textContent = ok ? "✓ готово" : "✗ ошибка";
      es.close(); connEl.textContent = "";
      loadTools();
      loadArtifacts();
      if(ok && isScan) showReport(null, "current");
    }
  };
  es.onerror = () => { connEl.textContent = ""; };
}
function currentTools(){
  const tools = Array.from(document.querySelectorAll("#tools-select input:checked"))
    .map(c => c.value).join(",");
  return tools;
}
function humanSize(value){
  const size = Number(value || 0);
  if(!Number.isFinite(size) || size <= 0) return "0 B";
  const units = ["B","KB","MB","GB","TB"];
  let idx = 0, cur = size;
  while(cur >= 1024 && idx < units.length - 1){ cur /= 1024; idx += 1; }
  return `${cur.toFixed(cur >= 100 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}
function uploadStatus(text, isError){
  const el = $("#upload-status");
  el.textContent = text;
  el.className = isError ? "" : "muted";
}
async function uploadArtifact(file){
  const fd = new FormData();
  fd.append("file", file);
  uploadStatus("загрузка " + file.name + "…", false);
  $("#report-panel").style.display = "none";
  try {
    const r = await fetch("/api/artifacts/upload", { method:"POST", body:fd });
    if(!r.ok){
      let msg = "ошибка загрузки: " + r.status;
      try { msg = (await r.json()).detail || msg; } catch(e){}
      uploadStatus(msg, true);
      return;
    }
    const body = await r.json();
    uploadStatus("загружен: " + (body.artifact.display_name || body.artifact.original_filename), false);
    await loadArtifacts();
  } catch(e) {
    uploadStatus("ошибка загрузки: " + e, true);
  }
}
async function scanArtifact(artifactId){
  statusEl.textContent = "запуск анализа…";
  const fd = new FormData();
  fd.append("tools", currentTools());
  const r = await fetch(`/api/artifacts/${encodeURIComponent(artifactId)}/scan`, { method:"POST", body:fd });
  if(!r.ok){
    let msg = "ошибка запуска: " + r.status;
    try { msg = (await r.json()).detail || msg; } catch(e){}
    statusEl.textContent = msg;
    return;
  }
  follow((await r.json()).job_id, "scan");
}
async function saveArtifact(artifactId){
  const caseId = document.getElementById("case-" + artifactId)?.value || "";
  const displayName = document.getElementById("name-" + artifactId)?.value || "";
  const r = await fetch(`/api/artifacts/${encodeURIComponent(artifactId)}`, {
    method:"PATCH",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({ case_id: caseId, display_name: displayName })
  });
  if(!r.ok){
    let msg = "ошибка сохранения: " + r.status;
    try { msg = (await r.json()).detail || msg; } catch(e){}
    uploadStatus(msg, true);
    return;
  }
  uploadStatus("метаданные сохранены", false);
  await loadArtifacts();
}
async function hideArtifact(artifactId){
  const r = await fetch(`/api/artifacts/${encodeURIComponent(artifactId)}`, { method:"DELETE" });
  if(!r.ok){
    let msg = "ошибка скрытия: " + r.status;
    try { msg = (await r.json()).detail || msg; } catch(e){}
    uploadStatus(msg, true);
    return;
  }
  await loadArtifacts();
}
// Hard delete. Three confirmations, exactly as asked — and the server still
// demands ?confirm=<id>, because these dialogs only exist in the browser.
async function purgeArtifact(artifactId, name){
  if(!confirm(`Удалить «${name}» навсегда — из каталога и из хранилища.\n\nУверены?`)) return;
  if(!confirm("Точно-точно?")) return;
  if(!confirm(`Совсем отчаялся?\n\nФайл будет стёрт с диска. Отменить будет нельзя.`)) return;
  const url = `/api/artifacts/${encodeURIComponent(artifactId)}/purge`
            + `?confirm=${encodeURIComponent(artifactId)}`;
  const r = await fetch(url, { method:"DELETE" });
  if(!r.ok){
    let msg = "ошибка удаления: " + r.status;
    try { msg = (await r.json()).detail || msg; } catch(e){}
    uploadStatus(msg, true);
    return;
  }
  uploadStatus(`удалён навсегда: ${name}`, false);
  await loadArtifacts();
}
async function deleteRun(runId){
  const r = await fetch(`/api/runs/${encodeURIComponent(runId)}`, { method:"DELETE" });
  if(r.ok) await loadArtifacts();
}
async function openArtifactReports(artifactId){
  const r = await fetch(`/api/artifacts/${encodeURIComponent(artifactId)}/runs`);
  if(!r.ok){
    let msg = "ошибка отчётов: " + r.status;
    try { msg = (await r.json()).detail || msg; } catch(e){}
    uploadStatus(msg, true);
    return;
  }
  const body = await r.json();
  const first = (body.runs || []).find(x => x.default_report_path);
  if(!first){
    uploadStatus("для артефакта ещё нет сохранённого отчёта", true);
    return;
  }
  runInfoEl.textContent = "run: " + first.id;
  showReport(`/api/runs/${encodeURIComponent(first.id)}/files/${first.default_report_path}`, first.id);
}
function artifactRunButtons(artifact){
  const runs = artifact.runs || [];
  if(!runs.length) return `<span class="muted">запусков пока нет</span>`;
  return runs.slice(0, 4).map(run =>
    `<button type="button" onclick="openRunReport('${esc(run.id)}')">${esc(run.id)}</button>` +
    `<button type="button" onclick="deleteRun('${esc(run.id)}')">скрыть run</button>`
  ).join("");
}
// Цвет обводки карточки — это статус, а не украшение.  Считаем только по тем
// данным, что реально есть в /api/artifacts: наличие прогонов и legacy-природа.
function artifactStatus(a){
  if(a.deleted_at) return "";
  if(String(a.id).startsWith("legacy-")) return "st-legacy";
  return Number(a.run_count || 0) > 0 ? "st-scanned" : "st-new";
}
function artifactStatusTitle(a){
  if(a.deleted_at) return "скрыт";
  if(String(a.id).startsWith("legacy-")) return "legacy: представление сохранённого прогона (evidence)";
  return Number(a.run_count || 0) > 0 ? "есть сохранённые прогоны" : "ещё не сканировался";
}
function renderArtifacts(items){
  const box = $("#artifact-list");
  if(!(items || []).length){
    box.innerHTML = `<div class="muted">Артефактов пока нет. Перетащи файл выше.</div>`;
    return;
  }
  box.innerHTML = items.map(a => `
    <div class="artifact-card ${a.deleted_at ? "deleted" : ""} ${artifactStatus(a)}"
         title="${artifactStatusTitle(a)}">
      <div class="artifact-head">
        <div>
          <div class="artifact-name">${esc(a.display_name || a.original_filename || a.id)}</div>
          <div class="artifact-meta">${esc(a.original_filename || "")} · ${humanSize(a.size)} · SHA-256: ${esc(a.sha256 || "—")}</div>
          <div class="artifact-meta">${esc(a.stored_path || "")}</div>
        </div>
        <div class="artifact-actions">
          <button type="button" onclick="scanArtifact('${esc(a.id)}')">Scan</button>
          <button type="button" onclick="openArtifactReports('${esc(a.id)}')">Reports</button>
          <button type="button" onclick="hideArtifact('${esc(a.id)}')">Hide</button>
          ${String(a.id).startsWith("legacy-")
            ? `<button type="button" class="danger" disabled
                 title="legacy-артефакт — это представление сохранённого прогона (evidence). Удалять нельзя.">🗑 Удалить</button>`
            : `<button type="button" class="danger"
                 onclick="purgeArtifact('${esc(a.id)}','${esc(a.display_name || a.original_filename || a.id)}')"
                 title="Стирает файл из хранилища. Сохранённые прогоны не трогает.">🗑 Удалить навсегда</button>`}
        </div>
      </div>
      <div class="artifact-fields">
        <label>CYBERSEC-ID
          <input id="case-${esc(a.id)}" value="${esc(a.case_id || "")}" placeholder="CYBERSEC-12345">
        </label>
        <label>Название
          <input id="name-${esc(a.id)}" value="${esc(a.display_name || "")}" placeholder="prometheus-3.11.0">
        </label>
      </div>
      <div class="row" style="margin-top:12px">
        <button type="button" onclick="saveArtifact('${esc(a.id)}')">Сохранить</button>
        <span class="artifact-meta">запусков: ${Number(a.run_count || 0)} · загружен: ${esc(fmtTime(a.uploaded_at_utc))}</span>
      </div>
      <div class="artifact-runs">${artifactRunButtons(a)}</div>
    </div>
  `).join("");
}
async function loadArtifacts(){
  const r = await fetch("/api/artifacts");
  if(!r.ok){
    $("#artifact-list").innerHTML = `<div class="muted">Не удалось загрузить каталог (${r.status}).</div>`;
    return;
  }
  renderArtifacts((await r.json()).artifacts || []);
}
async function openRunReport(runId){
  const r = await fetch(`/api/runs/${encodeURIComponent(runId)}`);
  if(!r.ok) return;
  const body = await r.json();
  const reports = body.reports || [];
  const candidate = reports.find(p => p.endsWith("/index.html")) || reports.find(p => p.endsWith(".html")) || reports.find(p => p.endsWith(".md"));
  if(candidate) {
    runInfoEl.textContent = "run: " + runId;
    showReport(`/api/runs/${encodeURIComponent(runId)}/files/${candidate}`, runId);
  }
}
async function updateTarget(target){
  statusEl.textContent = "обновление баз: " + target + "…"; statusEl.className = "";
  const r = await fetch("/api/update-db?target=" + encodeURIComponent(target), { method:"POST" });
  if(!r.ok){ statusEl.textContent = "ошибка обновления: " + r.status; return; }
  const j = await r.json();
  follow(j.job_id, "update");
  if(j.log) appendLog("# лог обновления: " + j.log);
}
function fmtTime(t){
  if(!t) return "—";
  const d = new Date(t); return isNaN(d) ? t : d.toLocaleString();
}
// Grype/Trivy report when upstream BUILT the DB; cve-bin-tool can only report
// when we IMPORTED it (the NVD JSON feeds carry no build date). Label which.
const DB_DATE_SUFFIX = { built: " · сборка", imported: " · импорт" };
const DB_DATE_TITLE = {
  built: "дата сборки базы апстримом",
  imported: "время импорта базы у нас — у источника нет даты сборки",
};
function dbDateSuffix(t){
  return (t.db_updated && DB_DATE_SUFFIX[t.db_updated_kind]) || "";
}
function dbDateTitle(t){
  return (t.db_updated && DB_DATE_TITLE[t.db_updated_kind]) || "";
}
function barrel(fill, mini, stage, unavailable){
  const na = (fill == null);
  const f = na ? 0 : Math.max(0, Math.min(100, fill));
  const broken = !!unavailable;   // base that can't be loaded yet → red ✕
  let bubbles = "";
  if(!mini && f > 0){
    bubbles = [12,30,48,66].map((x,i) =>
      `<span class="bubble" style="left:${x}px;animation-duration:${(2.4+i*0.6).toFixed(1)}s;animation-delay:${(i*0.5).toFixed(1)}s"></span>`).join("");
  }
  return `<div class="barrel ${f>0?'lit':''} ${broken?'broken':''}" data-stage="${stage||''}">
      <div class="barrel-fill" style="height:${na?0:f}%"></div>${bubbles}
      <div class="rad">${broken?'✕':'☢'}</div>
      <div class="barrel-pct ${f<55?'low':''}">${broken?'—':(na?'n/a':f+'%')}</div>
    </div>`;
}
// Live download progress: fill the matching barrel as the DB streams in.
function setProgress(stage, pct){
  if(!stage) return;
  const b = document.querySelector('.barrel[data-stage="'+stage+'"]');
  if(!b) return;
  const f = Math.max(0, Math.min(100, pct));
  const fill = b.querySelector(".barrel-fill"); if(fill) fill.style.height = f + "%";
  b.classList.toggle("lit", f > 0);
  if(f > 0){ b.classList.remove("broken"); const r = b.querySelector(".rad"); if(r) r.textContent = "☢"; }
  const p = b.querySelector(".barrel-pct");
  if(p){ p.textContent = Math.round(f) + "%"; p.classList.toggle("low", f < 55); }
}
async function loadTools(){
  const r = await fetch("/api/tools"); const data = await r.json();
  $("#upd-badge").textContent = data.db_update_enabled_by_default
    ? "обновление баз включено" : "обновление баз отключено по умолчанию";
  const box = $("#tools"); box.innerHTML = "";
  data.tools.forEach(t => {
    const el = document.createElement("div"); el.className = "barrel-box";
    const btn = t.update_target ? `<button data-upd="${t.update_target}">⟳ Обновить</button>` : "";
    let sources = "";
    if(t.sources && t.sources.length){
      sources = `<div class="cbt-sources">` + t.sources.map(s => `
        <div class="mini" title="${s.unavailable ? 'пока недоступен в этом контуре' : (s.count||0).toLocaleString()+' CVE'}">
          ${barrel(s.fill, true, "", s.unavailable)}
          <div class="bsub">${s.name}</div>
          <button data-upd="${s.update_target}" title="обновить только ${s.name}">⟳</button>
        </div>`).join("") + `</div>`;
    }
    el.innerHTML = `
      ${barrel(t.fill, false, t.update_target)}
      <div class="bt">${t.name}</div>
      <div class="bsub">${t.version||"—"} · ${t.db_status||"n/a"}</div>
      <div class="bsub" title="${dbDateTitle(t)}">${fmtTime(t.db_updated)}${dbDateSuffix(t)}</div>
      ${btn}${sources}`;
    box.appendChild(el);
  });
  box.querySelectorAll("button[data-upd]").forEach(b =>
    b.addEventListener("click", () => updateTarget(b.dataset.upd)));
}
const drop = $("#drop"), fileInput = $("#file");
drop.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", e => { if(e.target.files[0]) uploadArtifact(e.target.files[0]); });
["dragenter","dragover"].forEach(ev => drop.addEventListener(ev, e => {
  e.preventDefault(); drop.classList.add("hot"); }));
["dragleave","drop"].forEach(ev => drop.addEventListener(ev, e => {
  e.preventDefault(); drop.classList.remove("hot"); }));
drop.addEventListener("drop", e => { const f = e.dataTransfer.files[0]; if(f) uploadArtifact(f); });
$("#btn-update").addEventListener("click", () => updateTarget("all"));
$("#btn-refresh").addEventListener("click", loadTools);
loadTools();
loadArtifacts();

// ── Resume from checkpoint ───────────────────────────────────────────────────
async function resumeScan(){
  const btn = $("#btn-resume"); btn.disabled = true;
  try {
    const r = await fetch("/api/scan/resume", { method:"POST" });
    if(!r.ok){
      let msg = "ошибка " + r.status;
      try { msg = (await r.json()).detail || msg; } catch(e){}
      $("#resume-info").textContent = msg;
      return;
    }
    follow((await r.json()).job_id, "scan");
  } finally { btn.disabled = false; }
}
$("#btn-resume").addEventListener("click", resumeScan);

// ── Монитор: контейнеры + прогресс пайплайна (обновление каждые 5 c) ────────
const MON_STAGE_ICON = { done:"✓", active:"▶", error:"✗", pending:"·" };
function esc(s){ const d=document.createElement("span"); d.textContent=String(s??""); return d.innerHTML; }
async function loadMonitor(){
  let m;
  try { const r = await fetch("/api/monitor"); if(!r.ok) return; m = await r.json(); }
  catch(e){ return; }
  const p = m.pipeline || {};
  let html = "";
  if(!p.present){
    html = "<span class='muted'>нет активного/последнего прогона</span>";
  } else {
    const head = [];
    head.push("<b>" + esc(p.status||"?") + "</b>");
    if(p.current_stage) head.push("этап: <b>" + esc(p.current_stage) + "</b>");
    if(p.elapsed_s != null) head.push(Math.round(p.elapsed_s) + "s");
    if(p.resumed) head.push("(продолжен с чекпоинта)");
    html = head.join(" · ");
    if(p.target) html += "<div class='muted' style='font-size:12px'>" + esc(p.target) + "</div>";
    html += "<div style='margin-top:6px'>" + (p.stages||[]).map(s => {
      const ic = MON_STAGE_ICON[s.status]||"?";
      let t = "";
      if(s.duration_s != null) t = " " + Math.round(s.duration_s) + "s";
      else if(s.elapsed_s != null) t = " …" + Math.round(s.elapsed_s) + "s";
      const skip = s.skipped_via_resume ? " (skip)" : "";
      return "<span class='pill' style='margin-right:6px'>" + ic + " " + esc(s.stage) + t + skip + "</span>";
    }).join("") + "</div>";
    // показать кнопку resume для прерванного/упавшего прогона
    const resumable = p.status === "error" || p.status === "aborted" ||
      (p.status === "running" && p.updated_utc && (Date.now() - new Date(p.updated_utc).getTime()) > 15*60*1000);
    $("#resume-row").style.display = resumable ? "" : "none";
    if(resumable) $("#resume-info").textContent =
      "прерванный прогон: " + (p.target||"") + " — продолжить с последнего завершённого этапа";
  }
  $("#mon-pipeline").innerHTML = html;
  const latest = m.latest_run || null;
  let shot = "";
  if(latest){
    const chk = latest.checkpoint || {};
    const bits = [];
    bits.push("<b>snapshot:</b> " + esc(latest.id || ""));
    if(chk.stage) bits.push("stage: <b>" + esc(chk.stage) + "</b>");
    if(chk.status) bits.push("status: <b>" + esc(chk.status) + "</b>");
    if(chk.updated_at_utc) bits.push("updated: " + esc(fmtTime(chk.updated_at_utc)));
    shot = "<div class='muted'>" + bits.join(" · ") + "</div>" +
      "<div class='muted' style='font-size:12px'>" + esc(latest.path || "") + "</div>";
  } else {
    shot = "<span class='muted'>сохранённых snapshots пока нет</span>";
  }
  $("#mon-snapshot").innerHTML = shot;
  const c = m.containers || {};
  let chtml = "";
  if(!c.ok){
    chtml = "<span class='muted'>docker недоступен: " + esc(c.error||"?") + "</span>";
  } else if(!(c.containers||[]).length){
    chtml = "<span class='muted'>контейнеры стека не запущены</span>";
  } else {
    chtml = c.containers.map(x => {
      const st = String(x.state||"").toLowerCase();
      const cls = st === "running" ? "ok" : (st === "exited" ? "" : "failed");
      return "<span class='pill " + cls + "' style='margin:0 6px 6px 0; display:inline-block'>" +
        esc(x.service||x.name) + ": " + esc(x.status||x.state||"?") + "</span>";
    }).join("");
  }
  $("#mon-containers").innerHTML = chtml;
}
loadMonitor();
setInterval(loadMonitor, 5000);

// ── Proxy chain toggle ────────────────────────────────────────────────────────
const CHAIN_LABELS = { direct: "🟢 Direct", corp: "🟡 Corp (proxy)", "via-vpn": "🟣 VPN" };
const CHAIN_CYCLE  = ["direct", "corp", "via-vpn"];
let currentChain = null;

function applyChain(chain){
  currentChain = chain;
  const btn = $("#btn-proxy");
  btn.textContent = CHAIN_LABELS[chain] || chain;
  btn.className = "proxy-btn " + chain;
}
async function loadProxyChain(){
  try {
    const r = await fetch("/api/proxy-chain");
    if(r.ok) applyChain((await r.json()).chain);
  } catch(e) { /* non-fatal */ }
}
async function cycleProxy(){
  const idx = CHAIN_CYCLE.indexOf(currentChain);
  const next = CHAIN_CYCLE[(idx + 1) % CHAIN_CYCLE.length];
  const btn = $("#btn-proxy"); btn.disabled = true;
  try {
    const r = await fetch("/api/proxy-chain?chain=" + encodeURIComponent(next), { method:"POST" });
    if(r.ok) applyChain((await r.json()).chain);
    else btn.textContent = "ошибка " + r.status;
  } finally { btn.disabled = false; }
}
loadProxyChain();

// ── Route plan (авто-маршрут обновлений) ─────────────────────────────────────
const ROUTE_SHORT = { cve_bin_tool: "cbt", trivy: "trivy", grype: "grype" };
function fmtRoute(plan){
  const parts = Object.entries(plan || {}).map(([tool, sel]) =>
    `${ROUTE_SHORT[tool] || tool}: ${sel && sel.transport ? sel.transport : "—"}`);
  return parts.length ? parts.join(" · ") : "ещё не зондировался";
}
async function loadRoute(){
  try {
    const r = await fetch("/api/route-plan");
    if(r.ok) $("#route-info").textContent = fmtRoute((await r.json()).plan);
  } catch(e) { /* non-fatal */ }
}
async function refreshRoute(){
  const b = $("#btn-route"); b.disabled = true;
  $("#route-info").textContent = "зондирую сеть…";
  try {
    const r = await fetch("/api/route-plan", { method:"POST" });
    if(r.ok) $("#route-info").textContent = fmtRoute((await r.json()).plan);
    else $("#route-info").textContent = "ошибка " + r.status;
  } finally { b.disabled = false; }
}
loadRoute();

// ── Скины: палитра + обводка ────────────────────────────────────────────────
// Храним выбор в localStorage, а не на сервере: дашборд отдаётся без
// аутентификации, и «текущая тема» на сервере означала бы, что любой в сети
// перекрашивает интерфейс всем сразу.
const SKIN_KEYS = { theme:"el-sca.theme", edge:"el-sca.edge" };
const SKIN_DEFAULTS = { theme:document.documentElement.dataset.theme,
                        edge:document.documentElement.dataset.edge };
function applySkin(kind, id){
  document.documentElement.dataset[kind] = id;
  try { localStorage.setItem(SKIN_KEYS[kind], id); } catch(e) { /* private mode */ }
  document.querySelectorAll(`.theme-card[data-kind="${kind}"]`).forEach(c =>
    c.classList.toggle("chosen", c.dataset.id === id));
}
function restoreSkin(){
  Object.keys(SKIN_KEYS).forEach(kind => {
    let saved = null;
    try { saved = localStorage.getItem(SKIN_KEYS[kind]); } catch(e) {}
    applySkin(kind, saved || SKIN_DEFAULTS[kind]);
  });
}
document.addEventListener("click", ev => {
  const pick = ev.target.closest(".skin-pick");
  if(pick){ applySkin(pick.dataset.kind, pick.dataset.id); return; }
  if(ev.target.id === "skin-reset"){
    Object.keys(SKIN_KEYS).forEach(kind => {
      try { localStorage.removeItem(SKIN_KEYS[kind]); } catch(e) {}
      applySkin(kind, SKIN_DEFAULTS[kind]);
    });
  }
});
restoreSkin();
</script>
</body></html>
"""


def render_gui() -> str:
    """Return the active dashboard GUI (drag-drop scan + pipeline + DB cards)."""
    from .themes import ACTIVE_EDGE_ID, ACTIVE_THEME_ID, render_skin_styles, render_theme_picker

    return (
        _GUI_HTML.replace("__THEME__", ACTIVE_THEME_ID)
        .replace("__EDGE__", ACTIVE_EDGE_ID)
        .replace("<!--SKIN_STYLES-->", render_skin_styles())
        .replace("<!--THEME_PICKER-->", render_theme_picker())
    )


def _artifact_runs_payload(
    artifacts_dir: Path,
    artifact: dict[str, Any],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for run_ref in artifact.get("runs", []):
        run_id = str(run_ref.get("id") or "").strip()
        if not run_id:
            continue
        detail = run_detail(artifacts_dir, run_id)
        if detail is None:
            continue
        run_root = Path(detail["path"])
        reports = _report_candidates(run_root)
        out.append(
            {
                "id": run_id,
                "path": detail["path"],
                "case_id": str((detail.get("manifest") or {}).get("case_id") or ""),
                "updated_at_utc": str((detail.get("checkpoint") or {}).get("updated_at_utc") or ""),
                "default_report_path": reports[0] if reports else "",
                "report_paths": reports,
                "markdown_report_path": _markdown_report(run_root),
            }
        )
    # Newest run first: run ids embed a YYYYMMDD-HHMMSS stamp, so a reverse
    # lexical sort is chronological.  This makes "open the artifact's report"
    # (openArtifactReports picks the first run with a report) resolve to the
    # LATEST scan of THIS artifact instead of an arbitrary/oldest one — the
    # fix for a stale or wrong-looking report opening from the card.
    out.sort(key=lambda r: str(r.get("id") or ""), reverse=True)
    return out


def create_app(artifacts_dir: Path | str, repo_root: Path | str | None = None):
    """Build the FastAPI app: read-only run browser + active scan/update GUI.

    ``repo_root`` is where ``docker compose`` is invoked from (defaults to the
    parent of ``artifacts_dir``).  Scans and DB updates run as host
    subprocesses via :mod:`resilient_updates.orchestrator`.
    """
    from fastapi import Body, FastAPI, File, Form, HTTPException
    from fastapi.responses import (
        FileResponse,
        HTMLResponse,
        PlainTextResponse,
        StreamingResponse,
    )

    from .orchestrator import JobRegistry, sse_stream

    root = Path(artifacts_dir)
    rroot = Path(repo_root) if repo_root is not None else root.resolve().parent
    uploads = root / "uploads"
    catalog = ArtifactCatalog(root)
    registry = JobRegistry(rroot)
    active_enabled = os.environ.get("EL_SCA_DASHBOARD_ACTIVE", "1").strip().lower() not in (
        "0",
        "false",
        "no",
    )

    app = FastAPI(title="el-sca-ansamble dashboard", version="0.2.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return render_gui()

    # -- legacy read-only run browser (still server-side rendered) -----------
    @app.get("/runs", response_class=HTMLResponse)
    def runs_index() -> str:
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

    # -- active GUI API -----------------------------------------------------
    @app.get("/api/tools")
    def tools() -> dict[str, Any]:
        return tool_status(root, rroot)

    @app.get("/api/artifacts")
    def artifacts(include_deleted: bool = False) -> dict[str, Any]:
        return {
            "artifacts": catalog.list_artifacts(include_deleted=include_deleted, legacy_runs=list_runs(root))
        }

    @app.post("/api/artifacts/upload", response_model=None)
    def upload_artifact(
        file: UploadFile = File(...),
        case_id: str = Form(""),
        display_name: str = Form(""),
    ) -> dict[str, Any]:
        if not active_enabled:
            raise HTTPException(status_code=403, detail="active upload is disabled for this dashboard")
        if not is_valid_case_id(case_id):
            raise HTTPException(status_code=400, detail="case_id must look like CYBERSEC-12345")
        artifact = catalog.create_upload(
            filename=file.filename or "artifact.bin",
            fileobj=file.file,
            case_id=case_id,
            display_name=display_name,
        )
        return {"artifact": artifact}

    @app.patch("/api/artifacts/{artifact_id}")
    def patch_artifact(artifact_id: str, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        case_id = payload.get("case_id")
        display_name = payload.get("display_name")
        if case_id is not None and not is_valid_case_id(str(case_id)):
            raise HTTPException(status_code=400, detail="case_id must look like CYBERSEC-12345")
        artifact = catalog.update_artifact(
            artifact_id,
            case_id=(None if case_id is None else str(case_id)),
            display_name=(None if display_name is None else str(display_name)),
            legacy_runs=list_runs(root),
        )
        if artifact is None:
            raise HTTPException(status_code=404, detail=f"artifact not found: {artifact_id}")
        return {"artifact": artifact}

    @app.delete("/api/artifacts/{artifact_id}")
    def delete_artifact(artifact_id: str) -> dict[str, Any]:
        artifact = catalog.soft_delete_artifact(artifact_id, legacy_runs=list_runs(root))
        if artifact is None:
            raise HTTPException(status_code=404, detail=f"artifact not found: {artifact_id}")
        return {"artifact": artifact}

    @app.delete("/api/artifacts/{artifact_id}/purge")
    def purge_artifact(artifact_id: str, confirm: str = "") -> dict[str, Any]:
        """Hard-delete an uploaded artifact from the catalogue AND from disk.

        The GUI asks three times before calling this, but that is client-side
        only — a stray `curl -X DELETE` would not see those dialogs.  So the
        server requires `?confirm=<artifact_id>`: deleting is never the result
        of a single accidental request.

        Saved runs are NOT touched: they are evidence under `_SCA_reports/`.
        `legacy-*` ids are a view over those runs and are refused outright.
        """
        if confirm != artifact_id:
            raise HTTPException(
                status_code=400,
                detail="purge requires ?confirm=<artifact_id>",
            )
        try:
            artifact = catalog.purge_artifact(artifact_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if artifact is None:
            raise HTTPException(status_code=404, detail=f"artifact not found: {artifact_id}")
        return {"purged": artifact_id, "artifact": artifact}

    @app.get("/api/artifacts/{artifact_id}/runs")
    def artifact_runs(artifact_id: str) -> dict[str, Any]:
        artifact = catalog.get_artifact(artifact_id, legacy_runs=list_runs(root))
        if artifact is None:
            raise HTTPException(status_code=404, detail=f"artifact not found: {artifact_id}")
        return {"artifact_id": artifact_id, "runs": _artifact_runs_payload(root, artifact)}

    @app.post("/api/artifacts/{artifact_id}/scan")
    def scan_artifact(artifact_id: str, tools: str = Form("")) -> dict[str, str]:
        if not active_enabled:
            raise HTTPException(status_code=403, detail="active scan is disabled for this dashboard")
        artifact = catalog.get_artifact(artifact_id, legacy_runs=list_runs(root))
        if artifact is None:
            raise HTTPException(status_code=404, detail=f"artifact not found: {artifact_id}")
        target_path = Path(str(artifact.get("stored_path") or ""))
        if not target_path.is_file():
            raise HTTPException(status_code=409, detail=f"artifact file is missing: {target_path}")
        selected = {t.strip() for t in tools.split(",") if t.strip()} or None
        job = registry.start_scan(
            str(target_path), tools=selected, case_id=str(artifact.get("case_id") or "")
        )
        if job.run_dir:
            catalog.add_run(artifact_id, run_id=job.run_dir.name, run_dir=job.run_dir)
        return {
            "job_id": job.id,
            "artifact_id": artifact_id,
            "target": str(target_path),
            "run_dir": str(job.run_dir) if job.run_dir else "",
            "log": str(job.log_path) if job.log_path else "",
        }

    @app.post("/api/scan", response_model=None)
    def scan(
        file: UploadFile = File(...),
        tools: str = Form(""),
        case_id: str = Form(""),
        display_name: str = Form(""),
    ) -> dict[str, str]:
        if not active_enabled:
            raise HTTPException(status_code=403, detail="active scan is disabled for this dashboard")
        if not is_valid_case_id(case_id):
            raise HTTPException(status_code=400, detail="case_id must look like CYBERSEC-12345")
        uploads.mkdir(parents=True, exist_ok=True)
        artifact = catalog.create_upload(
            filename=file.filename or "artifact.bin",
            fileobj=file.file,
            case_id=case_id,
            display_name=display_name,
        )
        # tools = comma-separated subset of syft,grype,trivy,cve-bin-tool; empty = all.
        selected = {t.strip() for t in tools.split(",") if t.strip()} or None
        target_path = str(Path(str(artifact["stored_path"])).resolve())
        job = registry.start_scan(target_path, tools=selected, case_id=str(artifact.get("case_id") or ""))
        if job.run_dir:
            catalog.add_run(str(artifact["id"]), run_id=job.run_dir.name, run_dir=job.run_dir)
        return {
            "job_id": job.id,
            "artifact_id": str(artifact["id"]),
            "target": target_path,
            "run_dir": str(job.run_dir) if job.run_dir else "",
            "log": str(job.log_path) if job.log_path else "",
        }

    @app.post("/api/scan/resume")
    def scan_resume() -> dict[str, str]:
        """Resume the last interrupted scan from its checkpoint (pipeline_state.json)."""
        if not active_enabled:
            raise HTTPException(status_code=403, detail="active scan is disabled for this dashboard")
        from .pipeline_state import load_state

        state = load_state(root)
        target = (state or {}).get("target") or ""
        if not state or not target:
            raise HTTPException(status_code=409, detail="нет сохранённого чекпоинта (pipeline_state.json)")
        if not Path(target).exists():
            raise HTTPException(status_code=409, detail=f"цель чекпоинта недоступна: {target}")
        tool_key = str(state.get("tool") or "all")
        tools_set = None if tool_key in ("", "all") else {t for t in tool_key.split(",") if t}
        job = registry.start_scan(
            target, tools=tools_set, resume=True, case_id=str(state.get("case_id") or "")
        )
        return {
            "job_id": job.id,
            "target": target,
            "run_dir": str(job.run_dir) if job.run_dir else "",
            "log": str(job.log_path) if job.log_path else "",
        }

    @app.get("/api/monitor")
    def monitor_endpoint() -> dict[str, Any]:
        """Container status + current pipeline progress (the «Монитор» panel)."""
        from .monitor import gather_status

        return gather_status(root, repo_root=rroot)

    @app.get("/api/report/{path:path}")
    def report_file(path: str):
        base = (root / "reports" / "final").resolve()
        target = (base / path).resolve()
        if base != target and base not in target.parents:
            raise HTTPException(status_code=400, detail="bad path")
        if not target.is_file():
            raise HTTPException(status_code=404, detail="report not found")
        return FileResponse(target)

    @app.get("/api/runs/{run_id}/report.md")
    def run_report_markdown(run_id: str):
        """The run's final Markdown report as inline UTF-8 text.

        Served as text (not a FileResponse) so the browser renders it for
        copy/paste instead of downloading it — that is what operators hand over.
        """
        run_root = _resolve_run_dir(root, run_id)
        if run_root is None:
            raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
        rel = _markdown_report(run_root)
        if not rel:
            raise HTTPException(status_code=404, detail="run has no markdown report")
        target = run_root / rel
        return PlainTextResponse(
            target.read_text(encoding="utf-8", errors="replace"),
            media_type="text/markdown; charset=utf-8",
        )

    @app.get("/api/runs/{run_id}/files/{path:path}")
    def run_file(run_id: str, path: str):
        run_root = _resolve_run_dir(root, run_id)
        if run_root is None:
            raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
        base = run_root.resolve()
        target = (base / path).resolve()
        if base != target and base not in target.parents:
            raise HTTPException(status_code=400, detail="bad path")
        if not target.is_file():
            raise HTTPException(status_code=404, detail="file not found")
        return FileResponse(target)

    @app.post("/api/update-db")
    def update_db(target: str = "all") -> dict[str, str]:
        if not active_enabled:
            raise HTTPException(status_code=403, detail="active DB update is disabled for this dashboard")
        # target: all | trivy | grype | cve-bin-tool | cve-bin-tool:<SOURCE>
        job = registry.start_update(target=target)
        return {"job_id": job.id, "target": target, "log": str(job.log_path) if job.log_path else ""}

    @app.get("/api/jobs/{job_id}")
    def job_status(job_id: str) -> dict[str, Any]:
        job = registry.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"job not found: {job_id}")
        return job.snapshot()

    @app.get("/api/jobs/{job_id}/stream")
    def job_stream(job_id: str):
        job = registry.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"job not found: {job_id}")
        return StreamingResponse(sse_stream(job), media_type="text/event-stream")

    @app.delete("/api/runs/{run_id}")
    def delete_run(run_id: str) -> dict[str, str]:
        detail = run_detail(root, run_id)
        if detail is None:
            raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
        catalog.hide_run(run_id)
        return {"status": "deleted", "run_id": run_id}

    # ── Route plan API (ADR-0007 P2) ─────────────────────────────────────────
    # route-doctor probes the live egress from INSIDE the docker network and
    # writes artifacts/route-plan.{json,env}; updates apply it automatically.
    @app.get("/api/route-plan")
    def get_route_plan() -> dict[str, Any]:
        """Current per-tool egress plan (empty if route-doctor never ran)."""
        data = _safe_read_json(root / "route-plan.json") or {}
        return {
            "generated_utc": data.get("generated_utc"),
            "plan": data.get("plan") or {},
            "transports": data.get("transports") or [],
        }

    @app.post("/api/route-plan")
    def refresh_route_plan() -> dict[str, Any]:
        """Re-probe the network (run route-doctor) and return the fresh plan."""
        if not active_enabled:
            raise HTTPException(status_code=403, detail="active mode is disabled for this dashboard")
        import subprocess

        try:
            subprocess.run(  # fixed argv, no shell
                [*registry.compose, "--profile", "route", "run", "--rm", "route-doctor"],
                cwd=str(rroot),
                capture_output=True,
                timeout=240,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"route-doctor failed: {exc}") from exc
        return get_route_plan()

    # ── Proxy chain API ───────────────────────────────────────────────────────
    # Static defaults live in configs/feed_sources.yaml (tracked by git).
    # The selection made via this API is persisted to a separate gitignored
    # runtime file so toggling a chain never dirties the git work tree.
    _VALID_CHAINS = {"direct", "corp", "via-vpn"}
    _CHAIN_RE = re.compile(r"^(\s*default_chain:\s*)\S+", re.MULTILINE)

    def _chain_paths() -> tuple[Path, Path]:
        configs = rroot / "configs"
        return configs / "feed_sources.runtime.yaml", configs / "feed_sources.yaml"

    @app.get("/api/proxy-chain")
    def get_proxy_chain() -> dict[str, str]:
        """Return the active default_chain (runtime override first, then static config)."""
        for cfg in _chain_paths():
            try:
                m = _CHAIN_RE.search(cfg.read_text(encoding="utf-8"))
            except FileNotFoundError:
                continue
            if m:
                return {"chain": m.group(0).split(":")[-1].strip()}
        return {"chain": "unknown"}

    @app.post("/api/proxy-chain")
    def set_proxy_chain(chain: str = "direct") -> dict[str, str]:
        """Persist default_chain (direct | corp | via-vpn) to the runtime override file."""
        if chain not in _VALID_CHAINS:
            raise HTTPException(status_code=400, detail=f"chain must be one of {_VALID_CHAINS}")
        runtime_cfg, _static_cfg = _chain_paths()
        try:
            runtime_cfg.parent.mkdir(parents=True, exist_ok=True)
            runtime_cfg.write_text(
                "# Runtime override written by the dashboard. Gitignored.\n"
                "# Delete this file to fall back to configs/feed_sources.yaml.\n"
                f"default_chain: {chain}\n",
                encoding="utf-8",
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {"chain": chain}

    return app
