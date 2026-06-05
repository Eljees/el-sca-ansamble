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

    tools = [
        {
            "name": "Syft",
            "role": "SBOM generator",
            "version": versions.get("SYFT_VERSION", "—"),
            "db_status": "n/a",
            "db_updated": None,
            "detail": "no vulnerability DB (produces SBOM)",
        },
        {
            "name": "Grype",
            "role": "SBOM → CVE scanner",
            "version": versions.get("GRYPE_VERSION", "—"),
            "db_status": _status("grype"),
            "db_updated": _deep_find(grype_payload, "built") or _updated("grype"),
            "detail": (f"checksum {str(grype_checksum)[:23]}…" if grype_checksum else "anchore DB"),
        },
        {
            "name": "Trivy",
            "role": "filesystem/CVE scanner",
            "version": versions.get("TRIVY_VERSION", "—"),
            "db_status": _status("trivy"),
            "db_updated": _updated("trivy"),
            "detail": "aquasec trivy-db",
        },
        {
            "name": "cve-bin-tool",
            "role": "binary CVE scanner",
            "version": "local build",
            "db_status": _status("cve-bin-tool-db") or _status("cve-bin-tool-update-status"),
            "db_updated": _updated("cve-bin-tool-db", "cve-bin-tool-update-status"),
            "detail": (
                f"{int(cbt_counts):,} CVE rows"
                if isinstance(cbt_counts, (int, float))
                else "json-mirror DB"
            ),
        },
    ]
    return {"db_update_enabled_by_default": False, "tools": tools}


# ── Active GUI (drag-drop scan + live pipeline + DB cards) ───────────────────

_GUI_HTML = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>el-sca-ansamble — анализ артефактов</title>
<style>
  :root { --bg:#0f1419; --panel:#1a2027; --line:#2b3540; --fg:#e6edf3;
          --muted:#8b98a5; --accent:#3b82f6; --ok:#22c55e; --active:#eab308; --err:#ef4444; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif; }
  header { padding:16px 24px; border-bottom:1px solid var(--line);
           display:flex; align-items:center; gap:16px; flex-wrap:wrap; }
  h1 { font-size:18px; margin:0; }
  .badge { font-size:12px; padding:3px 10px; border-radius:999px;
           background:#3a2a14; color:#f0c674; border:1px solid #5c4420; }
  main { max-width:1100px; margin:0 auto; padding:24px; }
  .grid { display:grid; gap:20px; }
  .panel { background:var(--panel); border:1px solid var(--line);
           border-radius:12px; padding:18px; }
  h2 { font-size:14px; text-transform:uppercase; letter-spacing:.04em;
       color:var(--muted); margin:0 0 14px; }
  #drop { border:2px dashed var(--line); border-radius:12px; padding:36px;
          text-align:center; color:var(--muted); cursor:pointer; transition:.15s; }
  #drop.hot { border-color:var(--accent); background:#13243d; color:var(--fg); }
  #drop b { color:var(--fg); }
  .pipeline { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .stage { flex:1 1 120px; min-width:110px; padding:10px 12px; border-radius:10px;
           border:1px solid var(--line); background:#10161d; position:relative; }
  .stage .lbl { font-weight:600; }
  .stage .st { font-size:12px; color:var(--muted); margin-top:2px; }
  .stage.pending { opacity:.55; }
  .stage.active { border-color:var(--active); box-shadow:0 0 0 1px var(--active) inset; }
  .stage.active .st { color:var(--active); }
  .stage.done { border-color:var(--ok); }
  .stage.done .st { color:var(--ok); }
  .stage.error { border-color:var(--err); }
  .stage.error .st { color:var(--err); }
  pre#log { background:#0a0e12; border:1px solid var(--line); border-radius:10px;
            padding:12px; height:300px; overflow:auto; margin:0; white-space:pre-wrap;
            font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace; color:#c8d3de; }
  .tools { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:12px; }
  .tool { border:1px solid var(--line); border-radius:10px; padding:12px; background:#10161d; }
  .tool .tn { font-weight:600; display:flex; justify-content:space-between; gap:8px; }
  .tool .role { color:var(--muted); font-size:12px; }
  .tool dl { margin:10px 0 0; display:grid; grid-template-columns:auto 1fr; gap:2px 10px; }
  .tool dt { color:var(--muted); font-size:12px; }
  .tool dd { margin:0; font-size:12px; word-break:break-word; }
  .pill { font-size:11px; padding:1px 7px; border-radius:999px; border:1px solid var(--line); }
  .pill.fresh,.pill.active,.pill.ok { color:var(--ok); border-color:#1c3a24; }
  .pill.healthcheckonly,.pill.failed { color:var(--active); border-color:#3a3214; }
  button { font:inherit; border:1px solid var(--line); background:#1f2937; color:var(--fg);
           padding:9px 16px; border-radius:9px; cursor:pointer; }
  button:hover { border-color:var(--accent); }
  button:disabled { opacity:.5; cursor:not-allowed; }
  .row { display:flex; gap:12px; align-items:center; flex-wrap:wrap; }
  a { color:var(--accent); }
  .muted { color:var(--muted); }
  .tools-select { display:flex; gap:16px; flex-wrap:wrap; align-items:center; margin-top:12px; }
  .tools-select label { display:flex; gap:6px; align-items:center; cursor:pointer; }
  /* analysis map */
  #map { display:flex; align-items:center; gap:18px; flex-wrap:wrap; }
  .map-col { display:flex; flex-direction:column; gap:8px; }
  .map-node { padding:8px 12px; border:1px solid var(--line); border-radius:10px;
              background:#10161d; min-width:120px; text-align:center; font-size:13px; }
  .map-node .ms { font-size:11px; color:var(--muted); }
  .map-node.active { border-color:var(--active); box-shadow:0 0 0 1px var(--active) inset; }
  .map-node.active .ms { color:var(--active); }
  .map-node.done { border-color:var(--ok); } .map-node.done .ms { color:var(--ok); }
  .map-node.error { border-color:var(--err); } .map-node.error .ms { color:var(--err); }
  .map-node.skip { opacity:.45; }
  .map-arrow { color:var(--muted); font-size:20px; }
  iframe#report-frame { width:100%; height:600px; border:1px solid var(--line);
                        border-radius:10px; background:#fff; }
</style></head>
<body>
<header>
  <h1>el-sca-ansamble</h1>
  <span class="badge" id="upd-badge">обновление баз отключено по умолчанию</span>
  <span class="muted" style="margin-left:auto" id="conn"></span>
</header>
<main class="grid">
  <section class="panel">
    <h2>Анализ артефакта</h2>
    <div id="drop">
      <p><b>Перетащите сюда артефакт</b> (.tar.gz / .zip / .apk / .exe)<br>
      или нажмите, чтобы выбрать файл — анализ начнётся автоматически.</p>
      <input type="file" id="file" hidden>
    </div>
    <div class="tools-select" id="tools-select">
      <span class="muted">Инструменты:</span>
      <label><input type="checkbox" value="syft" checked> Syft (SBOM)</label>
      <label><input type="checkbox" value="grype" checked> Grype</label>
      <label><input type="checkbox" value="trivy" checked> Trivy</label>
      <label><input type="checkbox" value="cve-bin-tool" checked> cve-bin-tool</label>
    </div>
    <div class="row" id="ready-row" style="display:none; margin-top:12px">
      <span class="muted">Артефакт: <b id="ready-name"></b></span>
      <button id="btn-go">▶ Тулз ок, погнали</button>
      <span class="muted">— выбери инструменты выше и запускай</span>
    </div>
  </section>

  <section class="panel">
    <h2>Процесс анализа</h2>
    <div class="pipeline" id="pipeline"></div>
    <div class="row" style="margin:14px 0 10px">
      <strong id="job-status" class="muted">ожидание</strong>
    </div>
    <pre id="log">Лог появится здесь после запуска…</pre>
  </section>

  <section class="panel">
    <h2>Карта анализа</h2>
    <div id="map"></div>
  </section>

  <section class="panel" id="report-panel" style="display:none">
    <h2>Отчёт</h2>
    <iframe id="report-frame" title="report"></iframe>
  </section>

  <section class="panel">
    <h2>Базы инструментов</h2>
    <div class="row" style="margin-bottom:14px">
      <button id="btn-update">⟳ Обновить базы (разово)</button>
      <button id="btn-refresh">Обновить статус</button>
      <span class="muted">Скан использует уже скачанные базы и НЕ обновляет их.</span>
    </div>
    <div class="tools" id="tools"></div>
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
const logEl = $("#log"), pipeEl = $("#pipeline"), statusEl = $("#job-status"), connEl = $("#conn"), mapEl = $("#map");
let es = null;
let stagesByKey = {};

function renderStages(stages){
  pipeEl.innerHTML = "";
  (stages||[]).forEach(s => {
    const d = document.createElement("div");
    d.className = "stage " + (s.status||"pending");
    d.innerHTML = `<div class="lbl">${s.label}</div><div class="st">${s.status||"pending"}</div>`;
    pipeEl.appendChild(d);
  });
  stagesByKey = {}; (stages||[]).forEach(s => stagesByKey[s.key] = s.status||"pending");
  renderMap();
}
function mapNode(key, label){
  const st = stagesByKey[key] || "pending";
  return `<div class="map-node ${st}"><div>${label}</div><div class="ms">${st}</div></div>`;
}
function renderMap(){
  // Артефакт → Extract → веер инструментов → Отчёт
  mapEl.innerHTML =
    `<div class="map-col"><div class="map-node">Артефакт</div></div>` +
    `<div class="map-arrow">→</div>` +
    `<div class="map-col">${mapNode("extract","Extract")}</div>` +
    `<div class="map-arrow">→</div>` +
    `<div class="map-col">${mapNode("sbom","Syft")}${mapNode("grype","Grype")}${mapNode("trivy","Trivy")}${mapNode("cve-bin-tool","cve-bin-tool")}</div>` +
    `<div class="map-arrow">→</div>` +
    `<div class="map-col">${mapNode("report","Отчёт")}</div>`;
}
function showReport(){
  const f = $("#report-frame");
  f.src = "/api/report/index.html?t=" + Date.now();
  $("#report-panel").style.display = "";
}
renderMap();
function appendLog(line){
  if(line==null) return;
  const atBottom = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 4;
  logEl.textContent += (logEl.textContent ? "\\n" : "") + line;
  if(atBottom) logEl.scrollTop = logEl.scrollHeight;
}
function follow(jobId){
  if(es) es.close();
  logEl.textContent = "";
  statusEl.textContent = "выполняется…"; statusEl.className = "";
  es = new EventSource(`/api/jobs/${jobId}/stream`);
  connEl.textContent = "● подключено";
  es.onmessage = ev => {
    const m = JSON.parse(ev.data);
    if(m.type === "snapshot"){
      renderStages(m.stages); (m.log||[]).forEach(appendLog);
      statusEl.textContent = m.status;
    } else {
      if("line" in m) appendLog(m.line);
      if(m.stages) renderStages(m.stages);
      if(m.status) statusEl.textContent = m.status;
    }
    if(m.final || m.status === "done" || m.status === "error"){
      const ok = (m.returncode === 0) || m.status === "done";
      statusEl.textContent = ok ? "✓ готово" : "✗ ошибка";
      es.close(); connEl.textContent = "";
      loadTools();
      if(ok) showReport();
    }
  };
  es.onerror = () => { connEl.textContent = ""; };
}
let pendingFile = null;
function selectFile(file){
  pendingFile = file;
  $("#ready-name").textContent = file.name;
  $("#ready-row").style.display = "";
  $("#report-panel").style.display = "none";
  statusEl.textContent = "готов к запуску — выбери инструменты и нажми «погнали»";
  statusEl.className = "muted";
}
async function startScan(file){
  const tools = Array.from(document.querySelectorAll("#tools-select input:checked"))
    .map(c => c.value).join(",");
  const fd = new FormData(); fd.append("file", file); fd.append("tools", tools);
  statusEl.textContent = "загрузка артефакта…";
  $("#report-panel").style.display = "none";
  const r = await fetch("/api/scan", { method:"POST", body:fd });
  if(!r.ok){ statusEl.textContent = "ошибка запуска: " + r.status; return; }
  follow((await r.json()).job_id);
}
async function startUpdate(){
  const b = $("#btn-update"); b.disabled = true;
  const r = await fetch("/api/update-db", { method:"POST" });
  b.disabled = false;
  if(!r.ok){ statusEl.textContent = "ошибка обновления: " + r.status; return; }
  follow((await r.json()).job_id);
}
function fmtTime(t){
  if(!t) return "—";
  const d = new Date(t); return isNaN(d) ? t : d.toLocaleString();
}
async function loadTools(){
  const r = await fetch("/api/tools"); const data = await r.json();
  $("#upd-badge").textContent = data.db_update_enabled_by_default
    ? "обновление баз включено" : "обновление баз отключено по умолчанию";
  const box = $("#tools"); box.innerHTML = "";
  data.tools.forEach(t => {
    const st = (t.db_status||"—").replace(/[^a-z0-9]/gi,"");
    const el = document.createElement("div"); el.className = "tool";
    el.innerHTML = `
      <div class="tn"><span>${t.name}</span>
        <span class="pill ${st}">${t.db_status||"—"}</span></div>
      <div class="role">${t.role}</div>
      <dl>
        <dt>версия</dt><dd>${t.version||"—"}</dd>
        <dt>база обновлена</dt><dd>${fmtTime(t.db_updated)}</dd>
        <dt>детали</dt><dd>${t.detail||"—"}</dd>
      </dl>`;
    box.appendChild(el);
  });
}
const drop = $("#drop"), fileInput = $("#file");
drop.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", e => { if(e.target.files[0]) selectFile(e.target.files[0]); });
["dragenter","dragover"].forEach(ev => drop.addEventListener(ev, e => {
  e.preventDefault(); drop.classList.add("hot"); }));
["dragleave","drop"].forEach(ev => drop.addEventListener(ev, e => {
  e.preventDefault(); drop.classList.remove("hot"); }));
drop.addEventListener("drop", e => { const f = e.dataTransfer.files[0]; if(f) selectFile(f); });
$("#btn-go").addEventListener("click", () => { if(pendingFile) startScan(pendingFile); });
$("#btn-update").addEventListener("click", startUpdate);
$("#btn-refresh").addEventListener("click", loadTools);
loadTools();
</script>
</body></html>
"""


def render_gui() -> str:
    """Return the active dashboard GUI (drag-drop scan + pipeline + DB cards)."""
    return _GUI_HTML


def create_app(artifacts_dir: Path | str, repo_root: Path | str | None = None):
    """Build the FastAPI app: read-only run browser + active scan/update GUI.

    ``repo_root`` is where ``docker compose`` is invoked from (defaults to the
    parent of ``artifacts_dir``).  Scans and DB updates run as host
    subprocesses via :mod:`resilient_updates.orchestrator`.
    """
    from fastapi import FastAPI, File, Form, HTTPException
    from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse

    from .orchestrator import JobRegistry, sse_stream

    root = Path(artifacts_dir)
    rroot = Path(repo_root) if repo_root is not None else root.resolve().parent
    uploads = root / "uploads"
    registry = JobRegistry(rroot)

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

    @app.post("/api/scan", response_model=None)
    def scan(file: UploadFile = File(...), tools: str = Form("")) -> dict[str, str]:
        uploads.mkdir(parents=True, exist_ok=True)
        safe_name = Path(file.filename or "artifact").name
        dest = uploads / safe_name
        with dest.open("wb") as fh:
            while chunk := file.file.read(1024 * 1024):
                fh.write(chunk)
        # tools = comma-separated subset of syft,grype,trivy,cve-bin-tool; empty = all.
        selected = {t.strip() for t in tools.split(",") if t.strip()} or None
        job = registry.start_scan(str(dest.resolve()), tools=selected)
        return {"job_id": job.id, "target": str(dest)}

    @app.get("/api/report/{path:path}")
    def report_file(path: str):
        base = (root / "reports" / "final").resolve()
        target = (base / path).resolve()
        if base != target and base not in target.parents:
            raise HTTPException(status_code=400, detail="bad path")
        if not target.is_file():
            raise HTTPException(status_code=404, detail="report not found")
        return FileResponse(target)

    @app.post("/api/update-db")
    def update_db() -> dict[str, str]:
        job = registry.start_update()
        return {"job_id": job.id}

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

    return app
