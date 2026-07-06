"""Stack monitor: container status + pipeline progress in one view.

Answers "что сейчас происходит и не повисло ли" without digging in docker
or log files by hand.  Three consumers share :func:`gather_status`:

* CLI — ``python -m resilient_updates.cli monitor [--watch N] [--json]``
* dashboard — ``GET /api/monitor`` (the GUI's «Монитор» panel)
* MCP bridge — the ``monitor`` tool

Pure helpers (:func:`summarize_db_status`, :func:`render_text`) carry no
docker dependency and are unit-tested directly; only :func:`list_containers`
shells out (and degrades to an explanatory error when docker is absent).
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - fixed argv, no shell
from pathlib import Path
from typing import Any

from .pipeline_state import load_state, summarize

_PS_TIMEOUT = 30
_LOG_TAIL_LINES = 12


def list_containers(repo_root: str | Path) -> dict[str, Any]:
    """``docker compose ps`` as structured data (best-effort)."""
    cmd = ["docker", "compose", "ps", "-a", "--format", "json"]
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv, validated cwd
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=_PS_TIMEOUT,
        )
    except FileNotFoundError:
        return {"ok": False, "error": "docker not found on PATH", "containers": []}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"docker compose ps timed out ({_PS_TIMEOUT}s)", "containers": []}
    if proc.returncode != 0:
        return {
            "ok": False,
            "error": (proc.stderr or proc.stdout or "").strip()[-400:],
            "containers": [],
        }
    containers: list[dict[str, Any]] = []
    # compose v2 prints one JSON object per line (or a JSON array on old builds).
    text = proc.stdout.strip()
    if text.startswith("["):
        try:
            containers = [c for c in json.loads(text) if isinstance(c, dict)]
        except ValueError:
            containers = []
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                containers.append(obj)
    slim = [
        {
            "name": c.get("Name") or c.get("name"),
            "service": c.get("Service") or c.get("service"),
            "state": c.get("State") or c.get("state"),
            "status": c.get("Status") or c.get("status"),
            "health": c.get("Health") or c.get("health") or "",
        }
        for c in containers
    ]
    return {"ok": True, "containers": slim}


def summarize_db_status(artifacts_dir: str | Path) -> list[dict[str, Any]]:
    """Cached per-tool DB freshness from ``artifacts/db_status/*.json``."""
    out: list[dict[str, Any]] = []
    db_dir = Path(artifacts_dir) / "db_status"
    if not db_dir.is_dir():
        return out
    for path in sorted(db_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        out.append(
            {
                "tool": data.get("tool") or path.stem,
                "exists": data.get("exists"),
                "age_hours": data.get("age_hours"),
                "status": data.get("status") or data.get("freshness"),
            }
        )
    return out


def tail_log(artifacts_dir: str | Path, lines: int = _LOG_TAIL_LINES) -> list[str]:
    log = Path(artifacts_dir) / "run-scan.log"
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [ln.rstrip() for ln in text.splitlines()[-lines:]]


def latest_run_snapshot(artifacts_dir: str | Path) -> dict[str, Any] | None:
    """Newest saved run snapshot under ``artifacts/runs``.

    Near-source snapshots intentionally live outside ``artifacts/`` and cannot
    be discovered globally; dashboard-launched and POSIX/PowerShell fallback
    snapshots under ``artifacts/runs`` are listed here for the monitor panel.
    """
    runs_root = Path(artifacts_dir) / "runs"
    if not runs_root.is_dir():
        return None
    candidates = [p for p in runs_root.iterdir() if p.is_dir()]
    if not candidates:
        return None
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    checkpoint = latest / "checkpoint.json"
    manifest = latest / "MANIFEST.json"
    try:
        checkpoint_data = json.loads(checkpoint.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        checkpoint_data = None
    try:
        manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest_data = None
    return {
        "id": latest.name,
        "path": str(latest),
        "checkpoint": checkpoint_data,
        "manifest_present": manifest_data is not None,
        "updated_at_utc": (checkpoint_data or {}).get("updated_at_utc")
        if isinstance(checkpoint_data, dict)
        else None,
    }


def gather_status(artifacts_dir: str | Path, repo_root: str | Path | None = None) -> dict[str, Any]:
    """One self-contained snapshot for every monitor consumer."""
    artifacts = Path(artifacts_dir)
    root = Path(repo_root) if repo_root is not None else artifacts.resolve().parent
    return {
        "pipeline": summarize(load_state(artifacts)),
        "containers": list_containers(root),
        "db_status": summarize_db_status(artifacts),
        "log_tail": tail_log(artifacts),
        "latest_run": latest_run_snapshot(artifacts),
    }


_STATE_ICON = {
    "running": "▶",
    "exited": "■",
    "created": "·",
    "paused": "⏸",
    "dead": "✗",
    "restarting": "↻",
}
_STAGE_ICON = {"done": "✓", "active": "▶", "error": "✗", "pending": "·"}


def render_text(status: dict[str, Any]) -> str:
    """Human-readable monitor screen (plain text, no curses)."""
    lines: list[str] = []
    pipe = status.get("pipeline") or {}
    lines.append("── Пайплайн ──────────────────────────────────")
    if not pipe.get("present"):
        lines.append("  нет активного/последнего прогона (pipeline_state.json отсутствует)")
    else:
        head = f"  {pipe.get('status', '?')}"
        if pipe.get("current_stage"):
            head += f" · этап: {pipe['current_stage']}"
        if pipe.get("elapsed_s") is not None:
            head += f" · {pipe['elapsed_s']:.0f}s"
        if pipe.get("resumed"):
            head += " · (продолжен с чекпоинта)"
        lines.append(head)
        if pipe.get("target"):
            lines.append(f"  target: {pipe['target']}")
        for st in pipe.get("stages") or []:
            icon = _STAGE_ICON.get(st.get("status", "pending"), "?")
            extra = ""
            if st.get("duration_s") is not None:
                extra = f" {st['duration_s']:.0f}s"
            elif st.get("elapsed_s") is not None:
                extra = f" …{st['elapsed_s']:.0f}s"
            if st.get("skipped_via_resume"):
                extra += " (skip:checkpoint)"
            lines.append(f"   {icon} {st['stage']}{extra}")

    lines.append("── Контейнеры ────────────────────────────────")
    cont = status.get("containers") or {}
    if not cont.get("ok"):
        lines.append(f"  docker недоступен: {cont.get('error', '?')}")
    elif not cont.get("containers"):
        lines.append("  контейнеры стека не запущены")
    else:
        for c in cont["containers"]:
            icon = _STATE_ICON.get(str(c.get("state") or "").lower(), "?")
            health = f" [{c['health']}]" if c.get("health") else ""
            lines.append(f"   {icon} {c.get('service') or c.get('name')}: {c.get('status')}{health}")

    db = status.get("db_status") or []
    if db:
        lines.append("── Базы ──────────────────────────────────────")
        for d in db:
            age = f"{d['age_hours']:.1f}h" if isinstance(d.get("age_hours"), (int, float)) else "?"
            lines.append(f"   {d['tool']}: {d.get('status') or '?'} · возраст {age}")

    tail = status.get("log_tail") or []
    if tail:
        lines.append("── Лог (хвост) ───────────────────────────────")
        lines.extend(f"   {ln}" for ln in tail)
    latest = status.get("latest_run")
    if latest:
        lines.append("── Последний snapshot ────────────────────────")
        lines.append(f"   {latest.get('id')}: {latest.get('path')}")
        chk = latest.get("checkpoint") if isinstance(latest, dict) else None
        if isinstance(chk, dict):
            lines.append(
                f"   stage={chk.get('stage')} status={chk.get('status')} updated={chk.get('updated_at_utc')}"
            )
    return "\n".join(lines)
