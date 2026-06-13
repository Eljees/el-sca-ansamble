"""Per-pipeline checkpoint state shared by the CLI runner and the dashboard.

Long artifact scans (extraction of multi-GB archives, cve-bin-tool passes)
can run for hours.  This module persists a small ``artifacts/pipeline_state.json``
after every stage transition so that:

* an interrupted/hung run can be **resumed from the last completed stage**
  (``run-scan.sh --resume`` / dashboard "продолжить с чекпоинта");
* the monitor (CLI ``monitor`` subcommand, dashboard ``/api/monitor``, MCP)
  can show what the pipeline is doing right now and for how long.

The state is keyed by ``run_key`` — a digest of the target path + tool
selection — so a resume against a *different* target never skips stages.

All writes are atomic (tmp + replace) and best-effort: a filesystem error
must never break the pipeline itself.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

try:
    from datetime import UTC  # py3.11+
except ImportError:  # pragma: no cover - py3.10 fallback
    from datetime import timezone as _tz

    UTC = _tz.utc  # noqa: UP017
from datetime import datetime

STATE_FILENAME = "pipeline_state.json"
SCHEMA_VERSION = 1

#: Canonical stage order of the full pipeline (mirrors run-scan.sh and
#: orchestrator.SCAN_STAGES).  Unknown stages are appended as they appear.
KNOWN_STAGES = ("extract", "sbom", "grype", "trivy", "cve-bin-tool", "report")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def state_path(artifacts_dir: str | Path) -> Path:
    return Path(artifacts_dir) / STATE_FILENAME


def compute_run_key(target: str, tool: str = "all", extra: str = "") -> str:
    """Stable digest identifying *this* pipeline configuration.

    Only inputs that change WHAT the stages produce participate: the resolved
    target path, the tool selection, and free-form ``extra`` (e.g. ``sbom-scan``).
    """
    blob = "\x00".join((os.path.normcase(str(target)), tool or "all", extra or ""))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def load_state(artifacts_dir: str | Path) -> dict[str, Any] | None:
    try:
        return json.loads(state_path(artifacts_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write_state(artifacts_dir: str | Path, state: dict[str, Any]) -> None:
    """Atomic, best-effort persist."""
    path = state_path(artifacts_dir)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".pipeline_state.", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh, indent=2, ensure_ascii=False, sort_keys=True)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):  # replace failed → don't leave litter
                with contextlib.suppress(OSError):  # pragma: no cover - defensive
                    os.unlink(tmp)
    except OSError:  # pragma: no cover - state must never break the pipeline
        pass


def begin_run(
    artifacts_dir: str | Path,
    *,
    target: str,
    tool: str = "all",
    case_id: str | None = None,
    extra: str = "",
    resume: bool = False,
) -> dict[str, Any]:
    """Start (or resume) a pipeline run; returns the persisted state.

    With ``resume=True`` and a matching ``run_key``, previously completed
    stages are kept so :func:`completed_stages` can skip them.  Any mismatch
    (different target/tool, incompatible schema_version, no previous state)
    silently degrades to a fresh run — resuming must never poison a scan of
    a different artifact or misparse a stale file format.
    """
    run_key = compute_run_key(target, tool, extra)
    prev = load_state(artifacts_dir) if resume else None
    if (
        prev is not None
        and prev.get("run_key") == run_key
        and prev.get("schema_version") == SCHEMA_VERSION
    ):
        state = prev
        state["resumed"] = True
        state["status"] = "running"
        state["updated_utc"] = _now_iso()
        # error/active stages must re-run; only "done" survives a resume.
        for info in state.get("stages", {}).values():
            if info.get("status") != "done":
                info["status"] = "pending"
    else:
        state = {
            "schema_version": SCHEMA_VERSION,
            "run_key": run_key,
            "target": str(target),
            "tool": tool or "all",
            "case_id": case_id or "",
            "extra": extra or "",
            "status": "running",
            "resumed": False,
            "started_utc": _now_iso(),
            "started_ts": time.time(),
            "updated_utc": _now_iso(),
            "stages": {},
        }
    if case_id:
        state["case_id"] = case_id
    _write_state(artifacts_dir, state)
    return state


def _touch_stage(state: dict[str, Any], stage: str) -> dict[str, Any]:
    stages = state.setdefault("stages", {})
    return stages.setdefault(stage, {"status": "pending"})


def stage_start(artifacts_dir: str | Path, stage: str) -> dict[str, Any] | None:
    state = load_state(artifacts_dir)
    if state is None:
        return None
    info = _touch_stage(state, stage)
    info["status"] = "active"
    info["started_utc"] = _now_iso()
    info["started_ts"] = time.time()
    state["current_stage"] = stage
    state["updated_utc"] = _now_iso()
    _write_state(artifacts_dir, state)
    return state


def stage_end(
    artifacts_dir: str | Path, stage: str, *, ok: bool, rc: int | None = None
) -> dict[str, Any] | None:
    state = load_state(artifacts_dir)
    if state is None:
        return None
    info = _touch_stage(state, stage)
    info["status"] = "done" if ok else "error"
    info["finished_utc"] = _now_iso()
    if rc is not None:
        info["rc"] = rc
    started = info.get("started_ts")
    if isinstance(started, (int, float)):
        info["duration_s"] = round(time.time() - started, 1)
    if state.get("current_stage") == stage:
        state["current_stage"] = None
    state["updated_utc"] = _now_iso()
    _write_state(artifacts_dir, state)
    return state


def stage_skip(artifacts_dir: str | Path, stage: str) -> dict[str, Any] | None:
    """Record that a stage was skipped thanks to a checkpoint (kept as done)."""
    state = load_state(artifacts_dir)
    if state is None:
        return None
    info = _touch_stage(state, stage)
    if info.get("status") != "done":  # pragma: no cover - defensive
        info["status"] = "done"
    info["skipped_via_resume"] = True
    state["updated_utc"] = _now_iso()
    _write_state(artifacts_dir, state)
    return state


def finish_run(artifacts_dir: str | Path, *, status: str = "done") -> dict[str, Any] | None:
    state = load_state(artifacts_dir)
    if state is None:
        return None
    state["status"] = status
    state["current_stage"] = None
    state["finished_utc"] = _now_iso()
    state["updated_utc"] = _now_iso()
    _write_state(artifacts_dir, state)
    return state


def completed_stages(state: dict[str, Any] | None) -> set[str]:
    if not state:
        return set()
    return {name for name, info in (state.get("stages") or {}).items() if info.get("status") == "done"}


def should_skip(
    artifacts_dir: str | Path, stage: str, *, target: str, tool: str = "all", extra: str = ""
) -> bool:
    """True when *stage* already completed for the SAME run configuration."""
    state = load_state(artifacts_dir)
    if state is None or state.get("run_key") != compute_run_key(target, tool, extra):
        return False
    return stage in completed_stages(state)


def summarize(state: dict[str, Any] | None) -> dict[str, Any]:
    """Compact, display-ready view of a state file (for monitor/GUI)."""
    if not state:
        return {"present": False}
    stages_in = state.get("stages") or {}
    order = [s for s in KNOWN_STAGES if s in stages_in]
    order += [s for s in stages_in if s not in order]
    stages_out = []
    now = time.time()
    for name in order:
        info = stages_in.get(name) or {}
        entry: dict[str, Any] = {"stage": name, "status": info.get("status", "pending")}
        if "duration_s" in info:
            entry["duration_s"] = info["duration_s"]
        elif info.get("status") == "active" and isinstance(info.get("started_ts"), (int, float)):
            entry["elapsed_s"] = round(now - info["started_ts"], 1)
        if "rc" in info:
            entry["rc"] = info["rc"]
        if info.get("skipped_via_resume"):
            entry["skipped_via_resume"] = True
        stages_out.append(entry)
    out: dict[str, Any] = {
        "present": True,
        "status": state.get("status"),
        "target": state.get("target"),
        "tool": state.get("tool"),
        "case_id": state.get("case_id"),
        "run_key": state.get("run_key"),
        "resumed": bool(state.get("resumed")),
        "current_stage": state.get("current_stage"),
        "started_utc": state.get("started_utc"),
        "updated_utc": state.get("updated_utc"),
        "stages": stages_out,
    }
    started = state.get("started_ts")
    if state.get("status") == "running" and isinstance(started, (int, float)):
        out["elapsed_s"] = round(now - started, 1)
    return out
