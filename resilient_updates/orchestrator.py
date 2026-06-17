"""Host-side scan/update orchestration for the dashboard GUI (ADR-0006).

This module launches ``docker compose`` on the host, maps each profile's
services onto an ordered **stage pipeline**, streams log lines + stage
transitions to subscribers (the GUI consumes them over SSE), and writes
per-run checkpoints/snapshots.

Design notes
------------
* **Runs on the host**, not inside a container — it shells out to
  ``docker compose`` directly (the chosen architecture; no docker.sock mount).
* **DB updates are opt-in.** A scan uses only the ``scan`` profile and never
  refreshes databases; the explicit "update" job uses the ``update`` profile.
* The pure pieces — :func:`detect_service`, :func:`service_to_stage`, and the
  :class:`Job` state machine (``feed_line`` / ``finish``) — carry no docker
  dependency and are unit-tested without it.  Only :meth:`JobRegistry.start`
  spawns a subprocess.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from collections import deque
from collections.abc import Iterator
from pathlib import Path
from queue import Empty, Queue
from typing import Any, ClassVar

from . import pipeline_state
from .run_layout import resolve_run_dir, snapshot_artifacts, write_checkpoint


def _load_dotenv(env: dict[str, str], dotenv_path: Path) -> None:
    """Merge KEY=VALUE pairs from a ``.env`` file into *env*.

    Shell environment (already in *env* via ``os.environ``) takes priority —
    existing keys are never overwritten.  This makes proxy settings declared in
    ``.env`` visible to the orchestrator's auto-route logic, which otherwise only
    sees the shell environment (``os.environ``), while ``docker compose`` reads
    ``.env`` automatically.  Without this merge, a proxy configured only in
    ``.env`` is invisible to :meth:`JobRegistry._apply_auto_route`, causing the
    route-doctor to run unnecessarily and potentially write a conflicting plan.
    """
    try:
        for raw in dotenv_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            # Strip surrounding quotes (common in .env files: VAR="value")
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            if key and key not in env:  # shell env always wins
                env[key] = val
    except OSError:
        pass

# ── Stage pipelines ─────────────────────────────────────────────────────────
# Each entry: (stage_key, human_label, [compose service names feeding it]).
# Order is the visual left-to-right pipeline shown in the GUI.

SCAN_STAGES: list[tuple[str, str, list[str]]] = [
    ("extract", "Extract", ["artifact-extractor"]),
    ("sbom", "SBOM · Syft", ["syft-sbom"]),
    ("grype", "Grype", ["grype-static", "grype-db-importer", "grype-scanner"]),
    ("trivy", "Trivy", ["trivy-scanner"]),
    ("cve-bin-tool", "cve-bin-tool", ["cve-bin-tool-scanner"]),
    ("report", "Report", ["report-collector"]),
]

UPDATE_STAGES: list[tuple[str, str, list[str]]] = [
    ("trivy", "Trivy DB", ["trivy-updater"]),
    ("grype", "Grype DB", ["grype-updater", "grype-db-importer"]),
    ("cve-bin-tool", "cve-bin-tool DB", ["cve-bin-tool-updater"]),
    ("report", "Provenance", ["report-collector"]),
]

# compose v2 prefixes each line with "<service>-<replica>  | ...".  Capture the
# leading token before the pipe; the trailing "-<n>" replica index is stripped
# by detect_service().
_PREFIX_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*?)\s*\|")
_REPLICA_RE = re.compile(r"-\d+$")

# Download-progress parsing (drives the barrel fill while a DB downloads).
# Trivy prints "12.34 MiB / 95.30 MiB [bar] 12.95%"; we prefer the byte ratio
# (works even if the trailing % is missing) and fall back to a bare percent.
_SIZE_RE = re.compile(r"([\d.]+)\s*([KMG])i?B\s*/\s*([\d.]+)\s*([KMG])i?B")
_PCT_RE = re.compile(r"(\d{1,3}(?:\.\d+)?)\s*%")
_UNIT = {"K": 1.0, "M": 1024.0, "G": 1048576.0}


def parse_progress(line: str) -> float | None:
    """Return a 0-100 download percentage parsed from a log line, or None."""
    m = _SIZE_RE.search(line)
    if m:
        try:
            dl = float(m.group(1)) * _UNIT[m.group(2)]
            tot = float(m.group(3)) * _UNIT[m.group(4)]
            if tot > 0:
                return max(0.0, min(100.0, dl / tot * 100.0))
        except (ValueError, KeyError):  # pragma: no cover - defensive
            pass
    m = _PCT_RE.search(line)
    if m:
        try:
            return max(0.0, min(100.0, float(m.group(1))))
        except ValueError:  # pragma: no cover - defensive
            pass
    return None


def detect_service(line: str) -> str | None:
    """Return the compose service base name a log line was emitted by, or None.

    ``"syft-sbom-1  | scanning"`` → ``"syft-sbom"``.  Lines without a compose
    prefix (our own status lines, blank lines) return ``None``.
    """
    m = _PREFIX_RE.match(line)
    if not m:
        return None
    name = m.group("name")
    return _REPLICA_RE.sub("", name)


def service_to_stage(stages: list[tuple[str, str, list[str]]]) -> dict[str, str]:
    """Map every compose service name to its stage key for a given pipeline."""
    out: dict[str, str] = {}
    for key, _label, services in stages:
        for svc in services:
            out[svc] = key
    return out


def _initial_stage_list(stages: list[tuple[str, str, list[str]]]) -> list[dict[str, str]]:
    return [{"key": k, "label": label, "status": "pending"} for k, label, _ in stages]


# ── Job state machine ───────────────────────────────────────────────────────


class Job:
    """A single scan/update invocation and its live state.

    ``feed_line`` and ``finish`` are pure with respect to docker — feed them
    raw log lines (from a subprocess or a test) and the stage pipeline advances
    monotonically.  Subscribers receive a JSON snapshot on every change.
    """

    LOG_MAXLEN = 4000

    def __init__(
        self,
        kind: str,
        stages: list[tuple[str, str, list[str]]],
        target: str | None = None,
        *,
        artifacts_dir: Path | None = None,
        run_dir: Path | None = None,
    ):
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind  # "scan" | "update"
        self.target = target
        self.artifacts_dir = artifacts_dir
        self.run_dir = run_dir
        self.status = "running"  # running | done | error
        self.returncode: int | None = None
        self.started_at = time.time()
        self.finished_at: float | None = None
        self.stages = _initial_stage_list(stages)
        self._index = {k: i for i, (k, _l, _s) in enumerate(stages)}
        self._svc_to_stage = service_to_stage(stages)
        # Longest service name first so e.g. "grype-static" wins over a shorter
        # accidental substring; used by _resolve_stage for suffix matching.
        self._svc_pairs = sorted(self._svc_to_stage.items(), key=lambda kv: -len(kv[0]))
        self._max_index = -1
        # When the runner drives stages explicitly (begin_stage/end_stage),
        # feed_line must NOT also auto-advance from log prefixes.
        self._explicit = False
        self.log: deque[str] = deque(maxlen=self.LOG_MAXLEN)
        self._subscribers: list[Queue] = []
        self._lock = threading.Lock()
        # Last emitted download % per stage (throttles progress events).
        self._last_pct: dict[str, float] = {}
        # Optional on-disk transcript (set via attach_log).  Lines are flushed
        # immediately so a hung/stalled update still leaves a readable partial
        # log to hand off for analysis.
        self.log_path: Path | None = None
        self._log_fh: Any = None
        self._checkpoint_interval = max(
            60,
            int(os.environ.get("EL_SCA_CHECKPOINT_INTERVAL_SECONDS", "3600") or "3600"),
        )
        self._last_checkpoint_at = self.started_at

    # -- on-disk transcript -------------------------------------------------
    def attach_log(self, path: Path, header: list[str] | None = None) -> None:
        """Tee every log line to ``path`` (created/truncated).  Best-effort:
        a filesystem error never breaks the job, it just disables the file."""
        with self._lock:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                self._log_fh = path.open("w", encoding="utf-8")
                self.log_path = path
                for h in header or []:
                    self._log_fh.write(h + "\n")
                self._log_fh.flush()
            except Exception:  # pragma: no cover - defensive
                self._log_fh = None
                self.log_path = None

    def _write_log_locked(self, line: str) -> None:
        if self._log_fh is None:
            return
        try:
            self._log_fh.write(line + "\n")
            self._log_fh.flush()
        except Exception:  # pragma: no cover - defensive
            self._log_fh = None

    def _close_log_locked(self, footer: str | None = None) -> None:
        if self._log_fh is None:
            return
        try:
            if footer:
                self._log_fh.write(footer + "\n")
            self._log_fh.flush()
            self._log_fh.close()
        except Exception:  # pragma: no cover - defensive
            pass
        finally:
            self._log_fh = None

    # -- stage logic --------------------------------------------------------
    def _resolve_stage(self, svc: str) -> str | None:
        """Map a detected service token to a stage key.

        Tolerant of compose printing project-prefixed container names
        (``el-sca-ansamble-syft-sbom`` as well as plain ``syft-sbom``): an exact
        match wins, otherwise the longest known service name that ``svc`` ends
        with on a ``-`` boundary.
        """
        exact = self._svc_to_stage.get(svc)
        if exact is not None:
            return exact
        for name, key in self._svc_pairs:
            if svc == name or svc.endswith("-" + name):
                return key
        return None

    def _advance(self, stage_key: str) -> bool:
        idx = self._index.get(stage_key)
        if idx is None or idx < self._max_index:
            return False
        changed = False
        for i in range(idx):
            if self.stages[i]["status"] != "done":
                self.stages[i]["status"] = "done"
                changed = True
        if self.stages[idx]["status"] != "active":
            self.stages[idx]["status"] = "active"
            changed = True
        self._max_index = idx
        return changed

    def feed_line(self, line: str) -> None:
        line = line.rstrip("\r\n")
        # A progress-bar redraw (e.g. trivy's "X MiB / Y MiB ... NN%") would
        # flood the transcript, so keep those out of the log and only use them
        # to drive the live barrel fill.
        is_bar = _SIZE_RE.search(line) is not None
        pct = parse_progress(line) if not self._explicit else None
        with self._lock:
            if not is_bar:
                self.log.append(line)
                self._write_log_locked(line)
            stage_changed = False
            if not self._explicit and not is_bar:
                svc = detect_service(line)
                if svc is not None:
                    key = self._resolve_stage(svc)
                    if key is not None:
                        stage_changed = self._advance(key)
            progress = None
            if pct is not None and self._max_index >= 0:
                key = self.stages[self._max_index]["key"]
                last = self._last_pct.get(key)
                if last is None or abs(pct - last) >= 1.0 or pct >= 99.9:
                    self._last_pct[key] = pct
                    progress = (key, pct)
            self._publish_locked(
                line=(None if is_bar else line),
                include_state=stage_changed,
                progress=progress,
            )

    # -- explicit stage control (sequential runner) -------------------------
    def begin_stage(self, key: str) -> None:
        """Mark a stage active (and all earlier ones done).  Switches the job
        into explicit-stage mode so feed_line stops auto-detecting."""
        with self._lock:
            self._explicit = True
            idx = self._index.get(key)
            if idx is None:
                return
            for i in range(idx):
                if self.stages[i]["status"] not in ("done", "error"):
                    self.stages[i]["status"] = "done"
            if self.stages[idx]["status"] == "pending":
                self.stages[idx]["status"] = "active"
            self._publish_locked(line=None, include_state=True)

    def end_stage(self, key: str, ok: bool) -> None:
        with self._lock:
            idx = self._index.get(key)
            if idx is None:
                return
            self.stages[idx]["status"] = "done" if ok else "error"
            self._publish_locked(line=None, include_state=True)

    def finalize(self) -> None:
        """Terminal state for an explicitly-driven job (no single return code)."""
        with self._lock:
            self.finished_at = time.time()
            any_err = any(s["status"] == "error" for s in self.stages)
            self.status = "error" if any_err else "done"
            self.returncode = 1 if any_err else 0
            dur = self.finished_at - self.started_at
            self._close_log_locked(
                f"# --- finished status={self.status} rc={self.returncode} duration={dur:.1f}s"
            )
            self._publish_locked(line=None, include_state=True, final=True)

    def finish(self, returncode: int) -> None:
        with self._lock:
            self.returncode = returncode
            self.finished_at = time.time()
            if returncode == 0:
                self.status = "done"
                for s in self.stages:
                    s["status"] = "done"
            else:
                self.status = "error"
                for s in self.stages:
                    if s["status"] == "active":
                        s["status"] = "error"
            dur = self.finished_at - self.started_at
            self._close_log_locked(
                f"# --- finished status={self.status} rc={self.returncode} duration={dur:.1f}s"
            )
            self._publish_locked(line=None, include_state=True, final=True)

    # -- snapshot / pub-sub -------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return self._snapshot_locked()

    def _snapshot_locked(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "target": self.target,
            "status": self.status,
            "returncode": self.returncode,
            "stages": [dict(s) for s in self.stages],
            "log": list(self.log),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "run_dir": str(self.run_dir) if self.run_dir else "",
            "log_path": str(self.log_path) if self.log_path else "",
        }

    def subscribe(self) -> Queue[dict[str, Any] | None]:
        q: Queue = Queue()
        with self._lock:
            # Replay current state so a late subscriber is immediately caught up.
            q.put({"type": "snapshot", **self._snapshot_locked()})
            if self.status != "running":
                q.put(None)  # already finished → close immediately after replay
            else:
                self._subscribers.append(q)
        return q

    def _publish_locked(
        self,
        *,
        line: str | None,
        include_state: bool,
        final: bool = False,
        progress: tuple[str, float] | None = None,
    ) -> None:
        event: dict[str, Any] = {"type": "update"}
        if line is not None:
            event["line"] = line
        if progress is not None:
            event["progress"] = {"stage": progress[0], "pct": round(progress[1], 1)}
        if include_state:
            event["status"] = self.status
            event["stages"] = [dict(s) for s in self.stages]
        if final:
            event["final"] = True
            event["returncode"] = self.returncode
        dead: list[Queue] = []
        for q in self._subscribers:
            try:
                q.put(event)
                if final:
                    q.put(None)
            except Exception:  # pragma: no cover - defensive
                dead.append(q)
        if final:
            self._subscribers.clear()
        else:
            for q in dead:
                self._subscribers.remove(q)

    def current_stage_key(self) -> str | None:
        with self._lock:
            for stage in self.stages:
                if stage["status"] == "active":
                    return stage["key"]
            return None

    def maybe_periodic_checkpoint(self) -> None:
        if not self.run_dir or not self.artifacts_dir:
            return
        now = time.time()
        if now - self._last_checkpoint_at < self._checkpoint_interval:
            return
        self._last_checkpoint_at = now
        write_checkpoint(
            self.run_dir,
            stage=self.current_stage_key(),
            status=self.status,
            artifacts_dir=self.artifacts_dir,
        )


# ── Registry + subprocess launcher ──────────────────────────────────────────


def build_scan_command(profile: str = "scan", compose: list[str] | None = None) -> list[str]:
    base = compose or ["docker", "compose"]
    return [*base, "--profile", profile, "up", "--abort-on-container-exit"]


def build_update_command(compose: list[str] | None = None) -> list[str]:
    """Return a legacy ``compose up`` update command.

    .. deprecated::
        ``JobRegistry.start_update`` now issues sequential ``compose run --rm``
        steps instead of a single ``up --abort-on-container-exit``.  That avoids
        cascading aborts when a fast one-shot container (e.g. ``volume-init``)
        exits before the updaters finish.  This function is kept for external
        callers that probe the profile name, but is no longer used internally.
    """
    base = compose or ["docker", "compose"]
    # --force-recreate: never reuse an existing updater container.  A reused
    # container can carry a dead network-endpoint reference after a Docker
    # restart ("network <id> not found"), wedging every update; recreating it
    # fresh attaches it to the current network.
    return [*base, "--profile", "update", "up", "--abort-on-container-exit", "--force-recreate"]


class JobRegistry:
    """Owns running/finished jobs and launches the compose subprocesses."""

    def __init__(self, repo_root: Path, compose: list[str] | None = None):
        self.repo_root = Path(repo_root)
        self.compose = compose or ["docker", "compose"]
        self.artifacts_dir = self.repo_root / "artifacts"
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def _register(self, job: Job) -> None:
        with self._lock:
            self._jobs[job.id] = job

    def start_scan(self, target_host: str, tools: set[str] | None = None, *, resume: bool = False) -> Job:
        # tools = which analysers to run (subset of syft/grype/trivy/cve-bin-tool).
        # None = all enabled.  grype needs the SBOM, so syft is forced on with it.
        # resume = skip stages already completed for the SAME target+tools
        # (artifacts/pipeline_state.json — written by every previous run).
        # "auto" tries near-source (sibling dir named <pkg>-<timestamp>) when the
        # target path exists on disk; falls back to artifacts/runs/ otherwise.
        mode = os.environ.get("EL_SCA_RUN_OUTPUT_MODE", "auto")
        run_dir = resolve_run_dir(
            artifacts_dir=self.artifacts_dir,
            target_host=target_host,
            case_id=os.environ.get("CASE_ID"),
            mode=mode,
            timestamp=time.time(),
        )
        job = Job(
            "scan",
            SCAN_STAGES,
            target=target_host,
            artifacts_dir=self.artifacts_dir,
            run_dir=run_dir,
        )
        job.attach_log(
            run_dir / "job.log",
            header=[
                "# el-sca-ansamble scan log",
                f"# target : {target_host}",
                f"# run_dir: {run_dir}",
            ],
        )
        job.feed_line(f"# run artifacts -> {run_dir}")
        self._register(job)
        threading.Thread(
            target=self._run_scan,
            args=(job, target_host, tools),
            kwargs={"resume": resume},
            name=f"job-{job.id}",
            daemon=True,
        ).start()
        return job

    # cve-bin-tool DB is built from these sources (for per-source update buttons).
    CVEBT_SOURCES: ClassVar[list[str]] = ["NVD", "OSV", "GAD", "REDHAT", "CURL", "EPSS", "PURL2CPE", "RSD"]

    def start_update(self, target: str = "all") -> Job:
        """Run a DB update.  ``target`` selects scope:
        all | trivy | grype | cve-bin-tool | cve-bin-tool:<SOURCE>."""
        job = Job("update", UPDATE_STAGES)
        self._register(job)
        env = dict(os.environ)
        # Merge .env so proxy settings declared there are visible to _apply_auto_route.
        # docker compose reads .env automatically; the orchestrator process doesn't.
        # Without this merge a proxy in .env is invisible here → auto-route fires
        # unnecessarily and may write a conflicting route-plan that overrides .env.
        _load_dotenv(env, self.repo_root / ".env")
        # Compose interpolates the whole file (incl. the ${SCAN_TARGET_HOST:?}
        # guard on the scanner services) before selecting the `update` profile,
        # so set a harmless value — the update services don't read it.
        env.setdefault("SCAN_TARGET_HOST", "/tmp/el-sca-db-update-noscan")  # nosec B108
        env.setdefault("EXTRACT_INPUT_HOST", "/tmp/el-sca-db-update-noscan")  # nosec B108
        # trivy-updater interpolates ${TRIVY_RENDERED_FLAGS} from the environment
        # (the aquasec/trivy image has no python to render them); without it the
        # updater aborts with "TRIVY_RENDERED_FLAGS is required".
        if not env.get("TRIVY_RENDERED_FLAGS"):
            env["TRIVY_RENDERED_FLAGS"] = self._render_trivy_flags()

        compose = self.compose
        tgt = (target or "all").strip()
        job.target = tgt

        # Persistent transcript so updates can be handed off for analysis,
        # especially to tell whether a failure is proxy/VPN-related: the header
        # records the proxy + cve-bin-tool env that was in effect.
        ts = time.strftime("%Y%m%d-%H%M%S", time.localtime(job.started_at))
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", tgt) or "all"
        log_path = self.repo_root / "artifacts" / "db_status" / "updates" / f"{ts}_{safe}.log"
        job.attach_log(log_path, header=self._update_log_header(tgt, env))
        job.feed_line(f"# лог пишется в {log_path}")

        # Each updater runs as its own SEQUENTIAL `compose run --rm` step.
        # NOT `up --abort-on-container-exit` of the whole profile: that aborts
        # everything the moment ANY container exits — a fast one-shot
        # (stack-info/db-admin) or one failed updater used to SIGKILL the
        # long-running cve-bin-tool mid-download (exit 137).  Sequential steps
        # also remove the grype-updater↔grype-db-importer start race, and one
        # tool failing no longer cancels the others.
        run = [*compose, "--profile", "update", "run", "--rm"]
        if tgt == "trivy":
            steps = [("trivy", [*run, "trivy-updater"], None)]
        elif tgt == "grype":
            steps = [
                ("grype", [*run, "grype-updater"], None),
                # importer only makes sense after a successful updater step
                ("grype-import", [*run, "grype-db-importer"], "grype"),
            ]
        elif tgt == "cve-bin-tool":
            steps = [("cve-bin-tool", [*run, "cve-bin-tool-updater"], None)]
        elif tgt.startswith("cve-bin-tool:"):
            src = tgt.split(":", 1)[1].strip().upper()
            env["CVE_BIN_TOOL_DISABLE_SOURCES"] = " ".join(s for s in self.CVEBT_SOURCES if s != src)
            if src == "NVD":
                # The NVD-only dashboard button should stop after building the
                # feed-backed NVD candidate instead of falling into best-effort
                # enrichment for GAD/EPSS/RedHat/PURL2CPE.
                env["CVE_BIN_TOOL_FEED_ENRICH"] = "0"
            job.feed_line(f"cve-bin-tool: обновление только источника {src}")
            steps = [("cve-bin-tool", [*run, "cve-bin-tool-updater"], None)]
        else:  # "all" and anything unrecognised
            steps = [
                ("trivy", [*run, "trivy-updater"], None),
                ("grype", [*run, "grype-updater"], None),
                ("grype-import", [*run, "grype-db-importer"], "grype"),
                ("cve-bin-tool", [*run, "cve-bin-tool-updater"], None),
            ]
        self._spawn_update(job, steps, env)
        return job

    _AUTO_ROUTE_OFF = frozenset({"0", "false", "no", "off"})

    def _apply_auto_route(self, job: Job, env: dict[str, str]) -> None:
        """Discover a live egress (route-doctor) and merge its plan into *env*.

        Best-effort and additive (ADR-0007 P2): if the operator already pinned
        HTTP_PROXY/ALL_PROXY, or EL_SCA_AUTO_ROUTE=0, or the doctor yields no
        fresh plan — the environment is left untouched and the update proceeds
        exactly as before.  The doctor's output streams into the job log, so
        the dashboard shows WHY a route was (not) chosen.
        """
        if env.get("EL_SCA_AUTO_ROUTE", "1").strip().lower() in self._AUTO_ROUTE_OFF:
            return
        if env.get("HTTP_PROXY") or env.get("ALL_PROXY"):
            job.feed_line("# route: HTTP_PROXY/ALL_PROXY уже заданы — авто-маршрут пропущен")
            return
        job.feed_line("# route: ищу живой egress изнутри docker-сети (route-doctor)…")
        rc = self._run_stream(job, [*self.compose, "--profile", "route", "run", "--rm", "route-doctor"], env)
        plan_env = self.repo_root / "artifacts" / "route-plan.env"
        try:
            fresh = (time.time() - plan_env.stat().st_mtime) < 600
        except OSError:
            fresh = False
        if not fresh:
            # rc=2 with a fresh file = partial plan (still applied above); a
            # missing/stale file means nothing usable was discovered.
            job.feed_line(f"# route: свежего плана нет (rc={rc}) — обновление пойдёт напрямую/по .env")
            return
        applied: list[str] = []
        for raw in plan_env.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip()
            if val:
                env[key] = val
                if key in ("HTTP_PROXY", "ALL_PROXY", "CVE_BIN_TOOL_ENRICH_PROXY"):
                    applied.append(f"{key}={val}")
        job.feed_line("# route: применён план — " + ("; ".join(applied) or "direct (без прокси)"))

    def _normalise_volumes(self, job: Job, env: dict[str, str]) -> None:
        """Run the volume-init one-shot so updaters (appuser) can write.

        Docker creates named volumes root-owned; without this the appuser
        grype-updater dies with EACCES on `/var/lib/resilient-db/grype/tmp` and
        report-collector cannot overwrite a root-owned `artifacts/summary.json`.
        Run as a discrete `run --rm` step (NOT part of the `up`, whose
        `--abort-on-container-exit` would trip on this fast one-shot exiting).
        Best-effort: a failure is logged but the update still proceeds.
        """
        job.feed_line("# volinit: нормализую владельца томов (uid 1001)…")
        rc = self._run_stream(job, [*self.compose, "--profile", "volinit", "run", "--rm", "volume-init"], env)
        if rc != 0:
            job.feed_line(f"# volinit: WARN rc={rc} — возможны ошибки прав при обновлении")

    def _spawn_update(
        self, job: Job, steps: list[tuple[str, list[str], str | None]], env: dict[str, str]
    ) -> None:
        """Run update *steps* sequentially in a worker thread.

        Each step is ``(name, argv, requires)`` where ``requires`` names an
        earlier step that must have succeeded (e.g. grype-import needs grype).
        Before the steps: volume permissions are normalised and a working
        egress is discovered/applied (ADR-0007).  A failed step does NOT stop
        the remaining tools — the job fails at the end if anything failed.
        """

        def run() -> None:
            self._normalise_volumes(job, env)
            self._apply_auto_route(job, env)
            results: dict[str, int] = {}
            for name, cmd, requires in steps:
                if requires is not None and results.get(requires, 1) != 0:
                    job.feed_line(f"# {name}: пропущен — шаг '{requires}' не выполнился")
                    results[name] = 1
                    continue
                job.feed_line(f"# ── обновление: {name} ──")
                results[name] = self._run_stream(job, cmd, env)
                if results[name] != 0:
                    job.feed_line(f"# {name}: ОШИБКА rc={results[name]} — остальные шаги продолжаются")
            failed = [n for n, rc in results.items() if rc != 0]
            if failed:
                job.feed_line("# итог: не обновились — " + ", ".join(failed))
            else:
                job.feed_line("# итог: все запрошенные базы обновлены")
            job.finish(1 if failed else 0)

        threading.Thread(target=run, name=f"job-{job.id}", daemon=True).start()

    @staticmethod
    def _update_log_header(target: str, env: dict[str, str]) -> list[str]:
        """Diagnostic header for an update transcript: when, what, and the
        proxy/cve-bin-tool environment — enough to see at a glance whether a
        failure lines up with the VPN/proxy being off."""

        def show(name: str) -> str:
            return f"{name}={env.get(name, '') or '(unset)'}"

        return [
            "# el-sca-ansamble DB update log",
            f"# time   : {time.strftime('%Y-%m-%d %H:%M:%S %z')}",
            f"# target : {target}",
            "# --- proxy / VPN context ---",
            "# " + show("ALL_PROXY"),
            "# " + show("HTTP_PROXY"),
            "# " + show("HTTPS_PROXY"),
            "# " + show("NO_PROXY"),
            "# --- cve-bin-tool context ---",
            "# " + show("CVE_BIN_TOOL_UPDATE_MODES"),
            "# " + show("CVE_BIN_TOOL_DB_POLICY"),
            "# " + show("EL_SCA_SKIP_CVEBT"),
            "# " + ("NVD_API_KEY=set" if env.get("NVD_API_KEY") else "NVD_API_KEY=(unset)"),
            "# ----------------------------",
        ]

    def _run_stream(self, job: Job, cmd: list[str], env: dict[str, str]) -> int:
        """Run one command to completion, streaming stdout into the job log;
        return its exit code.  Never raises — a launch/read failure is reported
        in the log and surfaced as a non-zero code."""
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(self.repo_root),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                # Force UTF-8 + replacement: text=True would use the OS locale
                # (cp1252 on Windows) and a single non-cp1252 byte in buildkit
                # output would raise UnicodeDecodeError and kill the reader.
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except FileNotFoundError as exc:
            job.feed_line(f"ERROR: cannot launch {cmd[0]}: {exc}")
            return 127
        job.feed_line(f"$ {' '.join(cmd)}")
        # Liveness heartbeat: long stages (extraction of huge archives, the
        # cve-bin-tool pass) can be silent for many minutes.  If no output
        # arrived for EL_SCA_HEARTBEAT_SECONDS, emit a status line with the
        # elapsed time so the GUI/CLI never LOOK hung.  0 disables.
        try:
            heartbeat = int(os.environ.get("EL_SCA_HEARTBEAT_SECONDS", "10") or "10")
        except ValueError:
            heartbeat = 10
        started = time.time()
        last_output = [started]
        stop_hb = threading.Event()

        def _heartbeat() -> None:
            while not stop_hb.wait(timeout=max(1.0, min(heartbeat, 10.0))):
                quiet = time.time() - last_output[0]
                if quiet < heartbeat:
                    continue
                stage = job.current_stage_key() or job.kind
                elapsed = time.time() - started
                job.feed_line(
                    f"# … {stage}: ещё выполняется, прошло {elapsed:.0f}s "
                    f"(нет вывода {quiet:.0f}s — это нормально для длинных этапов)"
                )
                last_output[0] = time.time()

        hb_thread: threading.Thread | None = None
        if heartbeat > 0:
            hb_thread = threading.Thread(target=_heartbeat, name=f"hb-{job.id}", daemon=True)
            hb_thread.start()
        try:
            assert proc.stdout is not None
            # Split on BOTH \r and \n: download progress bars redraw the same
            # visual line with carriage returns, so a plain readline() would
            # deliver the whole bar as one chunk at the end (no live %).  We
            # read in chunks and emit each \r/\n-delimited segment, which lets
            # the dashboard fill the barrel as the DB downloads.
            buf = ""
            while True:
                chunk = proc.stdout.read(2048)
                if not chunk:
                    break
                last_output[0] = time.time()
                buf += chunk
                parts = re.split(r"[\r\n]", buf)
                buf = parts.pop()  # keep the last, possibly-incomplete segment
                for seg in parts:
                    if seg:
                        job.feed_line(seg)
                        job.maybe_periodic_checkpoint()
            if buf:
                job.feed_line(buf)
                job.maybe_periodic_checkpoint()
            proc.wait()
            return proc.returncode
        except Exception as exc:  # pragma: no cover - defensive
            job.feed_line(f"ERROR: stream read failed: {exc!r}")
            with contextlib.suppress(Exception):
                proc.kill()
            return 1
        finally:
            stop_hb.set()
            if hb_thread is not None:
                hb_thread.join(timeout=2)

    def _spawn(self, job: Job, cmd: list[str], env: dict[str, str]) -> None:
        """Run a single command in a thread and finish the job with its code."""

        def run() -> None:
            job.finish(self._run_stream(job, cmd, env))

        threading.Thread(target=run, name=f"job-{job.id}", daemon=True).start()

    def _extract_produced_output(self) -> bool:
        """True if the extractor's manifest reports a successful unpack (used to
        keep the extract stage green even when it exited non-zero on a member)."""
        import json

        mf = self.repo_root / "artifacts" / "extracted" / "current" / "extraction_manifest.json"
        try:
            data = json.loads(mf.read_text(encoding="utf-8"))
            return data.get("status") == "pass" or int(data.get("extracted_count") or 0) > 0
        except Exception:
            return False

    def _render_trivy_flags(self) -> str:
        """Render Trivy CLI flags on the host — the aquasec/trivy image has no
        python to render them itself (see scripts/update_trivy.sh)."""
        import sys

        try:
            out = subprocess.run(
                [sys.executable, "-m", "resilient_updates.cli", "render-flags", "trivy"],
                cwd=str(self.repo_root),
                capture_output=True,
                text=True,
                timeout=60,
            )
            if out.returncode == 0:
                return out.stdout.strip()
        except Exception:  # pragma: no cover - defensive
            pass
        return ""

    def _run_scan(
        self, job: Job, target_host: str, tools: set[str] | None = None, *, resume: bool = False
    ) -> None:
        """Extract → re-point the target to artifacts/extracted/current → run
        each scanner stage sequentially → aggregate the report.

        Mirrors scripts/run-scan.sh: the uploaded artifact is unpacked first and
        the scanners are pointed at the EXTRACTED contents.  Without this, the
        scanners look at the raw archive, Syft catalogs 0 components, and every
        tool reports nothing.

        With ``resume=True`` stages already completed for the same target+tools
        (pipeline_state.json) are skipped, so a hung/interrupted scan restarts
        from its last checkpoint instead of from zero.
        """
        compose = self.compose
        extracted_host = str((self.repo_root / "artifacts" / "extracted" / "current").resolve())
        self._copy_input_to_run(job, target_host)
        self._checkpoint(job, "start", "running")

        # Shared checkpoint state (same file the CLI runner uses) — powers
        # --resume and the monitor for dashboard-launched scans too.
        tool_key = ",".join(sorted(tools)) if tools else "all"
        state = pipeline_state.begin_run(
            self.artifacts_dir,
            target=target_host,
            tool=tool_key,
            case_id=os.environ.get("CASE_ID"),
            resume=resume,
        )
        skip_done = pipeline_state.completed_stages(state) if resume and state.get("resumed") else set()
        if skip_done:
            job.feed_line("# resume: пропускаю завершённые этапы — " + ", ".join(sorted(skip_done)))

        # Pre-create REPORT dirs on the host so a root-running scanner can't
        # leave a dir the (uid 1001) report-collector then can't write to.
        # NB: do NOT pre-create extracted/current — the extractor cleans/owns it
        # itself, and a host-owned dir there makes it exit non-zero.
        for _sub in ("reports/grype", "reports/trivy", "reports/cve-bin-tool", "reports/final", "sbom"):
            (self.repo_root / "artifacts" / _sub).mkdir(parents=True, exist_ok=True)
        # Clear stale extraction output before each run.  A leftover
        # extracted/current (e.g. created by an earlier host process, or owned by
        # a different container uid) makes the in-container extractor fail with
        # "Permission denied".  The host can always delete it; the extractor then
        # re-creates it fresh.
        _cur = self.repo_root / "artifacts" / "extracted" / "current"
        # On resume the already-extracted tree IS the checkpoint — keep it
        # (only when its manifest is still in place, otherwise re-extract).
        resume_extract = "extract" in skip_done and self._extract_produced_output()
        if _cur.exists() and not resume_extract:
            shutil.rmtree(_cur, ignore_errors=True)
        # Trivy's image has no python -> render its flags on the host (run-scan.sh).
        trivy_flags = self._render_trivy_flags()

        # Stage 1 — extract.
        job.begin_stage("extract")
        if resume_extract:
            job.feed_line("extract: пропущен — распакованное дерево уже на месте (чекпоинт)")
            pipeline_state.stage_skip(self.artifacts_dir, "extract")
            job.end_stage("extract", True)
        else:
            pipeline_state.stage_start(self.artifacts_dir, "extract")
            ex_env = dict(os.environ)
            ex_env["SCAN_TARGET_HOST"] = target_host  # satisfies the :? guard
            ex_env["EXTRACT_INPUT_HOST"] = target_host
            ex_env["EXTRACT_OUTPUT"] = "/workspace/artifacts/extracted/current"
            rc = self._run_stream(
                job,
                # -u 0: run as root so the extractor can always write into the
                # bind-mounted artifacts/ (and overwrite any stale root-owned file).
                [*compose, "--profile", "extract", "run", "--rm", "-u", "0", "artifact-extractor"],
                ex_env,
            )
            # The extractor can exit non-zero on a single unreadable member while
            # still unpacking everything useful; treat it as OK if the manifest says
            # so, otherwise the whole scan would go red over one skipped file.
            extract_ok = rc == 0 or self._extract_produced_output()
            if extract_ok and rc != 0:
                job.feed_line("extract: предупреждения, но содержимое распаковано — продолжаем")
            job.end_stage("extract", extract_ok)
            pipeline_state.stage_end(self.artifacts_dir, "extract", ok=extract_ok, rc=rc)
            self._checkpoint(job, "extract", "done" if extract_ok else "error")

        # Re-point every scanner at the extracted directory.
        sc_env = dict(os.environ)
        _load_dotenv(sc_env, self.repo_root / ".env")
        sc_env["SCAN_TARGET_HOST"] = extracted_host
        sc_env["EXTRACT_INPUT_HOST"] = extracted_host
        sc_env["SYFT_TARGET"] = "/scan-target"
        sc_env["SYFT_FROM"] = "dir"
        sc_env["CVE_BIN_TOOL_TARGET"] = "/scan-target"
        # Trivy defaults to scanning "alpine:latest"; point it at the artifact.
        sc_env["TRIVY_TARGET"] = "/scan-target"

        # Which analysers to run.  Default = all; EL_SCA_SKIP_CVEBT drops
        # cve-bin-tool.  Grype consumes the Syft SBOM, so syft is forced on with it.
        enabled = set(tools) if tools else {"syft", "grype", "trivy", "cve-bin-tool"}
        if os.environ.get("EL_SCA_SKIP_CVEBT", "").strip().lower() not in ("", "0", "false", "no"):
            enabled.discard("cve-bin-tool")
        if "grype" in enabled:
            enabled.add("syft")
        stage_tool = {"sbom": "syft", "grype": "grype", "trivy": "trivy", "cve-bin-tool": "cve-bin-tool"}

        # (stage key, compose service, exit codes treated as success)
        stages = [
            ("sbom", "syft-sbom", {0}),
            ("grype", "grype-scanner", {0}),
            ("trivy", "trivy-scanner", {0}),
            # cve-bin-tool exits 1 when it FINDS CVEs — success, not failure.
            ("cve-bin-tool", "cve-bin-tool-scanner", {0, 1}),
            ("report", "report-collector", {0}),
        ]
        for key, service, ok_codes in stages:
            job.begin_stage(key)
            tool = stage_tool.get(key)
            if tool is not None and tool not in enabled:
                job.feed_line(f"{key}: пропущен (инструмент отключён)")
                job.end_stage(key, True)
                continue
            # report is never skipped on resume: it is cheap and re-aggregates
            # whatever the (partially skipped) scanners left in artifacts/.
            if key in skip_done and key != "report":
                job.feed_line(f"{key}: пропущен — уже выполнен (чекпоинт, resume)")
                pipeline_state.stage_skip(self.artifacts_dir, key)
                job.end_stage(key, True)
                continue
            pipeline_state.stage_start(self.artifacts_dir, key)
            run_cmd = [*compose, "--profile", "scan", "run", "--rm"]
            if service == "trivy-scanner":
                run_cmd += ["-e", f"TRIVY_RENDERED_FLAGS={trivy_flags}"]
            if service == "report-collector":
                # Run as root so it can always write into the bind-mounted
                # artifacts/ (scanners run as root and may own report dirs).
                run_cmd += ["-u", "0"]
            run_cmd.append(service)
            rc = self._run_stream(job, run_cmd, sc_env)
            job.end_stage(key, rc in ok_codes)
            pipeline_state.stage_end(self.artifacts_dir, key, ok=rc in ok_codes, rc=rc)
            self._checkpoint(job, key, "done" if rc in ok_codes else "error")

        self._checkpoint(job, "final", "done")
        # Stop the lingering grype-static dependency container (best effort).
        self._run_stream(job, [*compose, "--profile", "scan", "down", "--remove-orphans"], sc_env)
        job.finalize()
        pipeline_state.finish_run(self.artifacts_dir, status=job.status)

    def _copy_input_to_run(self, job: Job, target_host: str) -> None:
        if not job.run_dir:
            return
        target = Path(target_host)
        if not target.is_file():
            return
        try:
            dest = job.run_dir / "input" / target.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, dest)
        except Exception as exc:  # pragma: no cover - defensive
            job.feed_line(f"WARN: input snapshot failed: {exc!r}")

    def _checkpoint(self, job: Job, stage: str, status: str) -> None:
        if not job.run_dir:
            return
        try:
            snapshot_artifacts(
                self.artifacts_dir,
                job.run_dir,
                case_id=os.environ.get("CASE_ID"),
                target_host=job.target,
                target_container="/scan-target",
                stage=stage,
                status=status,
            )
            job.feed_line(f"checkpoint {stage}:{status} -> {job.run_dir / 'checkpoint.json'}")
        except Exception as exc:  # pragma: no cover - defensive
            job.feed_line(f"WARN: checkpoint failed: {exc!r}")


def sse_stream(job: Job, poll_timeout: float = 1.0) -> Iterator[str]:
    """Yield Server-Sent-Events frames for a job until it finishes.

    Heartbeats (SSE comment lines) keep the connection alive between updates.
    """
    q = job.subscribe()
    while True:
        try:
            event = q.get(timeout=poll_timeout)
        except Empty:
            yield ": keep-alive\n\n"
            continue
        if event is None:
            break
        yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
