"""Host-side scan/update orchestration for the dashboard GUI (ADR-0008).

The read-only dashboard (``dashboard.py``) only *reads* ``artifacts/``.  This
module adds the *active* half: it launches ``docker compose`` on the host,
maps each profile's services onto an ordered **stage pipeline**, and streams
log lines + stage transitions to subscribers (the GUI consumes them over SSE).

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
import subprocess
import threading
import time
import uuid
from collections import deque
from collections.abc import Iterator
from pathlib import Path
from queue import Empty, Queue
from typing import Any

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

    def __init__(self, kind: str, stages: list[tuple[str, str, list[str]]], target: str | None = None):
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind  # "scan" | "update"
        self.target = target
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
        line = line.rstrip("\n")
        with self._lock:
            self.log.append(line)
            stage_changed = False
            if not self._explicit:
                svc = detect_service(line)
                if svc is not None:
                    key = self._resolve_stage(svc)
                    if key is not None:
                        stage_changed = self._advance(key)
            self._publish_locked(line=line, include_state=stage_changed)

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

    def _publish_locked(self, *, line: str | None, include_state: bool, final: bool = False) -> None:
        event: dict[str, Any] = {"type": "update"}
        if line is not None:
            event["line"] = line
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


# ── Registry + subprocess launcher ──────────────────────────────────────────


def build_scan_command(profile: str = "scan", compose: list[str] | None = None) -> list[str]:
    base = compose or ["docker", "compose"]
    return [*base, "--profile", profile, "up", "--abort-on-container-exit"]


def build_update_command(compose: list[str] | None = None) -> list[str]:
    base = compose or ["docker", "compose"]
    return [*base, "--profile", "update", "up", "--abort-on-container-exit"]


class JobRegistry:
    """Owns running/finished jobs and launches the compose subprocesses."""

    def __init__(self, repo_root: Path, compose: list[str] | None = None):
        self.repo_root = Path(repo_root)
        self.compose = compose or ["docker", "compose"]
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def _register(self, job: Job) -> None:
        with self._lock:
            self._jobs[job.id] = job

    def start_scan(self, target_host: str, tools: set[str] | None = None) -> Job:
        # tools = which analysers to run (subset of syft/grype/trivy/cve-bin-tool).
        # None = all enabled.  grype needs the SBOM, so syft is forced on with it.
        job = Job("scan", SCAN_STAGES, target=target_host)
        self._register(job)
        threading.Thread(
            target=self._run_scan, args=(job, target_host, tools),
            name=f"job-{job.id}", daemon=True,
        ).start()
        return job

    def start_update(self) -> Job:
        job = Job("update", UPDATE_STAGES)
        self._register(job)
        env = dict(os.environ)
        # Compose interpolates the whole file (incl. the ${SCAN_TARGET_HOST:?}
        # guard on the scanner services) before selecting the `update` profile,
        # so set a harmless value — the update services don't read it.
        env.setdefault("SCAN_TARGET_HOST", "/tmp/el-sca-db-update-noscan")  # nosec B108
        env.setdefault("EXTRACT_INPUT_HOST", "/tmp/el-sca-db-update-noscan")  # nosec B108
        cmd = build_update_command(self.compose)
        self._spawn(job, cmd, env)
        return job

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
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                job.feed_line(line)
            proc.wait()
            return proc.returncode
        except Exception as exc:  # pragma: no cover - defensive
            job.feed_line(f"ERROR: stream read failed: {exc!r}")
            with contextlib.suppress(Exception):
                proc.kill()
            return 1

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

    def _run_scan(self, job: Job, target_host: str, tools: set[str] | None = None) -> None:
        """Extract → re-point the target to artifacts/extracted/current → run
        each scanner stage sequentially → aggregate the report.

        Mirrors scripts/run-scan.sh: the uploaded artifact is unpacked first and
        the scanners are pointed at the EXTRACTED contents.  Without this, the
        scanners look at the raw archive, Syft catalogs 0 components, and every
        tool reports nothing.
        """
        compose = self.compose
        extracted_host = str((self.repo_root / "artifacts" / "extracted" / "current").resolve())

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
        import shutil
        _cur = self.repo_root / "artifacts" / "extracted" / "current"
        if _cur.exists():
            shutil.rmtree(_cur, ignore_errors=True)
        # Trivy's image has no python -> render its flags on the host (run-scan.sh).
        trivy_flags = self._render_trivy_flags()

        # Stage 1 — extract.
        job.begin_stage("extract")
        ex_env = dict(os.environ)
        ex_env["SCAN_TARGET_HOST"] = target_host          # satisfies the :? guard
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

        # Re-point every scanner at the extracted directory.
        sc_env = dict(os.environ)
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

        # Archive the report with a timestamp (keeps history of runs).
        self._archive_reports(job)
        # Stop the lingering grype-static dependency container (best effort).
        self._run_stream(job, [*compose, "--profile", "scan", "down", "--remove-orphans"], sc_env)
        job.finalize()

    def _archive_reports(self, job: Job) -> None:
        """Copy artifacts/reports/final/* into a timestamped history folder so
        successive scans don't overwrite each other."""
        import datetime
        import shutil

        final = self.repo_root / "artifacts" / "reports" / "final"
        if not final.is_dir():
            return
        ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        dest = self.repo_root / "artifacts" / "reports" / "history" / ts
        try:
            dest.mkdir(parents=True, exist_ok=True)
            for f in final.glob("*"):
                if f.is_file():
                    shutil.copy2(f, dest / f.name)
            job.feed_line(f"report archived -> artifacts/reports/history/{ts}/")
        except Exception as exc:  # pragma: no cover - defensive
            job.feed_line(f"WARN: report archive failed: {exc!r}")


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
