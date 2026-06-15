"""Local Docker-Compose MCP bridge for el-sca-ansamble.

Exposes a SMALL, allow-listed set of ``docker compose`` operations over stdio so
an MCP client (Claude) can drive the scanner stack from the repo — validate the
stack, launch DB updaters, run scans, read logs — **without** granting arbitrary
shell access.

Run (in the environment where Docker is reachable — e.g. WSL with Docker Desktop):

    pip install "mcp>=1.2"
    EL_SCA_DIR=/mnt/d/dev/el-sca-ansamble python tools/docker-mcp/server.py

Security model:
- Only the compose subcommands wired below are reachable; there is **no**
  generic "run any command" tool and ``shell=True`` is never used.
- ``service`` / ``tool`` / ``profile`` arguments are validated against allow-lists.
- cwd is pinned to ``EL_SCA_DIR``; the scan target is passed via env vars (argv
  list form only — no shell interpolation).
- A ``proxy`` argument is translated ``127.0.0.1``/``localhost`` →
  ``host.docker.internal`` so the host's local proxy (e.g. xray on 10808) is
  reachable from inside containers (ADR-0007).
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time

try:
    from datetime import UTC  # py3.11+
except ImportError:  # pragma: no cover - py3.10 fallback
    from datetime import timezone as _tz

    UTC = _tz.utc  # noqa: UP017
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

PROJECT_DIR = Path(os.environ.get("EL_SCA_DIR", "/mnt/d/dev/el-sca-ansamble"))

SCANNER_TOOLS = {"trivy", "grype", "cve-bin-tool"}
# Stable execution order for update_db(tool="all").
ALL_UPDATE_ORDER = ("trivy", "grype", "cve-bin-tool")
ALL_SCAN_TOOLS = {"all", "syft", "trivy", "grype", "cve-bin-tool"}
# cve-bin-tool aggregate data sources (configs/feed_sources.yaml: cve_bin_tool.data_sources).
# Used by update_db(only_source=...) to update a single source by disabling the rest.
CVE_BIN_TOOL_SOURCES = {"NVD", "OSV", "GAD", "REDHAT", "CURL", "EPSS", "PURL2CPE", "RSD"}
KNOWN_SERVICES = {
    "trivy-updater",
    "trivy-scanner",
    "grype-updater",
    "grype-db-importer",
    "grype-static",
    "grype-scanner",
    "syft-sbom",
    "artifact-extractor",
    "cve-bin-tool-updater",
    "cve-bin-tool-scanner",
    "db-admin",
    "route-doctor",
    "dashboard",
    "report-collector",
    "osv-scanner",
    "proxy-xray",
    "tinyproxy",
    "wireguard",
}
KNOWN_PROFILES = {
    "default",
    "scan",
    "update",
    "offline",
    "airgap",
    "extract",
    "report",
    "test-failover",
    "dashboard",
    "apk",
    "win",
    "osv",
    "proxy",
    "vpn",
    "route",
}

mcp = FastMCP("el-sca-docker")


def _proxy_env(proxy: str | None) -> dict[str, str]:
    env = dict(os.environ)
    # compose needs these even for config/build (apk-analyzer fail-fast).
    env.setdefault("SCAN_TARGET_HOST", env.get("SCAN_TARGET_HOST", "."))
    env.setdefault("EXTRACT_INPUT_HOST", env.get("EXTRACT_INPUT_HOST", "."))
    if proxy:
        translated = proxy.replace("127.0.0.1", "host.docker.internal").replace(
            "localhost", "host.docker.internal"
        )
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
            env[key] = translated
    return env


def _tail(text: str | None, n: int = 60) -> str:
    return "\n".join((text or "").splitlines()[-n:])


# Map the MCP-facing tool name to the route-plan.json key.
_ROUTE_PLAN_KEY = {"trivy": "trivy", "grype": "grype", "cve-bin-tool": "cve_bin_tool"}
# A plan younger than this is reused instead of re-running route-doctor, so
# update_db("all") (or three back-to-back single-tool calls) probes the network
# once, not three times.
ROUTE_PLAN_MAX_AGE_SECONDS = 300


def _auto_route_enabled() -> bool:
    """Auto-routing is on by default; EL_SCA_AUTO_ROUTE=0/false disables it."""
    return os.environ.get("EL_SCA_AUTO_ROUTE", "1").strip().lower() not in {"0", "false", "no", "off"}


def _route_plan_path() -> Path:
    return PROJECT_DIR / "artifacts" / "route-plan.json"


def _run_volume_init() -> dict[str, Any]:
    """Normalise named-volume / artifacts ownership to uid 1001 before updaters.

    Docker creates named volumes root-owned; the appuser updaters (grype, the
    report-collector) then fail with EACCES.  This root one-shot (compose
    profile ``volinit``) chowns them; idempotent and best-effort.
    """
    return _run(
        ["docker", "compose", "--profile", "volinit", "run", "--rm", "volume-init"],
        timeout=180,
    )


def _run_route_doctor() -> dict[str, Any]:
    """Run the in-network route-doctor; it writes artifacts/route-plan.{json,env}.

    NOTE: route-doctor exits 2 when SOME tool has no reachable route — the plan
    file is still written and is still valid for the tools that do have one, so
    callers must not gate on ``ok`` alone.
    """
    return _run(
        ["docker", "compose", "--profile", "route", "run", "--rm", "route-doctor"],
        timeout=300,
    )


def _load_route_plan() -> dict[str, Any] | None:
    path = _route_plan_path()
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _ensure_route_plan(*, max_age_seconds: int = ROUTE_PLAN_MAX_AGE_SECONDS) -> dict[str, Any] | None:
    """Return a fresh route plan, re-running route-doctor only when stale.

    Freshness is judged by the plan file's mtime, so one route-doctor probe
    serves a whole "update everything" burst.
    """
    path = _route_plan_path()
    try:
        age = time.time() - path.stat().st_mtime
    except OSError:
        age = None
    if age is not None and 0 <= age < max_age_seconds:
        plan = _load_route_plan()
        if plan:
            return plan
    _run_route_doctor()
    return _load_route_plan()


def _route_for_tool(plan: dict[str, Any] | None, tool: str) -> tuple[str | None, list[str], dict[str, Any]]:
    """Select (proxy_url, extra -e flags, info) for *tool* from a route plan.

    For cve-bin-tool additionally returns ``-e CVE_BIN_TOOL_ENRICH_PROXY=<http>``
    so the updater's enrichment bridge uses the same route (its NVD client can't
    speak SOCKS; the plan already guarantees an HTTP URL for it).  With no plan
    the caller behaves exactly as before (direct / .env-configured).
    """
    if not plan:
        return None, [], {"auto_route": "skipped", "reason": "route-doctor produced no plan"}
    sel = (plan.get("plan") or {}).get(_ROUTE_PLAN_KEY.get(tool, tool)) or {}
    proxy_url = sel.get("proxy_url")
    extra_env: list[str] = []
    if tool == "cve-bin-tool" and proxy_url:
        extra_env = ["-e", f"CVE_BIN_TOOL_ENRICH_PROXY={proxy_url}"]
    info = {
        "auto_route": "applied" if proxy_url else "direct",
        "transport": sel.get("transport"),
        "proxy_url": proxy_url,
        "reason": sel.get("reason"),
    }
    return proxy_url, extra_env, info


def _auto_route_for(tool: str) -> tuple[str | None, list[str], dict[str, Any]]:
    """Discover the live egress for *tool* (cached plan or a fresh probe)."""
    return _route_for_tool(_ensure_route_plan(), tool)


def _run(
    args: list[str], *, timeout: int, proxy: str | None = None, allow_exit1: bool = False
) -> dict[str, Any]:
    if not PROJECT_DIR.is_dir():
        return {"ok": False, "error": f"EL_SCA_DIR not found: {PROJECT_DIR}"}
    try:
        proc = subprocess.run(
            args,
            cwd=str(PROJECT_DIR),
            env=_proxy_env(proxy),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout after {timeout}s", "cmd": shlex.join(args)}
    except FileNotFoundError:
        return {"ok": False, "error": "docker not found on PATH in this environment"}
    # cve-bin-tool exits 1 when CVEs are found — that is a success state.
    ok = proc.returncode == 0 or (allow_exit1 and proc.returncode == 1)
    return {
        "ok": ok,
        "returncode": proc.returncode,
        "cmd": shlex.join(args),
        "stdout_tail": _tail(proc.stdout),
        "stderr_tail": _tail(proc.stderr),
    }


@mcp.tool()
def compose_config() -> dict:
    """Validate docker-compose.yml schema. READ-ONLY. Returns ok/returncode/output."""
    return _run(["docker", "compose", "config", "-q"], timeout=60)


@mcp.tool()
def list_services() -> dict:
    """List all compose service names. READ-ONLY."""
    return _run(["docker", "compose", "config", "--services"], timeout=60)


@mcp.tool()
def compose_ps() -> dict:
    """Show running stack containers. READ-ONLY."""
    return _run(["docker", "compose", "ps"], timeout=60)


@mcp.tool()
def monitor() -> dict:
    """Live stack monitor: container status + current pipeline stage/progress
    + DB freshness + log tail. READ-ONLY (`cli monitor --json`).

    Use this to answer "что сейчас происходит / не повис ли скан": the
    pipeline block shows the active stage with elapsed seconds and per-stage
    durations from artifacts/pipeline_state.json.
    """
    if not PROJECT_DIR.is_dir():
        return {"ok": False, "error": f"EL_SCA_DIR not found: {PROJECT_DIR}"}
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv, no shell
            [sys.executable, "-m", "resilient_updates.cli", "monitor", "--json"],
            cwd=str(PROJECT_DIR),
            env=_proxy_env(None),
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc)}
    if proc.returncode != 0:
        return {"ok": False, "returncode": proc.returncode, "stderr_tail": _tail(proc.stderr)}
    try:
        return {"ok": True, "status": json.loads(proc.stdout)}
    except ValueError:
        return {"ok": False, "error": "monitor printed non-JSON", "stdout_tail": _tail(proc.stdout)}


@mcp.tool()
def update_doctor() -> dict:
    """Run the reachability matrix (`cli update-doctor --json`) from the repo. READ-ONLY."""
    return _run([sys.executable, "-m", "resilient_updates.cli", "update-doctor", "--json"], timeout=180)


@mcp.tool()
def compose_logs(service: str, tail: int = 80) -> dict:
    """Show recent logs for one service. READ-ONLY.

    Args:
        service: one of the known compose services.
        tail: number of trailing log lines (1-500).
    """
    if service not in KNOWN_SERVICES:
        return {"ok": False, "error": f"unknown service '{service}'", "known": sorted(KNOWN_SERVICES)}
    tail = max(1, min(int(tail), 500))
    return _run(["docker", "compose", "logs", "--tail", str(tail), service], timeout=60)


@mcp.tool()
def route_plan(force: bool = False) -> dict:
    """Run the in-network route-doctor and return the chosen egress per tool.

    Probes the in-network sidecars (tinyproxy/proxy-xray), the host's local proxy
    and a direct route from *inside* the stack, then writes
    artifacts/route-plan.{json,env} and returns the per-tool plan. READ-ONLY.
    This is what ``update_db``/``run_scan`` call automatically when no explicit
    proxy is given (unless EL_SCA_AUTO_ROUTE=0).

    Args:
        force: re-probe even if a recent plan (younger than 5 min) exists.
    """
    plan = _ensure_route_plan(max_age_seconds=0 if force else ROUTE_PLAN_MAX_AGE_SECONDS)
    if not plan:
        return {"ok": False, "error": "route-doctor produced no plan"}
    return {
        "ok": True,
        "generated_utc": plan.get("generated_utc"),
        "plan": plan.get("plan"),
        "transports": plan.get("transports"),
    }


def _update_one(tool: str, proxy: str | None, extra_env: list[str]) -> dict[str, Any]:
    """Run one tool's updater container (plus grype's importer)."""
    result = _run(
        ["docker", "compose", "--profile", "update", "run", "--rm", *extra_env, f"{tool}-updater"],
        timeout=2400,
        proxy=proxy,
    )
    if tool == "grype" and result.get("ok"):
        result = {
            "ok": result.get("ok", False),
            "updater": result,
            "importer": _run(
                ["docker", "compose", "--profile", "update", "run", "--rm", "grype-db-importer"],
                timeout=600,
                proxy=proxy,
            ),
        }
        result["ok"] = bool(result["updater"].get("ok")) and bool(result["importer"].get("ok"))
    return result


@mcp.tool()
def update_db(
    tool: str, proxy: str | None = None, only_source: str | None = None, auto_route: bool = True
) -> dict:
    """Update scanner DBs — one tool or all of them (profile ``update``).

    ``tool="all"`` updates trivy, grype (with importer) and cve-bin-tool in one
    call, sharing a SINGLE route-doctor probe: each tool gets its own egress
    from the same plan (cve-bin-tool always an HTTP bridge; trivy/grype may go
    via SOCKS).  Pass ``proxy`` (e.g. ``http://127.0.0.1:10808``) to force one
    proxy for everything — it is auto-translated to ``host.docker.internal``
    for the containers.

    When ``proxy`` is omitted and ``auto_route`` is true (the default), the
    in-network route-doctor picks a live egress automatically (works under any
    tunnel/proxy/VPN setup); a plan younger than 5 minutes is reused.  If
    nothing is found the update proceeds direct, exactly as before.  Set
    ``auto_route=False`` or the env ``EL_SCA_AUTO_ROUTE=0`` to disable.

    Args:
        tool: all | trivy | grype | cve-bin-tool.
        proxy: optional explicit proxy URL for the DB fetch (overrides auto-route).
        only_source: cve-bin-tool only — update just this single data source
            (NVD|OSV|GAD|REDHAT|CURL|EPSS|PURL2CPE|RSD).  Implemented by passing
            ``-e CVE_BIN_TOOL_DISABLE_SOURCES=<all the others>`` to the updater
            container, so only the requested source is fetched.
        auto_route: discover and apply a working egress when no proxy is given.
    """
    if tool != "all" and tool not in SCANNER_TOOLS:
        return {"ok": False, "error": f"tool must be one of ['all', *{sorted(SCANNER_TOOLS)}]"}
    if only_source is not None and tool != "cve-bin-tool":
        return {"ok": False, "error": "only_source is supported for cve-bin-tool only"}

    # Fix volume/artifacts ownership once before any updater runs (root-owned
    # named volumes otherwise break the appuser grype-updater / report-collector).
    volinit = _run_volume_init()

    use_auto = proxy is None and auto_route and _auto_route_enabled()
    plan = _ensure_route_plan() if use_auto else None

    # ── all tools, one probe ─────────────────────────────────────────────
    if tool == "all":
        results: dict[str, Any] = {}
        routes: dict[str, Any] = {}
        for t in ALL_UPDATE_ORDER:
            t_proxy, t_extra, t_info = (proxy, [], None) if not use_auto else _route_for_tool(plan, t)
            results[t] = _update_one(t, t_proxy, t_extra)
            if t_info is not None:
                routes[t] = t_info
        out: dict[str, Any] = {
            "ok": all(bool(r.get("ok")) for r in results.values()),
            "results": results,
            "volume_init_ok": bool(volinit.get("ok")),
        }
        if routes:
            out["route"] = routes
        return out

    # ── single tool ──────────────────────────────────────────────────────
    route_info: dict[str, Any] | None = None
    extra_env: list[str] = []
    if use_auto:
        proxy, extra_env, route_info = _route_for_tool(plan, tool)
    if only_source is not None:
        src = only_source.strip().upper()
        if src not in CVE_BIN_TOOL_SOURCES:
            return {
                "ok": False,
                "error": f"only_source must be one of {sorted(CVE_BIN_TOOL_SOURCES)}",
            }
        disabled = sorted(CVE_BIN_TOOL_SOURCES - {src})
        # Disable every other source for the base run, and clear the retry-disable
        # default (OSV) so a single-source run is not silently skipped on retry.
        # Append (don't overwrite) so any auto-route -e flags above are kept.
        extra_env += [
            "-e",
            "CVE_BIN_TOOL_DISABLE_SOURCES=" + " ".join(disabled),
            "-e",
            "CVE_BIN_TOOL_DISABLE_SOURCES_ON_RETRY=",
        ]

    result = _update_one(tool, proxy, extra_env)
    if isinstance(result, dict):
        result["volume_init_ok"] = bool(volinit.get("ok"))
        if route_info is not None:
            result["route"] = route_info
    return result


@mcp.tool()
def run_scan(
    target: str,
    tool: str = "all",
    extract: bool = True,
    update_db: bool = False,
    sbom_scan: bool = False,
    proxy: str | None = None,
    resume: bool = False,
) -> dict:
    """Run the full SCA pipeline against ``target`` via scripts/run-scan.sh.

    Args:
        target: path to the artifact/directory to scan (on the Docker host FS).
        tool: all | syft | trivy | grype | cve-bin-tool.
        extract: unpack archives before scanning.
        update_db: pull fresh DBs first (needs network/proxy).
        sbom_scan: feed Syft SBOM to cve-bin-tool (faster).
        proxy: optional proxy URL (auto-translated for containers).
        resume: continue from the last checkpoint — stages already completed
            for the SAME target+tool are skipped (artifacts/pipeline_state.json).

    cve-bin-tool exit code 1 (CVEs found) is treated as success.
    """
    if tool not in ALL_SCAN_TOOLS:
        return {"ok": False, "error": f"tool must be one of {sorted(ALL_SCAN_TOOLS)}"}
    if not target or target.strip() in {"", ".", "/"}:
        return {"ok": False, "error": "refusing to scan an empty/root target; pass a concrete path"}
    args = ["bash", "scripts/run-scan.sh", "--target", target, "--tool", tool]
    if extract:
        args.append("--extract")
    if update_db:
        args.append("--update-db")
    if sbom_scan:
        args.append("--sbom-scan")
    if resume:
        args.append("--resume")
    env_proxy = proxy
    if proxy:
        os.environ["SCAN_TARGET_HOST"] = target
    return _run(args, timeout=3600, proxy=env_proxy, allow_exit1=True)


JOBS_DIR_REL = Path("artifacts") / "mcp-jobs"


@mcp.tool()
def run_scan_async(
    target: str,
    tool: str = "all",
    extract: bool = True,
    update_db: bool = False,
    sbom_scan: bool = False,
    proxy: str | None = None,
    resume: bool = False,
) -> dict:
    """Launch the SCA pipeline in the background and return immediately.

    Long scans exceed the MCP client's request timeout when run via the
    synchronous ``run_scan`` (the client sees -32001 although the host keeps
    going). This variant detaches the pipeline and returns a ``job_id``;
    poll ``scan_status`` to follow progress via artifacts/run-scan.log.

    Pass ``resume=True`` to continue a hung/interrupted scan from its last
    checkpoint instead of restarting from zero (see ``monitor`` for progress).
    """
    if tool not in ALL_SCAN_TOOLS:
        return {"ok": False, "error": f"tool must be one of {sorted(ALL_SCAN_TOOLS)}"}
    if not target or target.strip() in {"", ".", "/"}:
        return {"ok": False, "error": "refusing to scan an empty/root target; pass a concrete path"}
    if not PROJECT_DIR.is_dir():
        return {"ok": False, "error": f"EL_SCA_DIR not found: {PROJECT_DIR}"}
    # On Windows the MCP server's Python process runs natively; WSL bash cannot
    # resolve Windows paths like d:\..., so we delegate to run-scan.ps1 instead.
    # run-scan.ps1 writes [stage] markers and updates pipeline_state.json via the
    # same CLI tools, so scan_status works identically on both platforms.
    if sys.platform == "win32":
        ps_script = str(PROJECT_DIR / "scripts" / "windows" / "run-scan.ps1")
        args: list[str] = [
            "powershell.exe",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ps_script,
            "-Target",
            target,
            "-Tool",
            tool,
        ]
        if extract:
            args.append("-Extract")
        if update_db:
            args.append("-UpdateDb")
        if sbom_scan:
            args.append("-SbomScan")
        if resume:
            args.append("-Resume")
    else:
        args = ["bash", "scripts/run-scan.sh", "--target", target, "--tool", tool]
        if extract:
            args.append("--extract")
        if update_db:
            args.append("--update-db")
        if sbom_scan:
            args.append("--sbom-scan")
        if resume:
            args.append("--resume")
    jobs_dir = PROJECT_DIR / JOBS_DIR_REL
    jobs_dir.mkdir(parents=True, exist_ok=True)
    job_id = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    log_path = PROJECT_DIR / "artifacts" / "run-scan.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if sys.platform == "win32":
            # PowerShell manages its own output; we capture it to run-scan.log
            # so scan_status can tail it (mirrors run-scan.sh's `tee` redirect).
            log_fh = open(log_path, "w", encoding="utf-8")  # noqa: WPS515,SIM115
            proc = subprocess.Popen(  # argv list, no shell
                args,
                cwd=str(PROJECT_DIR),
                env=_proxy_env(proxy),
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        else:
            proc = subprocess.Popen(  # argv list, allow-listed script — no shell
                args,
                cwd=str(PROJECT_DIR),
                env=_proxy_env(proxy),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
    except FileNotFoundError:
        return {"ok": False, "error": "bash/powershell not found on PATH in this environment"}
    job = {
        "job_id": job_id,
        "pid": proc.pid,
        "cmd": shlex.join(args),
        "target": target,
        "started_utc": datetime.now(UTC).isoformat(),
    }
    (jobs_dir / f"{job_id}.json").write_text(json.dumps(job, indent=2), encoding="utf-8")
    return {
        "ok": True,
        **job,
        "log": "artifacts/run-scan.log",
        "hint": "poll scan_status(job_id) until running=false, then read artifacts/reports/final/",
    }


@mcp.tool()
def scan_status(job_id: str = "") -> dict:
    """Report progress of a background scan started by ``run_scan_async``.

    Args:
        job_id: id returned by run_scan_async; empty = most recent job.
    """
    jobs_dir = PROJECT_DIR / JOBS_DIR_REL
    candidates = sorted(jobs_dir.glob("*.json"), reverse=True)
    if job_id:
        candidates = [p for p in candidates if p.stem == job_id]
    if not candidates:
        return {"ok": False, "error": "no such job (run_scan_async writes artifacts/mcp-jobs/<id>.json)"}
    job = json.loads(candidates[0].read_text(encoding="utf-8"))
    running = True
    try:
        os.kill(int(job["pid"]), 0)
    except (OSError, ValueError):
        running = False
    log_path = PROJECT_DIR / "artifacts" / "run-scan.log"
    log_tail = ""
    stages: list[str] = []
    if log_path.is_file():
        text = log_path.read_text(encoding="utf-8", errors="replace")
        log_tail = _tail(text, 15)
        stages = [ln.strip() for ln in text.splitlines() if ln.startswith("[stage]") or "Reports ready" in ln]
    # Structured per-stage progress (status/durations) from the checkpoint file.
    pipeline: dict[str, Any] | None = None
    try:
        state = json.loads((PROJECT_DIR / "artifacts" / "pipeline_state.json").read_text(encoding="utf-8"))
        pipeline = {
            "status": state.get("status"),
            "current_stage": state.get("current_stage"),
            "stages": {name: info.get("status") for name, info in (state.get("stages") or {}).items()},
        }
    except (OSError, ValueError):
        pass
    return {
        "ok": True,
        "job_id": job["job_id"],
        "pid": job["pid"],
        "running": running,
        "started_utc": job.get("started_utc"),
        "stages_seen": stages[-8:],
        "pipeline": pipeline,
        "log_tail": log_tail,
    }


@mcp.tool()
def start_dashboard() -> dict:
    """Start the read-only FastAPI dashboard (compose profile ``dashboard``).

    Serves the last run's ``artifacts/`` at http://127.0.0.1:8080 (read-only;
    it never scans or mutates). Idempotent — re-running just ensures it is up.
    """
    return _run(
        ["docker", "compose", "--profile", "dashboard", "up", "-d", "--build", "dashboard"],
        timeout=900,
    )


@mcp.tool()
def stop_dashboard() -> dict:
    """Stop the dashboard container (leaves the rest of the stack alone)."""
    return _run(
        ["docker", "compose", "--profile", "dashboard", "rm", "-sf", "dashboard"],
        timeout=120,
    )


@mcp.tool()
def compose_down() -> dict:
    """Stop and remove the stack containers. DESTRUCTIVE (no volumes removed)."""
    return _run(["docker", "compose", "down"], timeout=300)


if __name__ == "__main__":  # pragma: no cover
    mcp.run()
