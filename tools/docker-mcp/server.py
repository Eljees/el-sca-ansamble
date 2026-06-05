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

import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

PROJECT_DIR = Path(os.environ.get("EL_SCA_DIR", "/mnt/d/dev/el-sca-ansamble"))

SCANNER_TOOLS = {"trivy", "grype", "cve-bin-tool"}
ALL_SCAN_TOOLS = {"all", "syft", "trivy", "grype", "cve-bin-tool"}
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
def update_db(tool: str, proxy: str | None = None) -> dict:
    """Update a scanner DB by running its updater container (profile ``update``).

    For grype, also runs grype-db-importer.  Pass ``proxy`` (e.g.
    ``http://127.0.0.1:10808``) to route the container through the host's local
    proxy — it is auto-translated to ``host.docker.internal`` for the container.

    Args:
        tool: one of trivy | grype | cve-bin-tool.
        proxy: optional proxy URL for the DB fetch.
    """
    if tool not in SCANNER_TOOLS:
        return {"ok": False, "error": f"tool must be one of {sorted(SCANNER_TOOLS)}"}
    result = _run(
        ["docker", "compose", "--profile", "update", "run", "--rm", f"{tool}-updater"],
        timeout=2400,
        proxy=proxy,
    )
    if tool == "grype" and result.get("ok"):
        result = {
            "updater": result,
            "importer": _run(
                ["docker", "compose", "--profile", "update", "run", "--rm", "grype-db-importer"],
                timeout=600,
                proxy=proxy,
            ),
        }
    return result


@mcp.tool()
def run_scan(
    target: str,
    tool: str = "all",
    extract: bool = True,
    update_db: bool = False,
    sbom_scan: bool = False,
    proxy: str | None = None,
) -> dict:
    """Run the full SCA pipeline against ``target`` via scripts/run-scan.sh.

    Args:
        target: path to the artifact/directory to scan (on the Docker host FS).
        tool: all | syft | trivy | grype | cve-bin-tool.
        extract: unpack archives before scanning.
        update_db: pull fresh DBs first (needs network/proxy).
        sbom_scan: feed Syft SBOM to cve-bin-tool (faster).
        proxy: optional proxy URL (auto-translated for containers).

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
    env_proxy = proxy
    if proxy:
        os.environ["SCAN_TARGET_HOST"] = target
    return _run(args, timeout=3600, proxy=env_proxy, allow_exit1=True)


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


if __name__ == "__main__":
    mcp.run()
