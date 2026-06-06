#!/usr/bin/env python3
"""docker_mcp — a general-purpose MCP server for working with local Docker.

Wraps the `docker` CLI (so it works anywhere the Docker Desktop / Engine CLI is
on PATH, including Windows + WSL2). Exposes observation, lifecycle, exec, build,
and destructive operations as discrete MCP tools with proper safety annotations.

Run locally over stdio:
    python docker_mcp.py

Requires the `docker` binary on PATH and a running Docker daemon.
"""

# NB: deliberately NO `from __future__ import annotations`.  With PEP 563 the
# Enum/model annotations in tool signatures become forward-ref strings that
# FastMCP/pydantic v2 cannot resolve when building each tool's arg-model JSON
# schema ("X is not fully defined").  Evaluating annotations eagerly fixes it.

import asyncio
import json
import shutil
from enum import StrEnum
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

mcp = FastMCP("docker_mcp")


class ListKind(StrEnum):
    IMAGES = "images"
    NETWORKS = "networks"
    VOLUMES = "volumes"


class LifecycleAction(StrEnum):
    START = "start"
    STOP = "stop"
    RESTART = "restart"


class PruneScope(StrEnum):
    CONTAINERS = "container"
    IMAGES = "image"
    VOLUMES = "volume"
    NETWORKS = "network"
    SYSTEM = "system"


# ---------------------------------------------------------------------------# #
# Constants & shared helpers
# ----------------------------------------------------------------------------- #

DEFAULT_TIMEOUT = 60  # seconds for normal commands
BUILD_TIMEOUT = 1800  # builds can be slow
DOCKER_BIN = "docker"


class ResponseFormat(StrEnum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


def _docker_available() -> str | None:
    """Return an error string if the docker CLI is missing, else None."""
    if shutil.which(DOCKER_BIN) is None:
        return (
            "Error: the `docker` CLI was not found on PATH. Install Docker "
            "Desktop / Engine and ensure `docker` is runnable from this shell."
        )
    return None


async def _run(args: list[str], timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Run a docker subcommand with arguments passed as a list (no shell).

    Returns a dict: {ok, returncode, stdout, stderr}. Never raises for a
    non-zero exit; callers decide how to interpret returncode.
    """
    missing = _docker_available()
    if missing is not None:
        return {"ok": False, "returncode": 127, "stdout": "", "stderr": missing}

    try:
        proc = await asyncio.create_subprocess_exec(
            DOCKER_BIN,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return {
                "ok": False,
                "returncode": 124,
                "stdout": "",
                "stderr": f"Error: `docker {args[0] if args else ''}` timed out after {timeout}s.",
            }
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": out.decode("utf-8", "replace").strip(),
            "stderr": err.decode("utf-8", "replace").strip(),
        }
    except Exception as e:  # pragma: no cover - defensive
        return {
            "ok": False,
            "returncode": 1,
            "stdout": "",
            "stderr": f"Error: failed to launch docker: {type(e).__name__}: {e}",
        }


def _result(res: dict[str, Any], success_note: str = "") -> str:
    """Format a _run result as a compact JSON string for the agent."""
    payload: dict[str, Any] = {
        "ok": res["ok"],
        "returncode": res["returncode"],
    }
    if res.get("stdout"):
        payload["stdout"] = res["stdout"]
    if res.get("stderr"):
        payload["stderr"] = res["stderr"]
    if success_note and res["ok"]:
        payload["note"] = success_note
    return json.dumps(payload, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------- #
# Observation tools (read-only)
# ---------------------------------------------------------------------------- #


class PsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    all: bool = Field(default=False, description="Include stopped containers (docker ps -a).")


@mcp.tool(
    name="docker_ps",
    annotations={
        "title": "List containers",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def docker_ps(params: PsInput) -> str:
    """List Docker containers with id, image, status, names and ports.

    Args:
        params.all (bool): include stopped containers when True.
    Returns: JSON {ok, returncode, stdout(JSON-lines of containers), stderr?}.
    """
    args = ["ps", "--no-trunc", "--format", "{{ json . }}"]
    if params.all:
        args.insert(1, "-a")
    return _result(await _run(args))


class IdInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    target: str = Field(
        ..., description="Container/image name or id (e.g. 'web', 'a1b2c3').", min_length=1, max_length=256
    )


@mcp.tool(
    name="docker_inspect",
    annotations={
        "title": "Inspect object",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def docker_inspect(params: IdInput) -> str:
    """Return low-level JSON metadata for a container, image, network or volume.

    Args:
        params.target (str): the object name or id.
    Returns: JSON {ok, returncode, stdout(full inspect JSON), stderr?}.
    """
    return _result(await _run(["inspect", params.target]))


class LogsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    container: str = Field(..., description="Container name or id.", min_length=1, max_length=256)
    tail: int = Field(default=100, description="Number of trailing lines to show.", ge=1, le=10000)
    timestamps: bool = Field(default=False, description="Prefix each line with a timestamp.")


@mcp.tool(
    name="docker_logs",
    annotations={
        "title": "Container logs",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def docker_logs(params: LogsInput) -> str:
    """Fetch the last N log lines from a container (non-following snapshot).

    Args:
        params.container (str): container name/id.
        params.tail (int): trailing line count (default 100).
        params.timestamps (bool): include timestamps.
    Returns: JSON {ok, returncode, stdout(log text), stderr?}.
    """
    args = ["logs", "--tail", str(params.tail)]
    if params.timestamps:
        args.append("--timestamps")
    args.append(params.container)
    return _result(await _run(args))


@mcp.tool(
    name="docker_stats",
    annotations={
        "title": "Resource stats",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def docker_stats() -> str:
    """Snapshot CPU/memory/network/IO usage for running containers (no stream).

    Returns: JSON {ok, returncode, stdout(JSON-lines per container), stderr?}.
    """
    return _result(await _run(["stats", "--no-stream", "--format", "{{ json . }}"]))


class ListInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    kind: ListKind = Field(..., description="What to list: images | networks | volumes.")


@mcp.tool(
    name="docker_list",
    annotations={
        "title": "List images/networks/volumes",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def docker_list(params: ListInput) -> str:
    """List images, networks, or volumes depending on `kind`.

    Args:
        params.kind (ListKind): one of images | networks | volumes.
    Returns: JSON {ok, returncode, stdout(JSON-lines), stderr?}.
    """
    sub = {
        ListKind.IMAGES: ["images"],
        ListKind.NETWORKS: ["network", "ls"],
        ListKind.VOLUMES: ["volume", "ls"],
    }[params.kind]
    return _result(await _run([*sub, "--format", "{{ json . }}"]))


# ---------------------------------------------------------------------------- #
# Lifecycle tools
# ----------------------------------------------------------------------------# #


class LifecycleInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    action: LifecycleAction = Field(..., description="start | stop | restart.")
    containers: list[str] = Field(
        ..., description="One or more container names/ids.", min_length=1, max_length=50
    )


@mcp.tool(
    name="docker_lifecycle",
    annotations={
        "title": "Start/stop/restart containers",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def docker_lifecycle(params: LifecycleInput) -> str:
    """Start, stop, or restart one or more containers.

    Args:
        params.action (LifecycleAction): start | stop | restart.
        params.containers (List[str]): container names/ids to act on.
    Returns: JSON {ok, returncode, stdout(affected ids), stderr?}.
    """
    res = await _run([params.action.value, *params.containers])
    return _result(res, success_note=f"{params.action.value} applied")


# ---------------------------------------------------------------------------- #
# Exec & build
# --------------------------------------------------------------------------- #


class ExecInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    container: str = Field(..., description="Target container name/id.", min_length=1, max_length=256)
    command: list[str] = Field(
        ...,
        description="Command + args as a list, e.g. ['ls','-la','/app']. "
        "Run as-is (no shell); for shell features pass ['sh','-c','...'].",
        min_length=1,
        max_length=100,
    )
    workdir: str | None = Field(default=None, description="Working directory inside the container.")
    user: str | None = Field(default=None, description="User to run as (name or uid).")
    timeout: int = Field(
        default=DEFAULT_TIMEOUT, description="Seconds before the exec is killed.", ge=1, le=3600
    )


@mcp.tool(
    name="docker_exec",
    annotations={
        "title": "Exec command in container",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def docker_exec(params: ExecInput) -> str:
    """Run a command inside a running container (non-interactive).

    Args are passed without a shell, so each argument is literal. To use pipes,
    globbing, or env expansion, invoke a shell explicitly: ['sh','-c','...'].

    Args:
        params.container (str): container name/id.
        params.command (List[str]): argv list.
        params.workdir (Optional[str]): -w working dir.
        params.user (Optional[str]): -u user.
        params.timeout (int): kill after N seconds.
    Returns: JSON {ok, returncode, stdout, stderr?}.
    """
    args = ["exec"]
    if params.workdir:
        args += ["-w", params.workdir]
    if params.user:
        args += ["-u", params.user]
    args.append(params.container)
    args += params.command
    return _result(await _run(args, timeout=params.timeout))


class BuildInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    context: str = Field(
        ..., description="Build context path (directory) on the host.", min_length=1, max_length=1024
    )
    tag: str = Field(..., description="Image tag, e.g. 'myapp:latest'.", min_length=1, max_length=256)
    dockerfile: str | None = Field(
        default=None, description="Path to Dockerfile if not <context>/Dockerfile."
    )
    no_cache: bool = Field(default=False, description="Build without using cache.")


@mcp.tool(
    name="docker_build",
    annotations={
        "title": "Build image",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def docker_build(params: BuildInput) -> str:
    """Build a Docker image from a context directory.

    Args:
        params.context (str): build context dir.
        params.tag (str): -t tag for the resulting image.
        params.dockerfile (Optional[str]): -f Dockerfile path.
        params.no_cache (bool): disable build cache.
    Returns: JSON {ok, returncode, stdout(build log), stderr?}.
    """
    args = ["build", "-t", params.tag]
    if params.dockerfile:
        args += ["-f", params.dockerfile]
    if params.no_cache:
        args.append("--no-cache")
    args.append(params.context)
    return _result(await _run(args, timeout=BUILD_TIMEOUT))


# -------------------------------------------------------------------------- #
# Compose (flexible escape hatch)
# --------------------------------------------------------------------------- #


class ComposeInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    working_dir: str = Field(
        ..., description="Directory containing the compose file.", min_length=1, max_length=1024
    )
    args: list[str] = Field(
        ...,
        description="Compose args after `docker compose`, e.g. ['up','-d'] or ['ps'] or ['down'].",
        min_length=1,
        max_length=50,
    )
    timeout: int = Field(default=300, description="Seconds before the command is killed.", ge=1, le=3600)


@mcp.tool(
    name="docker_compose",
    annotations={
        "title": "Run docker compose",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def docker_compose(params: ComposeInput) -> str:
    """Run an arbitrary `docker compose` subcommand in a project directory.

    Destructive subcommands (down, rm) are possible, hence destructiveHint.

    Args:
        params.working_dir (str): project dir (used as --project-directory).
        params.args (List[str]): compose args, e.g. ['up','-d'], ['ps'], ['down'].
        params.timeout (int): kill after N seconds.
    Returns: JSON {ok, returncode, stdout, stderr?}.
    """
    full = ["compose", "--project-directory", params.working_dir, *params.args]
    return _result(await _run(full, timeout=params.timeout))


# ---------------------------------------------------------------------------- #
# Destructive tools
# ---------------------------------------------------------------------------- #


class RemoveInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    targets: list[str] = Field(..., description="Container names/ids to remove.", min_length=1, max_length=50)
    force: bool = Field(default=False, description="Force removal of running containers (-f).")
    volumes: bool = Field(default=False, description="Also remove anonymous volumes (-v).")


@mcp.tool(
    name="docker_rm",
    annotations={
        "title": "Remove containers",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def docker_rm(params: RemoveInput) -> str:
    """Remove one or more containers. DESTRUCTIVE.

    Args:
        params.targets (List[str]): container names/ids.
        params.force (bool): -f to remove running containers.
        params.volumes (bool): -v to drop anonymous volumes.
    Returns: JSON {ok, returncode, stdout(removed ids), stderr?}.
    """
    args = ["rm"]
    if params.force:
        args.append("-f")
    if params.volumes:
        args.append("-v")
    args += params.targets
    return _result(await _run(args), success_note="containers removed")


class RemoveImageInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    images: list[str] = Field(..., description="Image names/ids to remove.", min_length=1, max_length=50)
    force: bool = Field(default=False, description="Force removal (-f).")


@mcp.tool(
    name="docker_rmi",
    annotations={
        "title": "Remove images",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def docker_rmi(params: RemoveImageInput) -> str:
    """Remove one or more images. DESTRUCTIVE.

    Args:
        params.images (List[str]): image names/ids.
        params.force (bool): -f to force.
    Returns: JSON {ok, returncode, stdout, stderr?}.
    """
    args = ["rmi"]
    if params.force:
        args.append("-f")
    args += params.images
    return _result(await _run(args), success_note="images removed")


class KillInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    containers: list[str] = Field(
        ..., description="Container names/ids to kill.", min_length=1, max_length=50
    )
    signal: str | None = Field(default=None, description="Signal to send, e.g. 'SIGKILL', 'SIGTERM'.")


@mcp.tool(
    name="docker_kill",
    annotations={
        "title": "Kill containers",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def docker_kill(params: KillInput) -> str:
    """Send a kill signal to running containers (default SIGKILL). DESTRUCTIVE.

    Args:
        params.containers (List[str]): container names/ids.
        params.signal (Optional[str]): signal name.
    Returns: JSON {ok, returncode, stdout, stderr?}.
    """
    args = ["kill"]
    if params.signal:
        args += ["-s", params.signal]
    args += params.containers
    return _result(await _run(args), success_note="kill signal sent")


class PruneInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    scope: PruneScope = Field(..., description="What to prune: container|image|volume|network|system.")
    confirm: bool = Field(
        default=False, description="Must be True to actually run — a deliberate safety gate."
    )
    all_images: bool = Field(
        default=False, description="For image/system scope: prune unused images too (-a)."
    )


@mcp.tool(
    name="docker_prune",
    annotations={
        "title": "Prune unused objects",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def docker_prune(params: PruneInput) -> str:
    """Prune unused Docker objects. HIGHLY DESTRUCTIVE — requires confirm=True.

    Args:
        params.scope (PruneScope): container|image|volume|network|system.
        params.confirm (bool): must be True or the call is refused.
        params.all_images (bool): -a for image/system prune.
    Returns: JSON {ok, returncode, stdout, stderr?} or a refusal note.
    """
    if not params.confirm:
        return json.dumps(
            {
                "ok": False,
                "refused": True,
                "note": f"Refused: '{params.scope.value} prune' deletes data permanently. "
                "Re-call with confirm=true to proceed.",
            },
            indent=2,
            ensure_ascii=False,
        )

    if params.scope == PruneScope.SYSTEM:
        args = ["system", "prune", "-f"]
        if params.all_images:
            args.append("-a")
    else:
        args = [params.scope.value, "prune", "-f"]
        if params.scope == PruneScope.IMAGES and params.all_images:
            args.append("-a")
    return _result(await _run(args), success_note="prune completed")


# --- added: disk usage / volume sizes --------------------------------------- #
@mcp.tool()
async def docker_df(
    verbose: bool = False,
    fmt: ResponseFormat = ResponseFormat.MARKDOWN,
) -> str:
    """Report Docker disk usage: space used by images, containers, local volumes
    and the build cache. This is `docker system df`.

    Use it to answer "how big is my volume / how much disk is the stack eating".
    With verbose=True you get the per-object breakdown (every image, container and
    named volume with its individual size) — that is where you read the size of a
    specific volume.

    Args:
        verbose: include the per-image / per-container / per-volume breakdown
                 (`docker system df -v`). Default: compact summary only.
        fmt: "markdown" for the human-readable table, "json" for machine output
             (json is ignored together with verbose, since `-v` has no --format).
    """
    err = _docker_available()
    if err:
        return err

    args = ["system", "df"]
    want_json = fmt == ResponseFormat.JSON and not verbose
    if want_json:
        args += ["--format", "{{json .}}"]
    if verbose:
        args.append("-v")

    proc = await asyncio.create_subprocess_exec(
        DOCKER_BIN,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=DEFAULT_TIMEOUT)
    except TimeoutError:
        proc.kill()
        return f"Error: `docker {' '.join(args)}` timed out after {DEFAULT_TIMEOUT}s."

    out = out_b.decode("utf-8", "replace").strip()
    err_s = err_b.decode("utf-8", "replace").strip()

    if proc.returncode != 0:
        return f"Error (exit {proc.returncode}): {err_s or out or 'docker system df failed'}"

    if want_json:
        rows = [json.loads(line) for line in out.splitlines() if line.strip()]
        return json.dumps(rows, indent=2, ensure_ascii=False)

    return out or "(no output)"


if __name__ == "__main__":
    mcp.run()
