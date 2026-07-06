"""Publish scan run snapshots to the stack-local S3 storage.

The implementation intentionally drives the existing compose services instead
of depending on host-side S3 tools.  This keeps Windows/Linux operator commands
the same: Python starts SeaweedFS if needed, then runs the `s3-client` service
with minio/mc inside Docker.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

Run = Callable[..., subprocess.CompletedProcess[str]]

_TRUE = {"1", "true", "yes", "on"}


def env_enabled(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in _TRUE


def newest_run_dir(repo_root: str | Path) -> Path | None:
    root = Path(repo_root)
    candidates: list[Path] = []
    for runs_root in (root / "_SCA_reports", root / "artifacts" / "runs"):
        if runs_root.is_dir():
            candidates.extend(p for p in runs_root.iterdir() if p.is_dir())
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _relative_workspace_path(path: Path, repo_root: Path) -> str:
    try:
        rel = path.resolve().relative_to(repo_root.resolve())
    except ValueError as exc:
        raise ValueError(f"run_dir must live under repo_root so Docker can see it: {path}") from exc
    return "/workspace/" + rel.as_posix()


def _compose_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("SCAN_TARGET_HOST", "/tmp/el-sca-s3-noscan")
    env.setdefault("EXTRACT_INPUT_HOST", "/tmp/el-sca-s3-noextract")
    env.setdefault("COMPOSE_PROJECT_NAME", "el-sca-ansamble")
    return env


def _run_checked(
    runner: Run, cmd: list[str], *, cwd: Path, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    proc = runner(cmd, cwd=str(cwd), env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        stderr = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"{' '.join(cmd)} failed rc={proc.returncode}: {stderr}")
    return proc


def publish_results(
    run_dir: str | Path | None = None,
    *,
    repo_root: str | Path = ".",
    compose: list[str] | None = None,
    runner: Run = subprocess.run,
) -> dict[str, Any]:
    """Publish a scan run directory to ``scans/<run-id>`` and ``scans/latest``.

    If *run_dir* is omitted, the newest directory from ``_SCA_reports`` and
    legacy ``artifacts/runs`` is used.
    """
    root = Path(repo_root).resolve()
    selected = Path(run_dir).resolve() if run_dir else newest_run_dir(root)
    if selected is None or not selected.is_dir():
        raise FileNotFoundError("No run directory found under _SCA_reports or artifacts/runs")

    workspace_run = _relative_workspace_path(selected, root)
    run_id = selected.name
    bucket = os.environ.get("EL_SCA_S3_BUCKET", "el-sca")
    compose_cmd = compose or ["docker", "compose"]
    env = _compose_env()

    _run_checked(runner, [*compose_cmd, "--profile", "storage", "up", "-d", "seaweedfs"], cwd=root, env=env)

    q_run = shlex.quote(workspace_run)
    q_run_id = shlex.quote(run_id)
    script = f"""
set -eu
RUN_DIR={q_run}
RUN_ID={q_run_id}
ready=0
for i in $(seq 1 30); do
  mc alias set "$EL_SCA_S3_ALIAS" "$EL_SCA_S3_ENDPOINT" "$EL_SCA_S3_ACCESS_KEY" "$EL_SCA_S3_SECRET_KEY" --api S3v4 >/dev/null
  if mc ls "$EL_SCA_S3_ALIAS" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" != "1" ]; then
  echo "S3 endpoint is not ready: $EL_SCA_S3_ENDPOINT" >&2
  exit 3
fi
mc mb -p "$EL_SCA_S3_ALIAS/$EL_SCA_S3_BUCKET" >/dev/null 2>&1 || true
mc rm --recursive --force "$EL_SCA_S3_ALIAS/$EL_SCA_S3_BUCKET/scans/previous" >/dev/null 2>&1 || true
mc cp --recursive "$EL_SCA_S3_ALIAS/$EL_SCA_S3_BUCKET/scans/latest/" "$EL_SCA_S3_ALIAS/$EL_SCA_S3_BUCKET/scans/previous/" >/dev/null 2>&1 || true
mc mirror --overwrite --remove "$RUN_DIR" "$EL_SCA_S3_ALIAS/$EL_SCA_S3_BUCKET/scans/$RUN_ID"
mc mirror --overwrite --remove "$RUN_DIR" "$EL_SCA_S3_ALIAS/$EL_SCA_S3_BUCKET/scans/latest"
"""
    _run_checked(
        runner,
        [
            *compose_cmd,
            "--profile",
            "storage",
            "--profile",
            "storage-tools",
            "run",
            "--rm",
            "--no-deps",
            "s3-client",
            script,
        ],
        cwd=root,
        env=env,
    )
    return {
        "status": "ok",
        "run_id": run_id,
        "run_dir": str(selected),
        "bucket": bucket,
        "prefixes": [f"scans/{run_id}", "scans/latest"],
    }
