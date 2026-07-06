from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from resilient_updates.s3_publish import newest_run_dir, publish_results


def test_newest_run_dir_prefers_newest_across_host_and_legacy(tmp_path: Path) -> None:
    host = tmp_path / "_SCA_reports" / "host-run"
    legacy = tmp_path / "artifacts" / "runs" / "legacy-run"
    host.mkdir(parents=True)
    legacy.mkdir(parents=True)
    old = 1_700_000_000
    new = old + 60
    import os

    os.utime(host, (old, old))
    os.utime(legacy, (new, new))

    assert newest_run_dir(tmp_path) == legacy


def test_publish_results_runs_compose_storage_and_client(tmp_path: Path) -> None:
    run_dir = tmp_path / "_SCA_reports" / "app-20260707-120000"
    run_dir.mkdir(parents=True)
    calls: list[list[str]] = []

    def fake_runner(cmd, **kwargs):
        calls.append(list(cmd))
        assert kwargs["cwd"] == str(tmp_path.resolve())
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    payload = publish_results(run_dir, repo_root=tmp_path, compose=["docker", "compose"], runner=fake_runner)

    assert payload["status"] == "ok"
    assert payload["run_id"] == run_dir.name
    assert calls[0] == ["docker", "compose", "--profile", "storage", "up", "-d", "seaweedfs"]
    assert calls[1][-2] == "s3-client"
    script = calls[1][-1]
    assert "RUN_DIR=/workspace/_SCA_reports/app-20260707-120000" in script
    assert "scans/latest" in script


def test_publish_results_rejects_run_dir_outside_repo(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-run"
    outside.mkdir(exist_ok=True)
    with pytest.raises(ValueError, match="run_dir must live under repo_root"):
        publish_results(outside, repo_root=tmp_path, runner=lambda *a, **k: None)  # type: ignore[arg-type,return-value]
