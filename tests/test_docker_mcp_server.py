"""Smoke tests for tools/docker-mcp/server.py (the Claude MCP bridge).

The server module is not a package and depends on the ``mcp`` SDK, which is
not a runtime dependency of the pipeline. We stub ``mcp.server.fastmcp`` with
a no-op FastMCP before loading the module, then exercise the pure logic:
argument validation, env translation, subprocess wrapping and exit-code
whitelisting. No docker calls are made — every test either stops at
validation or runs a tiny ``sys.executable`` command.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = REPO_ROOT / "tools" / "docker-mcp" / "server.py"


class _StubFastMCP:
    def __init__(self, _name: str):
        self.tools: dict[str, object] = {}

    def tool(self):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorator

    def run(self) -> None:  # pragma: no cover - never called in tests
        raise AssertionError("run() must not be invoked by tests")


@pytest.fixture(scope="module")
def server(tmp_path_factory: pytest.TempPathFactory):
    project_dir = tmp_path_factory.mktemp("el-sca-dir")
    stub_pkg = types.ModuleType("mcp")
    stub_server = types.ModuleType("mcp.server")
    stub_fastmcp = types.ModuleType("mcp.server.fastmcp")
    stub_fastmcp.FastMCP = _StubFastMCP
    saved = {k: sys.modules.get(k) for k in ("mcp", "mcp.server", "mcp.server.fastmcp")}
    sys.modules["mcp"] = stub_pkg
    sys.modules["mcp.server"] = stub_server
    sys.modules["mcp.server.fastmcp"] = stub_fastmcp
    import os

    old_env = os.environ.get("EL_SCA_DIR")
    os.environ["EL_SCA_DIR"] = str(project_dir)
    try:
        spec = importlib.util.spec_from_file_location("docker_mcp_server_under_test", SERVER_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        yield module
    finally:
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
        if old_env is None:
            os.environ.pop("EL_SCA_DIR", None)
        else:
            os.environ["EL_SCA_DIR"] = old_env


def test_tail_returns_last_lines(server):
    text = "\n".join(str(i) for i in range(100))
    tail = server._tail(text, n=10)
    assert tail.splitlines() == [str(i) for i in range(90, 100)]
    assert server._tail(None) == ""


def test_proxy_env_translates_localhost_for_containers(server):
    env = server._proxy_env("http://127.0.0.1:10808")
    assert env["HTTP_PROXY"] == "http://host.docker.internal:10808"
    assert env["https_proxy"] == "http://host.docker.internal:10808"


def test_proxy_env_without_proxy_sets_compose_defaults(server):
    env = server._proxy_env(None)
    assert "SCAN_TARGET_HOST" in env
    assert "EXTRACT_INPUT_HOST" in env


def test_run_executes_command_and_captures_output(server):
    result = server._run([sys.executable, "-c", "print('bridge-ok')"], timeout=30)
    assert result["ok"] is True
    assert result["returncode"] == 0
    assert "bridge-ok" in result["stdout_tail"]


def test_run_whitelists_exit_1_only_when_allowed(server):
    args = [sys.executable, "-c", "raise SystemExit(1)"]
    assert server._run(args, timeout=30)["ok"] is False
    assert server._run(args, timeout=30, allow_exit1=True)["ok"] is True


def test_run_reports_timeout(server):
    result = server._run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    assert result["ok"] is False
    assert "timeout" in result["error"]


def test_run_refuses_missing_project_dir(server, monkeypatch):
    monkeypatch.setattr(server, "PROJECT_DIR", Path("/nonexistent/el-sca"))
    result = server._run([sys.executable, "-c", "print('x')"], timeout=10)
    assert result["ok"] is False
    assert "EL_SCA_DIR" in result["error"]


def test_run_scan_validates_tool_and_target(server):
    assert "tool must be one of" in server.run_scan("/tmp/x", tool="nmap")["error"]
    for bad_target in ("", ".", "/", "  "):
        assert "refusing" in server.run_scan(bad_target)["error"]


def test_run_scan_async_validates_like_sync(server):
    assert "tool must be one of" in server.run_scan_async("/tmp/x", tool="nmap")["error"]
    assert "refusing" in server.run_scan_async("/")["error"]


def test_scan_status_without_jobs_is_helpful(server):
    result = server.scan_status()
    assert result["ok"] is False
    assert "mcp-jobs" in result["error"]


def test_update_db_validates_tool(server):
    assert "tool must be one of" in server.update_db("syft")["error"]


def test_compose_logs_validates_service(server):
    result = server.compose_logs("not-a-service")
    assert result["ok"] is False
    assert "grype-scanner" in result["known"]


def test_expected_tools_are_registered(server):
    registered = set(server.mcp.tools)
    assert {
        "compose_config",
        "list_services",
        "compose_ps",
        "update_doctor",
        "compose_logs",
        "update_db",
        "run_scan",
        "run_scan_async",
        "scan_status",
        "start_dashboard",
        "stop_dashboard",
        "compose_down",
    } <= registered


def test_route_plan_tool_registered(server):
    assert "route_plan" in server.mcp.tools


def test_update_db_all_shares_one_route_probe(server, monkeypatch):
    """update_db('all') must run every updater with its own per-tool route,
    probing the network exactly once (one _ensure_route_plan call)."""
    calls = {"plan": 0}
    plan = {
        "plan": {
            "trivy": {"proxy_url": "socks5h://host.docker.internal:10808", "transport": "host-socks:10808"},
            "grype": {"proxy_url": "socks5h://host.docker.internal:10808", "transport": "host-socks:10808"},
            "cve_bin_tool": {"proxy_url": "http://tinyproxy:8888", "transport": "sidecar-http"},
        }
    }

    def fake_ensure(**kw):
        calls["plan"] += 1
        return plan

    ran: list[tuple[str, str | None]] = []

    def fake_update_one(tool, proxy, extra_env):
        ran.append((tool, proxy))
        return {"ok": True, "extra_env": list(extra_env)}

    monkeypatch.setattr(server, "_ensure_route_plan", fake_ensure)
    monkeypatch.setattr(server, "_update_one", fake_update_one)
    monkeypatch.setattr(server, "_run_volume_init", lambda: {"ok": True})
    monkeypatch.delenv("EL_SCA_AUTO_ROUTE", raising=False)

    out = server.update_db("all")
    assert out["ok"] is True
    assert out["volume_init_ok"] is True
    assert calls["plan"] == 1
    assert [t for t, _ in ran] == ["trivy", "grype", "cve-bin-tool"]
    by_tool = dict(ran)
    assert by_tool["trivy"] == "socks5h://host.docker.internal:10808"
    assert by_tool["cve-bin-tool"] == "http://tinyproxy:8888"
    # cve-bin-tool's enrichment bridge follows the same HTTP route.
    assert out["results"]["cve-bin-tool"]["extra_env"] == [
        "-e",
        "CVE_BIN_TOOL_ENRICH_PROXY=http://tinyproxy:8888",
    ]
    assert out["route"]["cve-bin-tool"]["proxy_url"] == "http://tinyproxy:8888"


def test_update_db_explicit_proxy_skips_probe(server, monkeypatch):
    probed = {"n": 0}
    monkeypatch.setattr(server, "_ensure_route_plan", lambda **kw: probed.__setitem__("n", probed["n"] + 1))
    monkeypatch.setattr(server, "_update_one", lambda tool, proxy, extra: {"ok": True, "proxy": proxy})
    monkeypatch.setattr(server, "_run_volume_init", lambda: {"ok": True})
    out = server.update_db("trivy", proxy="http://127.0.0.1:3128")
    assert probed["n"] == 0
    assert out["proxy"] == "http://127.0.0.1:3128"


def test_update_db_auto_route_off_via_env(server, monkeypatch):
    monkeypatch.setenv("EL_SCA_AUTO_ROUTE", "0")
    monkeypatch.setattr(
        server, "_ensure_route_plan", lambda **kw: (_ for _ in ()).throw(AssertionError("must not probe"))
    )
    monkeypatch.setattr(server, "_update_one", lambda tool, proxy, extra: {"ok": True, "proxy": proxy})
    monkeypatch.setattr(server, "_run_volume_init", lambda: {"ok": True})
    out = server.update_db("grype")
    assert out["ok"] is True
    assert out["proxy"] is None


def test_update_db_runs_volume_init_before_updaters(server, monkeypatch):
    """update_db must chown volumes (volume-init) before any updater runs."""
    order: list[str] = []
    monkeypatch.setattr(server, "_run_volume_init", lambda: order.append("volinit") or {"ok": True})
    monkeypatch.setattr(
        server, "_update_one", lambda tool, proxy, extra: order.append(f"update:{tool}") or {"ok": True}
    )
    monkeypatch.setenv("EL_SCA_AUTO_ROUTE", "0")
    server.update_db("grype")
    assert order == ["volinit", "update:grype"]


def test_update_db_only_source_rejected_for_all(server):
    out = server.update_db("all", only_source="NVD")
    assert out["ok"] is False
    assert "cve-bin-tool only" in out["error"]
