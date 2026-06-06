"""Smoke tests for tools/docker-mcp/server.py.

Tests pure-logic helpers (_proxy_env, _tail) and input-validation guards
without requiring Docker or a running MCP server.  The ``mcp`` package is
mocked at import time so the suite passes even when it is not installed.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "tools" / "docker-mcp" / "server.py"


def _load_server():
    """Load server.py with mcp dependencies mocked out.

    Temporarily injects mocks for the ``mcp`` namespace so the
    ``from mcp.server.fastmcp import FastMCP`` import doesn't fail when the
    package is absent.

    Key trick: ``@mcp.tool()`` is a decorator factory.  With a plain MagicMock
    it would replace every decorated function with a MagicMock, making the real
    validation logic unreachable.  Instead we give ``mcp_instance.tool`` a
    pass-through decorator factory so the original function bodies are preserved.
    """

    def _passthrough_tool(*_args, **_kwargs):
        """Decorator factory: @mcp.tool() → returns function unchanged."""

        def decorator(fn):
            return fn

        return decorator

    mcp_instance = MagicMock()
    mcp_instance.tool = _passthrough_tool

    fake_fastmcp_cls = MagicMock(return_value=mcp_instance)

    fake_fastmcp_mod = MagicMock()
    fake_fastmcp_mod.FastMCP = fake_fastmcp_cls

    stubs = {
        "mcp": MagicMock(),
        "mcp.server": MagicMock(),
        "mcp.server.fastmcp": fake_fastmcp_mod,
    }
    saved = {k: sys.modules.get(k) for k in stubs}
    sys.modules.update(stubs)
    try:
        spec = importlib.util.spec_from_file_location("docker_mcp_server", SERVER_PATH)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        for key, orig in saved.items():
            if orig is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = orig
    return mod


@pytest.fixture(scope="module")
def server():
    return _load_server()


# ---------------------------------------------------------------------------
# _tail — pure string helper
# ---------------------------------------------------------------------------


def test_tail_returns_last_n_lines(server):
    assert server._tail("a\nb\nc\nd", 2) == "c\nd"


def test_tail_none_returns_empty(server):
    assert server._tail(None) == ""


def test_tail_fewer_lines_than_n(server):
    assert server._tail("only\ntwo", 10) == "only\ntwo"


def test_tail_single_line(server):
    assert server._tail("hello", 1) == "hello"


# ---------------------------------------------------------------------------
# _proxy_env — environment variable injection
# ---------------------------------------------------------------------------


def test_proxy_env_none_sets_required_defaults(server):
    env = server._proxy_env(None)
    # These must always be present so compose guard clauses do not fail.
    assert "SCAN_TARGET_HOST" in env
    assert "EXTRACT_INPUT_HOST" in env


def test_proxy_env_translates_localhost(server):
    env = server._proxy_env("http://localhost:10808")
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        val = env.get(key, "")
        assert "host.docker.internal" in val, f"{key} should be translated"
        assert "localhost" not in val, f"{key} must not contain 'localhost'"


def test_proxy_env_translates_127_0_0_1(server):
    env = server._proxy_env("http://127.0.0.1:1080")
    assert "host.docker.internal" in env.get("ALL_PROXY", "")
    assert "127.0.0.1" not in env.get("ALL_PROXY", "")


def test_proxy_env_leaves_remote_proxy_unchanged(server):
    proxy = "http://proxy.corp.example.com:8080"
    env = server._proxy_env(proxy)
    assert env.get("HTTP_PROXY") == proxy


def test_proxy_env_none_does_not_overwrite_existing_proxy(server, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://existing:9999")
    env = server._proxy_env(None)
    # With proxy=None we do NOT inject anything — existing env is preserved.
    assert env.get("HTTP_PROXY") == "http://existing:9999"


# ---------------------------------------------------------------------------
# compose_logs — service validation
# ---------------------------------------------------------------------------


def test_compose_logs_rejects_unknown_service(server):
    result = server.compose_logs("not-a-real-service-xyz")
    assert result["ok"] is False
    assert "unknown service" in result["error"]
    assert "known" in result  # help field shows the allow-list


def test_compose_logs_accepts_known_service_in_allowlist(server):
    # Known-service validation passes before docker is called; PROJECT_DIR
    # check inside _run will fail gracefully if the dir doesn't exist —
    # that's fine, we're testing the allow-list guard here.
    assert "grype-scanner" in server.KNOWN_SERVICES  # sanity: still present


# ---------------------------------------------------------------------------
# update_db — tool validation
# ---------------------------------------------------------------------------


def test_update_db_rejects_syft(server):
    # syft has no updater service — correctly rejected.
    result = server.update_db("syft")
    assert result["ok"] is False
    assert "tool must be" in result["error"]


def test_update_db_rejects_unknown_tool(server):
    result = server.update_db("nessus")
    assert result["ok"] is False


def test_update_db_known_tools_are_accepted_by_allowlist(server):
    for tool in ("trivy", "grype", "cve-bin-tool"):
        assert tool in server.SCANNER_TOOLS


# ---------------------------------------------------------------------------
# run_scan — target + tool validation
# ---------------------------------------------------------------------------


def test_run_scan_rejects_empty_target(server):
    result = server.run_scan("")
    assert result["ok"] is False
    assert "refusing" in result["error"]


def test_run_scan_rejects_whitespace_target(server):
    result = server.run_scan("   ")
    assert result["ok"] is False


def test_run_scan_rejects_root_target(server):
    result = server.run_scan("/")
    assert result["ok"] is False


def test_run_scan_rejects_dot_target(server):
    result = server.run_scan(".")
    assert result["ok"] is False


def test_run_scan_rejects_unknown_tool(server):
    result = server.run_scan("/some/legit/path", tool="nessus")
    assert result["ok"] is False
    assert "tool must be" in result["error"]


# ---------------------------------------------------------------------------
# _run — PROJECT_DIR missing (no docker required)
# ---------------------------------------------------------------------------


def test_run_returns_error_when_project_dir_missing(tmp_path):
    mod = _load_server()
    mod.PROJECT_DIR = tmp_path / "does-not-exist"
    result = mod._run(["docker", "compose", "config", "-q"], timeout=5)
    assert result["ok"] is False
    assert "not found" in result.get("error", "").lower()


# ---------------------------------------------------------------------------
# Constants sanity
# ---------------------------------------------------------------------------


def test_known_services_nonempty(server):
    assert len(server.KNOWN_SERVICES) > 10  # stack has many services


def test_scanner_tools_subset_of_all_scan_tools(server):
    assert server.SCANNER_TOOLS.issubset(server.ALL_SCAN_TOOLS)


def test_known_profiles_contains_core_profiles(server):
    for profile in ("scan", "update", "offline", "airgap", "extract"):
        assert profile in server.KNOWN_PROFILES


def test_all_scan_tools_contains_expected(server):
    for tool in ("trivy", "grype", "cve-bin-tool", "syft", "all"):
        assert tool in server.ALL_SCAN_TOOLS
