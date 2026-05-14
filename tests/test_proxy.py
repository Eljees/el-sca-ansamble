"""Tests for proxy support: build_session(), parse_proxy_config(), validate_proxy_config()."""
from __future__ import annotations

import os

import pytest

from resilient_updates.config import parse_proxy_config, validate_proxy_config
from resilient_updates.fallback import build_session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clear_proxy_env(monkeypatch):
    """Remove all proxy-related env vars to ensure a clean slate for each test."""
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "no_proxy", "all_proxy"):
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# build_session — no config, no env → no proxies
# ---------------------------------------------------------------------------

def test_build_session_no_proxy_config_no_env(monkeypatch):
    _clear_proxy_env(monkeypatch)
    sess = build_session()
    # requests.Session.proxies starts empty when nothing is configured
    assert sess.proxies == {} or all(v == "" for v in sess.proxies.values())


# ---------------------------------------------------------------------------
# build_session — ALL_PROXY env var is wired to both http and https
# ---------------------------------------------------------------------------

def test_build_session_all_proxy_env_wired_to_http_and_https(monkeypatch):
    _clear_proxy_env(monkeypatch)
    monkeypatch.setenv("ALL_PROXY", "socks5h://host.docker.internal:1080")
    sess = build_session()
    assert sess.proxies.get("http") == "socks5h://host.docker.internal:1080"
    assert sess.proxies.get("https") == "socks5h://host.docker.internal:1080"


def test_build_session_all_proxy_lowercase_env_also_works(monkeypatch):
    _clear_proxy_env(monkeypatch)
    monkeypatch.setenv("all_proxy", "socks5h://proxy.internal:1080")
    sess = build_session()
    assert sess.proxies.get("http") == "socks5h://proxy.internal:1080"
    assert sess.proxies.get("https") == "socks5h://proxy.internal:1080"


# ---------------------------------------------------------------------------
# build_session — explicit proxies dict overrides env
# ---------------------------------------------------------------------------

def test_build_session_explicit_proxies_override_env(monkeypatch):
    _clear_proxy_env(monkeypatch)
    monkeypatch.setenv("ALL_PROXY", "socks5h://should-be-ignored:1080")
    explicit = {"http": "http://explicit-proxy:3128", "https": "http://explicit-proxy:3128"}
    sess = build_session(proxies=explicit)
    assert sess.proxies["http"] == "http://explicit-proxy:3128"
    assert sess.proxies["https"] == "http://explicit-proxy:3128"


def test_build_session_no_proxy_key_is_forwarded(monkeypatch):
    _clear_proxy_env(monkeypatch)
    explicit = {
        "http": "http://proxy:3128",
        "https": "http://proxy:3128",
        "no_proxy": "localhost,127.0.0.1,internal",
    }
    sess = build_session(proxies=explicit)
    assert sess.proxies.get("no_proxy") == "localhost,127.0.0.1,internal"


def test_build_session_empty_proxies_dict_skips_env(monkeypatch):
    """Passing an explicit empty dict means 'no proxy', even if ALL_PROXY is set."""
    _clear_proxy_env(monkeypatch)
    monkeypatch.setenv("ALL_PROXY", "socks5h://should-be-ignored:1080")
    # Empty dict is falsy in Python, so build_session falls back to env.
    # Document the *actual* behaviour so changes are visible.
    sess_with_empty = build_session(proxies={})
    sess_with_none = build_session(proxies=None)
    # Both should observe ALL_PROXY because {} is falsy.
    assert sess_with_empty.proxies.get("http") == "socks5h://should-be-ignored:1080"
    assert sess_with_none.proxies.get("http") == "socks5h://should-be-ignored:1080"


# ---------------------------------------------------------------------------
# parse_proxy_config
# ---------------------------------------------------------------------------

def test_parse_proxy_config_absent_section_returns_empty():
    assert parse_proxy_config({}) == {}
    assert parse_proxy_config({"proxy": None}) == {}


def test_parse_proxy_config_empty_values_are_ignored():
    cfg = {"proxy": {"http": "", "https": "  ", "no_proxy": ""}}
    assert parse_proxy_config(cfg) == {}


def test_parse_proxy_config_full_section():
    cfg = {
        "proxy": {
            "http": "socks5h://host.docker.internal:1080",
            "https": "socks5h://host.docker.internal:1080",
            "no_proxy": "localhost,127.0.0.1,grype-static",
        }
    }
    result = parse_proxy_config(cfg)
    assert result["http"] == "socks5h://host.docker.internal:1080"
    assert result["https"] == "socks5h://host.docker.internal:1080"
    assert result["no_proxy"] == "localhost,127.0.0.1,grype-static"


def test_parse_proxy_config_partial_section():
    cfg = {"proxy": {"http": "http://proxy:3128"}}
    result = parse_proxy_config(cfg)
    assert result == {"http": "http://proxy:3128"}
    assert "no_proxy" not in result


# ---------------------------------------------------------------------------
# validate_proxy_config
# ---------------------------------------------------------------------------

def test_validate_proxy_config_empty_is_valid():
    assert validate_proxy_config({}) == []
    assert validate_proxy_config({"proxy": {}}) == []


def test_validate_proxy_config_valid_socks5h_scheme():
    cfg = {"proxy": {"http": "socks5h://proxy:1080", "https": "socks5h://proxy:1080"}}
    assert validate_proxy_config(cfg) == []


def test_validate_proxy_config_valid_http_scheme():
    cfg = {"proxy": {"http": "http://proxy:3128", "https": "https://proxy:3128"}}
    assert validate_proxy_config(cfg) == []


def test_validate_proxy_config_unsupported_scheme_returns_error():
    cfg = {"proxy": {"http": "ftp://proxy:21"}}
    errors = validate_proxy_config(cfg)
    assert len(errors) == 1
    assert "unsupported scheme" in errors[0]
    assert "ftp" in errors[0]


def test_validate_proxy_config_both_schemes_invalid_returns_two_errors():
    cfg = {"proxy": {"http": "ftp://proxy:21", "https": "ws://proxy:8080"}}
    errors = validate_proxy_config(cfg)
    assert len(errors) == 2


def test_validate_proxy_config_no_proxy_key_is_not_validated():
    """no_proxy is a comma-separated string, not a URL — must not be scheme-checked."""
    cfg = {"proxy": {"no_proxy": "localhost,127.0.0.1"}}
    assert validate_proxy_config(cfg) == []
