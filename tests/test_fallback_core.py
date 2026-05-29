"""Unit tests for fallback.py helpers not covered by test_fallback_order.py.

Targets:
- classify_http_status: direct status-code → FailureReason mapping
- classify_exception: exception type → FailureReason mapping
- build_session: ALL_PROXY env-var wiring
- attempt_sources: empty-response path, 429 retry, all-sources-fail
"""

from __future__ import annotations

import socket

import pytest
import requests
import requests.exceptions

from resilient_updates.fallback import (
    FailureReason,
    attempt_sources,
    build_session,
    classify_exception,
    classify_http_status,
)
from resilient_updates.source_policy import SourceCandidate


def _src(name: str = "primary") -> SourceCandidate:
    return SourceCandidate(
        priority=10,
        name=name,
        url=f"http://127.0.0.1:0/{name}",
        tool="grype",
        layer="grype-db",
    )


# ---------------------------------------------------------------------------
# classify_http_status
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.parametrize(
    "code,expected",
    [
        (200, None),
        (204, None),
        (301, None),
        (429, FailureReason.HTTP_429),
        (401, FailureReason.AUTH_FAILURE),
        (403, FailureReason.AUTH_FAILURE),
        (404, FailureReason.HTTP_4XX),
        (422, FailureReason.HTTP_4XX),
        (500, FailureReason.HTTP_5XX),
        (502, FailureReason.HTTP_5XX),
        (503, FailureReason.HTTP_5XX),
        (599, FailureReason.HTTP_5XX),
    ],
)
def test_classify_http_status(code, expected):
    assert classify_http_status(code) is expected


# ---------------------------------------------------------------------------
# classify_exception
# ---------------------------------------------------------------------------


def test_classify_exception_timeout():
    assert classify_exception(requests.Timeout()) is FailureReason.TIMEOUT


def test_classify_exception_connection_error():
    assert classify_exception(requests.ConnectionError()) is FailureReason.DNS_OR_NETWORK


def test_classify_exception_socket_gaierror():
    exc = socket.gaierror("name or service not known")
    assert classify_exception(exc) is FailureReason.DNS_OR_NETWORK


def test_classify_exception_invalid_schema():
    exc = requests.exceptions.InvalidSchema("No connection adapters")
    assert classify_exception(exc) is FailureReason.INVALID_SCHEMA


def test_classify_exception_unknown():
    assert classify_exception(RuntimeError("unexpected")) is FailureReason.UNKNOWN


# ---------------------------------------------------------------------------
# build_session
# ---------------------------------------------------------------------------


def test_build_session_explicit_proxies():
    proxies = {"http": "socks5h://proxy:1080", "https": "socks5h://proxy:1080"}
    sess = build_session(proxies)
    assert sess.proxies.get("http") == "socks5h://proxy:1080"
    assert sess.proxies.get("https") == "socks5h://proxy:1080"


def test_build_session_all_proxy_env(monkeypatch):
    monkeypatch.setenv("ALL_PROXY", "socks5h://envproxy:1080")
    # Unset any explicit HTTP_PROXY so the ALL_PROXY branch fires
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    sess = build_session()
    assert sess.proxies.get("http") == "socks5h://envproxy:1080"
    assert sess.proxies.get("https") == "socks5h://envproxy:1080"


def test_build_session_no_proxies_returns_session():
    sess = build_session()
    assert isinstance(sess, requests.Session)


# ---------------------------------------------------------------------------
# attempt_sources — empty response
# ---------------------------------------------------------------------------


def test_attempt_sources_empty_response_classified_correctly():
    src = _src("empty-server")

    def downloader(url, timeout, session, headers):
        return 200, b""  # 200 but no body

    selected, payload, attempts = attempt_sources(
        [src],
        timeout=1,
        retry_count=0,
        backoff_seconds=0,
        retry_status_codes=[],
        downloader=downloader,
    )
    assert selected is None
    assert payload is None
    assert attempts[0].reason is FailureReason.EMPTY_RESPONSE


# ---------------------------------------------------------------------------
# attempt_sources — 429 retried up to retry_count then gives up
# ---------------------------------------------------------------------------


def test_attempt_sources_429_retried_then_fails():
    src = _src("rate-limited")
    call_log: list[int] = []

    def downloader(url, timeout, session, headers):
        call_log.append(1)
        return 429, b"slow down"

    selected, _payload, attempts = attempt_sources(
        [src],
        timeout=1,
        retry_count=2,
        backoff_seconds=0,
        retry_status_codes=[429],
        downloader=downloader,
    )
    assert selected is None
    assert len(call_log) == 3  # initial + 2 retries
    assert all(a.reason is FailureReason.HTTP_429 for a in attempts)


# ---------------------------------------------------------------------------
# attempt_sources — all sources fail → None winner
# ---------------------------------------------------------------------------


def test_attempt_sources_all_fail_returns_none():
    sources = [_src("a"), _src("b")]

    def downloader(url, timeout, session, headers):
        return 503, b"down"

    selected, payload, attempts = attempt_sources(
        sources,
        timeout=1,
        retry_count=0,
        backoff_seconds=0,
        retry_status_codes=[503],
        downloader=downloader,
    )
    assert selected is None
    assert payload is None
    assert len(attempts) == 2
