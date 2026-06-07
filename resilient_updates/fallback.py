from __future__ import annotations

import os
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import url2pathname

import requests

from .source_policy import SourceCandidate


class FailureReason(str, Enum):  # noqa: UP042 — StrEnum requires py3.11
    TIMEOUT = "timeout"
    HTTP_429 = "http_429"
    HTTP_5XX = "http_5xx"
    HTTP_4XX = "http_4xx_non_retryable"
    CHECKSUM_MISMATCH = "checksum_mismatch"
    CORRUPT_ARTIFACT = "corrupt_artifact"
    STALE_DATA = "stale_data"
    AUTH_FAILURE = "auth_failure"
    DNS_OR_NETWORK = "dns_or_network_unavailable"
    INVALID_SCHEMA = "invalid_schema"
    EMPTY_RESPONSE = "empty_response"
    UNKNOWN = "unknown"


@dataclass
class AttemptResult:
    source: SourceCandidate
    success: bool
    reason: FailureReason | None
    message: str
    status_code: int | None = None


def build_session(proxies: dict[str, str] | None = None) -> requests.Session:
    """Create a requests.Session with proxy support.

    Priority order:
    1. *proxies* dict passed explicitly (comes from feed_sources.yaml ``proxy:`` section).
    2. Standard env vars HTTP_PROXY / HTTPS_PROXY / NO_PROXY — requests picks these up
       automatically, so nothing extra is needed here.
    3. ALL_PROXY / all_proxy — requests does *not* read ALL_PROXY natively; we wire it
       explicitly so SOCKS5 (``socks5h://...``) works out of the box.

    Note on Docker: ``127.0.0.1`` inside a container resolves to the container itself, not
    the host.  Use ``host.docker.internal`` (add ``extra_hosts: [host.docker.internal:host-
    gateway]`` in docker-compose) so proxies on the Windows/Linux host are reachable from
    containers.
    """
    sess = requests.Session()
    if proxies:
        # Explicit config overrides everything.
        sess.proxies.update(proxies)
    else:
        # requests reads HTTP_PROXY / HTTPS_PROXY / NO_PROXY automatically.
        # ALL_PROXY is a widely supported convention but requests ignores it —
        # wire it to both schemes so SOCKS5 works without extra config.
        all_proxy = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy")  # noqa: SIM112
        if all_proxy:
            sess.proxies.setdefault("http", all_proxy)
            sess.proxies.setdefault("https", all_proxy)
            # When we wire ALL_PROXY manually, requests no longer applies
            # NO_PROXY automatically for the manually-set entries.  Wire it
            # ourselves so internal hosts (127.0.0.1, localhost, private
            # ranges) bypass the SOCKS proxy as the operator intended.
            no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy")
            if no_proxy:
                sess.proxies.setdefault("no_proxy", no_proxy)
    return sess


def classify_http_status(status_code: int) -> FailureReason | None:
    if status_code == 429:
        return FailureReason.HTTP_429
    if status_code in {401, 403}:
        return FailureReason.AUTH_FAILURE
    if 500 <= status_code <= 599:
        return FailureReason.HTTP_5XX
    if 400 <= status_code <= 499:
        return FailureReason.HTTP_4XX
    return None


def classify_exception(exc: Exception) -> FailureReason:
    if isinstance(exc, requests.Timeout):
        return FailureReason.TIMEOUT
    if isinstance(exc, (requests.ConnectionError, socket.gaierror)):
        return FailureReason.DNS_OR_NETWORK
    if isinstance(exc, requests.exceptions.InvalidSchema):
        # "No connection adapters were found for 'oci://...'" -- protocol not supported.
        # This is not a network error: retrying will not help.
        return FailureReason.INVALID_SCHEMA
    return FailureReason.UNKNOWN


# Errors where retrying is pointless (permanent, not transient).
#
# Design note (D10): AUTH_FAILURE is listed here, which means that even if
# a caller passes ``retry_status_codes=[403]`` the inner loop stops
# immediately on an auth failure.  This is intentional: auth failures are
# almost always permanent in this context (wrong credentials / key
# revoked) and blind retries would just waste time and burn rate-limits.
# The test ``test_auth_failure_403_is_not_retried`` documents this
# contract explicitly.  To *actually* retry 401/403 you must also remove
# AUTH_FAILURE from this set (or don't classify 401/403 as AUTH_FAILURE).
_NON_RETRYABLE_REASONS = frozenset(
    {
        FailureReason.INVALID_SCHEMA,
        FailureReason.AUTH_FAILURE,
        FailureReason.HTTP_4XX,
    }
)


def fetch_bytes(
    url: str,
    timeout: int,
    session: requests.Session | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    parsed = urlparse(url)
    if parsed.scheme == "file":
        # urlparse leaves the path as '/C:/x/y' on Windows, which Path()
        # does not handle.  url2pathname() from urllib.request handles
        # the platform-specific quirks (drive letters, percent-decoding,
        # forward-vs-back slashes).  See docs/audit/10-defects.md.
        local_path = Path(url2pathname(parsed.path))
        payload = local_path.read_bytes()
        return 200, payload
    sess = session or build_session()
    # requests does not remove manually-wired SOCKS proxies when no_proxy
    # matches the target host.  Check explicitly and pass per-request
    # proxies=None to clear the proxy for bypassed addresses (e.g. mock
    # servers on 127.0.0.1 in tests, or internal hosts in production).
    _no_proxy = sess.proxies.get("no_proxy") or os.environ.get("NO_PROXY") or os.environ.get("no_proxy")
    from requests.utils import should_bypass_proxies as _bypass

    _req_proxies: dict[str, str | None] | None = (
        {"http": None, "https": None} if _bypass(url, no_proxy=_no_proxy) else None
    )
    response = sess.get(url, timeout=timeout, headers=headers, proxies=_req_proxies)
    return response.status_code, response.content


def attempt_sources(
    sources: list[SourceCandidate],
    timeout: int,
    retry_count: int,
    backoff_seconds: int,
    retry_status_codes: list[int],
    downloader: Callable[
        [str, int, requests.Session | None, dict[str, str] | None], tuple[int, bytes]
    ] = fetch_bytes,
    session: requests.Session | None = None,
) -> tuple[SourceCandidate | None, bytes | None, list[AttemptResult]]:
    attempts: list[AttemptResult] = []
    for source in sources:
        headers = {}
        for attempt in range(retry_count + 1):
            try:
                status_code, payload = downloader(source.url, timeout, session, headers)
                reason = classify_http_status(status_code)
                if reason is None:
                    if not payload:
                        attempts.append(
                            AttemptResult(
                                source, False, FailureReason.EMPTY_RESPONSE, "empty response", status_code
                            )
                        )
                        break
                    attempts.append(AttemptResult(source, True, None, "ok", status_code))
                    return source, payload, attempts
                attempts.append(
                    AttemptResult(source, False, reason, f"http status {status_code}", status_code)
                )
                if (
                    reason in _NON_RETRYABLE_REASONS
                    or status_code not in retry_status_codes
                    or attempt >= retry_count
                ):
                    break
            except Exception as exc:  # pragma: no cover - covered via tests on classify result
                reason = classify_exception(exc)
                attempts.append(AttemptResult(source, False, reason, str(exc), None))
                if attempt >= retry_count or reason in _NON_RETRYABLE_REASONS:
                    break
            time.sleep(backoff_seconds)
    return None, None, attempts
