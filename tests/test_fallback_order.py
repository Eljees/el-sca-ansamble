import requests.exceptions

from resilient_updates.fallback import FailureReason, attempt_sources
from resilient_updates.source_policy import SourceCandidate


def test_primary_timeout_falls_back_to_secondary():
    sources = [
        SourceCandidate(priority=10, name="primary", url="https://primary", tool="grype", layer="grype-db"),
        SourceCandidate(
            priority=20, name="secondary", url="https://secondary", tool="grype", layer="grype-db"
        ),
    ]

    responses = {
        "https://primary": TimeoutError("slow"),
        "https://secondary": (200, b"ok"),
    }

    def downloader(url, timeout, session, headers):
        value = responses[url]
        if isinstance(value, Exception):
            raise value
        return value

    selected, payload, attempts = attempt_sources(
        sources,
        timeout=1,
        retry_count=0,
        backoff_seconds=0,
        retry_status_codes=[429, 500],
        downloader=downloader,
    )
    assert selected is not None
    assert selected.name == "secondary"
    assert payload == b"ok"
    assert len(attempts) == 2


# ---------------------------------------------------------------------------
# InvalidSchema (OCI) is non-retryable — must not retry even when retry_count > 0
# ---------------------------------------------------------------------------


def test_invalid_schema_is_not_retried():
    source = SourceCandidate(
        priority=10, name="oci", url="oci://registry/image:tag", tool="trivy", layer="trivy-db"
    )
    call_count = 0

    def downloader(url, timeout, session, headers):
        nonlocal call_count
        call_count += 1
        raise requests.exceptions.InvalidSchema("No connection adapters were found for 'oci://...'")

    selected, _payload, attempts = attempt_sources(
        [source],
        timeout=1,
        retry_count=3,
        backoff_seconds=0,
        retry_status_codes=[429, 500],
        downloader=downloader,
    )
    assert selected is None
    assert call_count == 1, "InvalidSchema must not be retried even when retry_count > 0"
    assert attempts[0].reason == FailureReason.INVALID_SCHEMA


# ---------------------------------------------------------------------------
# AUTH_FAILURE (401/403) is non-retryable
# ---------------------------------------------------------------------------


def test_auth_failure_401_is_not_retried():
    source = SourceCandidate(
        priority=10, name="protected", url="https://protected", tool="grype", layer="grype-db"
    )
    call_count = 0

    def downloader(url, timeout, session, headers):
        nonlocal call_count
        call_count += 1
        return 401, b"Unauthorized"

    selected, _payload, attempts = attempt_sources(
        [source],
        timeout=1,
        retry_count=3,
        backoff_seconds=0,
        retry_status_codes=[429, 500, 401],
        downloader=downloader,
    )
    assert selected is None
    assert call_count == 1, "AUTH_FAILURE must not be retried"
    assert attempts[0].reason == FailureReason.AUTH_FAILURE


def test_auth_failure_403_is_not_retried():
    source = SourceCandidate(
        priority=10, name="forbidden", url="https://forbidden", tool="grype", layer="grype-db"
    )
    call_count = 0

    def downloader(url, timeout, session, headers):
        nonlocal call_count
        call_count += 1
        return 403, b"Forbidden"

    selected, _payload, _attempts = attempt_sources(
        [source],
        timeout=1,
        retry_count=2,
        backoff_seconds=0,
        retry_status_codes=[403],
        downloader=downloader,
    )
    assert selected is None
    assert call_count == 1, "403 (AUTH_FAILURE) must not be retried"


# ---------------------------------------------------------------------------
# session argument is forwarded unchanged to the downloader
# ---------------------------------------------------------------------------


def test_session_is_forwarded_to_downloader():
    import requests as req

    source = SourceCandidate(priority=10, name="src", url="https://src", tool="grype", layer="grype-db")
    sentinel = req.Session()
    received = []

    def downloader(url, timeout, session, headers):
        received.append(session)
        return 200, b"ok"

    attempt_sources(
        [source],
        timeout=1,
        retry_count=0,
        backoff_seconds=0,
        retry_status_codes=[],
        downloader=downloader,
        session=sentinel,
    )
    assert received == [sentinel], "The session object must be forwarded unchanged to the downloader"


# ---------------------------------------------------------------------------
# 500 responses are retried up to retry_count times
# ---------------------------------------------------------------------------


def test_http_5xx_is_retried_up_to_retry_count():
    source = SourceCandidate(priority=10, name="flaky", url="https://flaky", tool="grype", layer="grype-db")
    call_count = 0

    def downloader(url, timeout, session, headers):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            return 500, b""
        return 200, b"recovered"

    selected, payload, _attempts = attempt_sources(
        [source],
        timeout=1,
        retry_count=3,
        backoff_seconds=0,
        retry_status_codes=[500],
        downloader=downloader,
    )
    assert selected is not None
    assert payload == b"recovered"
    assert call_count == 3
