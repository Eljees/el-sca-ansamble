from resilient_updates.fallback import attempt_sources
from resilient_updates.source_policy import SourceCandidate


def test_primary_timeout_falls_back_to_secondary():
    sources = [
        SourceCandidate(priority=10, name="primary", url="https://primary", tool="grype", layer="grype-db"),
        SourceCandidate(priority=20, name="secondary", url="https://secondary", tool="grype", layer="grype-db"),
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
