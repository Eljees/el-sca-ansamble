from resilient_updates.config import load_config
from resilient_updates.source_policy import build_sources


def test_build_sources_orders_by_priority():
    config = load_config("tests/fixtures/feed_sources.example.yaml")
    config["custom_sources"]["entries"] = [
        {
            "name": "custom-second",
            "type": "http",
            "url": "https://example.invalid/secondary",
            "tool": "grype",
            "layer": "grype-db",
            "priority": 20,
            "enabled": True,
            "trust_level": "custom",
        }
    ]
    sources = build_sources(config, "grype", "grype-db")
    assert [item.priority for item in sources] == [10, 20]
    assert sources[0].name == "primary"
