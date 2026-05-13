from resilient_updates.config import load_config, validate_config_data


def test_config_validation_catches_duplicates_and_invalid_values():
    config = load_config("tests/fixtures/feed_sources.example.yaml")
    config["grype"]["upstream_update_urls"].append(
        {"name": "dup", "url": "", "priority": 10, "enabled": True}
    )
    config["cve_bin_tool"]["db_audit"]["required_sources"] = ["NVD", "UNKNOWN"]
    config["cve_bin_tool"]["db_audit"]["min_entries"]["WRONG"] = 1
    config["custom_sources"]["entries"].append(
        {
            "name": "broken",
            "type": "ftp",
            "url": "",
            "tool": "unknown",
            "layer": "bad-layer",
            "priority": 1,
            "auth_env": "bad-env",
            "enabled": True,
        }
    )
    errors = validate_config_data(config)
    assert any("duplicate priority 10" in item for item in errors)
    assert any("invalid type ftp" in item for item in errors)
    assert any("invalid auth_env placeholder" in item for item in errors)
    assert any("required_sources contains unknown sources" in item for item in errors)
    assert any("min_entries contains unknown source" in item for item in errors)
