"""Unit tests for resilient_updates.config helpers.

test_config_validation.py has one smoke test that checks combined validation
paths.  This file covers the individual helpers (parse_duration_hours,
validate_proxy_config, validate_config_data corner cases) that the smoke
test leaves uncovered.
"""

from __future__ import annotations

import pytest

from resilient_updates.config import (
    load_config,
    parse_duration_hours,
    runtime_override_path,
    validate_config_data,
    validate_proxy_config,
)

FIXTURE = "tests/fixtures/feed_sources.example.yaml"


def _good() -> dict:
    return load_config(FIXTURE)


# ---------------------------------------------------------------------------
# parse_duration_hours
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_parse_duration_hours_hours():
    assert parse_duration_hours("24h") == 24
    assert parse_duration_hours("1h") == 1
    assert parse_duration_hours("168h") == 168


def test_parse_duration_hours_minutes():
    assert parse_duration_hours("60m") == 1
    assert parse_duration_hours("120m") == 2


def test_parse_duration_hours_minutes_rounds_up_to_one():
    # 30m < 1h  → rounds to 1 to avoid zero
    assert parse_duration_hours("30m") == 1


def test_parse_duration_hours_invalid_raises():
    with pytest.raises(ValueError, match="Unsupported duration format"):
        parse_duration_hours("2d")
    with pytest.raises(ValueError, match="Unsupported duration format"):
        parse_duration_hours("24")
    with pytest.raises(ValueError, match="Unsupported duration format"):
        parse_duration_hours("")


# ---------------------------------------------------------------------------
# validate_config_data — individual error paths
# ---------------------------------------------------------------------------


def test_missing_top_level_section_reported():
    config = _good()
    del config["syft"]
    errors = validate_config_data(config)
    assert any("missing top-level section: syft" in e for e in errors)


def test_grype_internal_url_required():
    config = _good()
    config["grype"]["internal_update_url"] = ""
    errors = validate_config_data(config)
    assert any("internal_update_url is required" in e for e in errors)


def test_grype_validation_flags_must_be_enabled():
    config = _good()
    config["grype"]["validation"]["validate_hash"] = False
    errors = validate_config_data(config)
    assert any("validate_hash must stay enabled" in e for e in errors)

    config2 = _good()
    config2["grype"]["validation"]["validate_age"] = False
    errors2 = validate_config_data(config2)
    assert any("validate_age must stay enabled" in e for e in errors2)


def test_syft_default_from_must_be_in_scan_sources():
    config = _good()
    config["syft"]["default_from"] = "nonexistent-source"
    errors = validate_config_data(config)
    assert any("default_from must exist in syft.scan_sources" in e for e in errors)


def test_syft_empty_scan_sources():
    config = _good()
    config["syft"]["scan_sources"] = []
    errors = validate_config_data(config)
    assert any("scan_sources must not be empty" in e for e in errors)


def test_insecure_key_detected():
    config = _good()
    # Inject an insecure key into a nested dict that repr() will stringify
    config["trivy"]["ignore_signatures"] = True
    errors = validate_config_data(config)
    assert any("unsafe setting detected: ignore_signatures" in e for e in errors)


def test_all_sources_disabled_is_an_error():
    config = _good()
    for src in config["trivy"]["db_repositories"]:
        src["enabled"] = False
    errors = validate_config_data(config)
    assert any("all sources are disabled" in e for e in errors)


def test_source_without_url_is_an_error():
    config = _good()
    config["grype"]["upstream_update_urls"].append(
        {"name": "no-url", "url": "", "priority": 99, "enabled": True}
    )
    errors = validate_config_data(config)
    assert any("source without url" in e for e in errors)


def test_valid_fixture_has_no_errors():
    errors = validate_config_data(_good())
    assert errors == [], f"Unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# validate_proxy_config
# ---------------------------------------------------------------------------


def test_proxy_valid_socks5():
    config = _good()
    config["proxy"] = {"http": "socks5h://proxy.local:1080", "https": "socks5h://proxy.local:1080"}
    assert validate_proxy_config(config) == []


def test_proxy_invalid_scheme_reported():
    config = _good()
    config["proxy"] = {"http": "ftp://bad-proxy:21"}
    errors = validate_proxy_config(config)
    assert any("unsupported scheme 'ftp'" in e for e in errors)


def test_proxy_empty_section_is_valid():
    config = _good()
    config["proxy"] = {}
    assert validate_proxy_config(config) == []


def test_proxy_absent_section_is_valid():
    config = _good()
    config.pop("proxy", None)
    assert validate_proxy_config(config) == []


# ---------------------------------------------------------------------------
# runtime override (configs/feed_sources.runtime.yaml, D-NEW-2)
# ---------------------------------------------------------------------------


def _write_cfg_pair(tmp_path, static: str, runtime: str | None):
    cfg = tmp_path / "feed_sources.yaml"
    cfg.write_text(static, encoding="utf-8")
    if runtime is not None:
        (tmp_path / "feed_sources.runtime.yaml").write_text(runtime, encoding="utf-8")
    return cfg


_STATIC = "proxy:\n  default_chain: corp\n  chains:\n    direct: []\n    corp: []\n    via-vpn: []\n"


def test_runtime_override_path_naming(tmp_path):
    assert runtime_override_path("configs/feed_sources.yaml").name == "feed_sources.runtime.yaml"


def test_load_config_applies_runtime_override(tmp_path):
    cfg = _write_cfg_pair(tmp_path, _STATIC, "default_chain: via-vpn\n")
    assert load_config(cfg)["proxy"]["default_chain"] == "via-vpn"


def test_load_config_without_runtime_file_keeps_static(tmp_path):
    cfg = _write_cfg_pair(tmp_path, _STATIC, None)
    assert load_config(cfg)["proxy"]["default_chain"] == "corp"


def test_load_config_ignores_undeclared_runtime_chain(tmp_path):
    cfg = _write_cfg_pair(tmp_path, _STATIC, "default_chain: evil\n")
    assert load_config(cfg)["proxy"]["default_chain"] == "corp"


def test_load_config_ignores_malformed_runtime_file(tmp_path):
    cfg = _write_cfg_pair(tmp_path, _STATIC, "{not yaml: [")
    assert load_config(cfg)["proxy"]["default_chain"] == "corp"
