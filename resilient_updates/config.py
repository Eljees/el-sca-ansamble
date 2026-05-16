from __future__ import annotations

from pathlib import Path
import re
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path("configs/feed_sources.yaml")
KNOWN_CUSTOM_TYPES = {"oci-registry", "http", "file", "git", "s3-compatible"}
KNOWN_TOOLS = {"trivy", "grype", "cve_bin_tool", "syft"}
KNOWN_LAYERS = {
    "trivy-db",
    "trivy-java-db",
    "trivy-checks",
    "grype-db",
    "cve-bin-tool-export",
    "cve-bin-tool-mirror",
    "syft-source",
}
AUTH_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
INSECURE_KEYS = {"ignore_signatures", "disable_validation", "insecure_registry", "allow_stale_forever"}
KNOWN_CVE_DATA_SOURCES = {"NVD", "OSV", "GAD", "REDHAT", "CURL", "EPSS", "PURL2CPE", "RSD"}


def load_config(path: str | Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def parse_duration_hours(value: str) -> int:
    match = re.fullmatch(r"(?P<count>\d+)(?P<unit>[hm])", value.strip())
    if not match:
        raise ValueError(f"Unsupported duration format: {value}")
    count = int(match.group("count"))
    unit = match.group("unit")
    return count if unit == "h" else max(1, count // 60)


def _validate_named_sources(items: list[dict[str, Any]], field: str, errors: list[str]) -> None:
    seen_priorities: set[int] = set()
    enabled_count = 0
    for item in items:
        if not item.get("url"):
            errors.append(f"{field}: source without url")
        priority = item.get("priority")
        if priority in seen_priorities:
            errors.append(f"{field}: duplicate priority {priority}")
        else:
            seen_priorities.add(priority)
        if item.get("enabled", True):
            enabled_count += 1
    if items and enabled_count == 0:
        errors.append(f"{field}: all sources are disabled")


def validate_config_data(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for tool in ("trivy", "grype", "cve_bin_tool", "syft", "custom_sources"):
        if tool not in config:
            errors.append(f"missing top-level section: {tool}")

    trivy = config.get("trivy", {})
    for field in ("db_repositories", "java_db_repositories", "checks_bundle_repositories"):
        _validate_named_sources(trivy.get(field, []), f"trivy.{field}", errors)
    if "db_status" in trivy:
        try:
            parse_duration_hours(trivy["db_status"].get("warning_age", "24h"))
        except ValueError as exc:
            errors.append(str(exc))

    grype = config.get("grype", {})
    if not grype.get("internal_update_url"):
        errors.append("grype.internal_update_url is required")
    _validate_named_sources(grype.get("upstream_update_urls", []), "grype.upstream_update_urls", errors)
    validation = grype.get("validation", {})
    if not validation.get("validate_hash", False):
        errors.append("grype.validation.validate_hash must stay enabled")
    if not validation.get("validate_age", False):
        errors.append("grype.validation.validate_age must stay enabled")
    try:
        parse_duration_hours(validation.get("max_allowed_built_age", "72h"))
    except ValueError as exc:
        errors.append(str(exc))
    if "db_status" in grype:
        try:
            parse_duration_hours(grype["db_status"].get("warning_age", "24h"))
        except ValueError as exc:
            errors.append(str(exc))

    cve_cfg = config.get("cve_bin_tool", {})
    if not cve_cfg.get("nvd_modes"):
        errors.append("cve_bin_tool.nvd_modes must not be empty")
    _validate_named_sources(cve_cfg.get("mirrors", []), "cve_bin_tool.mirrors", errors)
    declared_sources = set(cve_cfg.get("data_sources", []))
    unknown_declared_sources = declared_sources - KNOWN_CVE_DATA_SOURCES
    if unknown_declared_sources:
        errors.append(f"cve_bin_tool.data_sources contains unknown sources: {sorted(unknown_declared_sources)}")
    db_audit = cve_cfg.get("db_audit", {})
    required_sources = db_audit.get("required_sources", [])
    if not required_sources:
        errors.append("cve_bin_tool.db_audit.required_sources must not be empty")
    unknown_required_sources = set(required_sources) - KNOWN_CVE_DATA_SOURCES
    if unknown_required_sources:
        errors.append(f"cve_bin_tool.db_audit.required_sources contains unknown sources: {sorted(unknown_required_sources)}")
    for source_name in db_audit.get("min_entries", {}):
        if source_name not in KNOWN_CVE_DATA_SOURCES:
            errors.append(f"cve_bin_tool.db_audit.min_entries contains unknown source: {source_name}")
    try:
        parse_duration_hours(db_audit.get("max_cache_age", "168h"))
    except ValueError as exc:
        errors.append(str(exc))
    if "db_status" in cve_cfg:
        try:
            parse_duration_hours(cve_cfg["db_status"].get("warning_age", "24h"))
        except ValueError as exc:
            errors.append(str(exc))

    syft = config.get("syft", {})
    if not syft.get("scan_sources"):
        errors.append("syft.scan_sources must not be empty")
    if syft.get("default_from") not in set(syft.get("scan_sources", [])):
        errors.append("syft.default_from must exist in syft.scan_sources")

    custom_entries = config.get("custom_sources", {}).get("entries", [])
    custom_priorities: set[int] = set()
    for entry in custom_entries:
        if entry.get("type") not in KNOWN_CUSTOM_TYPES:
            errors.append(f"custom source {entry.get('name')}: invalid type {entry.get('type')}")
        if entry.get("tool") not in KNOWN_TOOLS:
            errors.append(f"custom source {entry.get('name')}: invalid tool {entry.get('tool')}")
        if entry.get("layer") not in KNOWN_LAYERS:
            errors.append(f"custom source {entry.get('name')}: invalid layer {entry.get('layer')}")
        auth_env = entry.get("auth_env")
        if auth_env and not AUTH_ENV_RE.fullmatch(auth_env):
            errors.append(f"custom source {entry.get('name')}: invalid auth_env placeholder")
        priority = entry.get("priority")
        if priority in custom_priorities:
            errors.append(f"custom_sources.entries: duplicate priority {priority}")
        else:
            custom_priorities.add(priority)
        if not entry.get("url"):
            errors.append(f"custom source {entry.get('name')}: missing url")

    flattened = repr(config)
    for key in INSECURE_KEYS:
        if key in flattened:
            errors.append(f"unsafe setting detected: {key}")

    errors.extend(validate_proxy_config(config))

    return errors


# ---------------------------------------------------------------------------
# Proxy helpers
# ---------------------------------------------------------------------------

_ALLOWED_PROXY_SCHEMES = {"http", "https", "socks5", "socks5h", "socks4", "socks4a"}


def parse_proxy_config(config: dict[str, Any]) -> dict[str, str]:
    """Return a proxies dict suitable for ``requests.Session.proxies``.

    Reads from the optional top-level ``proxy:`` section in feed_sources.yaml.
    An empty / absent section returns ``{}`` — callers then fall back to
    HTTP_PROXY / HTTPS_PROXY / ALL_PROXY environment variables (handled in
    ``fallback.build_session``).

    Example YAML::

        proxy:
          http: "socks5h://host.docker.internal:1080"
          https: "socks5h://host.docker.internal:1080"
          no_proxy: "localhost,127.0.0.1,grype-static"
    """
    section = config.get("proxy") or {}
    result: dict[str, str] = {}
    for key in ("http", "https"):
        val = (section.get(key) or "").strip()
        if val:
            result[key] = val
    no_proxy = (section.get("no_proxy") or "").strip()
    if no_proxy:
        result["no_proxy"] = no_proxy
    return result


def validate_proxy_config(config: dict[str, Any]) -> list[str]:
    """Return validation errors for the proxy section (non-fatal; collected by validate_config_data).

    Validates both styles:
    - flat: ``proxy.http`` / ``proxy.https`` (scheme check);
    - chained: ``proxy.chains`` / ``proxy.policies`` / ``proxy.per_source``
      (scheme check per hop URL, cross-reference of chain names).
    """
    errors: list[str] = []
    section = config.get("proxy") or {}

    # Flat-form checks (unchanged).
    for key in ("http", "https"):
        val = (section.get(key) or "").strip()
        if not val:
            continue
        from urllib.parse import urlparse as _urlparse
        parsed = _urlparse(val)
        if parsed.scheme not in _ALLOWED_PROXY_SCHEMES:
            errors.append(
                f"proxy.{key}: unsupported scheme '{parsed.scheme}'. "
                f"Allowed: {sorted(_ALLOWED_PROXY_SCHEMES)}"
            )

    # Chained-form checks.  Imported lazily so the package keeps importing
    # cleanly even when the new module is missing during partial deploys.
    if section.get("chains") is not None or section.get("policies") is not None:
        try:
            from .proxy_chain import validate_chains
        except Exception as exc:  # pragma: no cover - import error surfaces only on broken installs
            errors.append(f"proxy.chains: cannot load validator ({exc!r})")
        else:
            errors.extend(validate_chains(section))

    return errors
