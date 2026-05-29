from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(order=True)
class SourceCandidate:
    priority: int
    name: str
    url: str
    tool: str
    layer: str
    enabled: bool = True
    auth_env: str | None = None
    trust_level: str = "custom"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _custom_matches(tool: str, layer: str, entries: list[dict[str, Any]]) -> list[SourceCandidate]:
    matches: list[SourceCandidate] = []
    for entry in entries:
        if entry.get("tool") == tool and entry.get("layer") == layer:
            matches.append(
                SourceCandidate(
                    priority=int(entry["priority"]),
                    name=entry["name"],
                    url=entry["url"],
                    tool=tool,
                    layer=layer,
                    enabled=entry.get("enabled", True),
                    auth_env=entry.get("auth_env"),
                    trust_level=entry.get("trust_level", "custom"),
                    notes=entry.get("notes", ""),
                )
            )
    return matches


def build_sources(config: dict[str, Any], tool: str, layer: str) -> list[SourceCandidate]:
    custom_entries = config.get("custom_sources", {}).get("entries", [])
    sources: list[SourceCandidate] = []
    if tool == "trivy":
        mapping = {
            "trivy-db": "db_repositories",
            "trivy-java-db": "java_db_repositories",
            "trivy-checks": "checks_bundle_repositories",
            "trivy-vex": "vex_repositories",
        }
        field = mapping[layer]
        for item in config["trivy"].get(field, []):
            sources.append(
                SourceCandidate(
                    priority=int(item["priority"]),
                    name=item["name"],
                    url=item["url"],
                    tool=tool,
                    layer=layer,
                    enabled=item.get("enabled", True),
                    trust_level=item.get("trust_level", "official"),
                )
            )
    elif tool == "grype":
        for item in config["grype"].get("upstream_update_urls", []):
            sources.append(
                SourceCandidate(
                    priority=int(item["priority"]),
                    name=item["name"],
                    url=item["url"],
                    tool=tool,
                    layer=layer,
                    enabled=item.get("enabled", True),
                    trust_level=item.get("trust_level", "official"),
                )
            )
    elif tool == "cve_bin_tool":
        for item in config["cve_bin_tool"].get("mirrors", []):
            sources.append(
                SourceCandidate(
                    priority=int(item["priority"]),
                    name=item["name"],
                    url=item["url"],
                    tool=tool,
                    layer=layer,
                    enabled=item.get("enabled", True),
                    trust_level=item.get("trust_level", "official"),
                )
            )
    elif tool == "syft":
        for idx, value in enumerate(config["syft"].get("scan_sources", []), start=1):
            sources.append(
                SourceCandidate(
                    priority=idx * 10,
                    name=f"syft-{value}",
                    url=value,
                    tool=tool,
                    layer=layer,
                    enabled=True,
                    trust_level="local",
                )
            )
    sources.extend(_custom_matches(tool, layer, custom_entries))
    return sorted([item for item in sources if item.enabled])
