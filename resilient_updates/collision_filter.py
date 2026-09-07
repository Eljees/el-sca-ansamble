"""Drop cve-bin-tool vendor attributions that the SBOM disproves.

cve-bin-tool matches a Maven artifact by its bare ``artifactId`` and, when its
purl2cpe table has no entry for it, reports *every* NVD vendor that owns a
product of that name.  An in-house module called ``core`` therefore comes back
as Drupal core, MobileIron Core and ONLYOFFICE core at once and inherits all of
their CVEs.  On CYBERSEC-14277 that was 492 of 534 cve-bin-tool findings --
every CRITICAL one in the report -- pinned on the vendor's own
``core 3.29.3-SNAPSHOT``.

The Syft SBOM knows the artifact's ``groupId``.  This module uses it the way the
upstream fix does (ossf/cve-bin-tool#5905): a vendor found only by product name
must be corroborated by the groupId -- a token of it, the artifactId itself, or
NVD's ``<name>_project`` convention.  Otherwise the finding is a name collision
and is dropped, with the reason kept so the report can say what went and why.

Once a cve-bin-tool release carries the upstream fix this filter becomes a
no-op; it is deliberately a pure function over already-parsed findings so it
can be deleted without touching the scanners.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

_MAVEN_PURL = re.compile(r"^pkg:maven/(?P<group>[^/@?#]+)/(?P<name>[^/@?#]+)(?:@(?P<version>[^?#]+))?")


def names_an_owner(group_id: str) -> bool:
    """Is this groupId a reverse-DNS namespace that asserts an owner?

    ``log4j:log4j``, ``junit:junit``, ``commons-io:commons-io`` predate Maven's
    reverse-domain convention: the groupId is just the project name and says
    nothing about who owns it, so it cannot contradict any vendor.
    """
    return "." in group_id


def vendor_matches_group(vendor: str, group_id: str, artifact_id: str) -> bool:
    """Does a Maven groupId (or the artifactId) corroborate an NVD vendor?

    ``org.apache.santuario`` vouches for ``apache``, ``io.netty`` for ``netty``,
    ``org.yaml/snakeyaml`` for ``snakeyaml_project``.  ``ru.example.agent`` does
    not vouch for ``drupal``.  Identical to the rule proposed upstream.
    """
    tokens = {t for t in re.split(r"[.\-_]", group_id.lower()) if t}
    vendor = vendor.lower()
    candidates = {vendor}
    if vendor.endswith("_project"):
        candidates.add(vendor[: -len("_project")])
    return bool(candidates & tokens) or artifact_id.lower() in candidates


def maven_groups_from_sbom(syft: Any) -> dict[tuple[str, str], set[str]]:
    """Map ``(artifactId, version)`` -> groupIds seen in a Syft JSON SBOM.

    The version-less key ``(artifactId, "")`` is filled too, so a finding whose
    version string cve-bin-tool rendered differently can still be resolved when
    the artifactId is unambiguous in this SBOM.
    """
    groups: dict[tuple[str, str], set[str]] = defaultdict(set)
    artifacts = syft.get("artifacts") if isinstance(syft, dict) else None
    for art in artifacts or []:
        if not isinstance(art, dict):
            continue
        m = _MAVEN_PURL.match(str(art.get("purl") or ""))
        if not m:
            continue
        name = m.group("name").lower()
        group = m.group("group")
        groups[(name, m.group("version") or "")].add(group)
        groups[(name, "")].add(group)
    return dict(groups)


def _groups_for(finding: dict[str, Any], groups: dict[tuple[str, str], set[str]]) -> set[str]:
    name = str(finding.get("product") or "").lower()
    version = str(finding.get("version") or "")
    exact = groups.get((name, version))
    if exact:
        return exact
    loose = groups.get((name, ""))
    # Only trust the version-less key when it does not hide several groups.
    return loose if loose and len(loose) == 1 else set()


def _is_real_vendor(finding: dict[str, Any]) -> bool:
    vendor = str(finding.get("vendor") or "")
    return finding.get("tool") == "cve-bin-tool" and bool(vendor) and vendor.upper() != "UNKNOWN"


def filter_vendor_collisions(
    findings: list[dict[str, Any]],
    groups: dict[tuple[str, str], set[str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split cve-bin-tool findings into (kept, dropped).

    Unlike the upstream fix, this runs after the fact and cannot see whether
    cve-bin-tool got a vendor from its purl2cpe table (authoritative) or from the
    bare-name fallback (the defect).  So it only acts on the fallback's own
    signature -- one component attributed to two or more vendors -- and there
    keeps the vendors a reverse-DNS groupId corroborates and drops the rest.

    Everything else is kept: single-vendor attributions, components the SBOM
    does not know, and components whose groupId names no owner (``log4j:log4j``).
    Absence of evidence is not evidence of a collision.  Dropped findings get a
    ``dropped_reason`` so the report can list them.
    """
    vendors_by_component: dict[tuple[str, str], set[str]] = defaultdict(set)
    for finding in findings:
        if _is_real_vendor(finding):
            key = (str(finding.get("product") or "").lower(), str(finding.get("version") or ""))
            vendors_by_component[key].add(str(finding["vendor"]).lower())

    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for finding in findings:
        if not _is_real_vendor(finding):
            kept.append(finding)
            continue
        key = (str(finding.get("product") or "").lower(), str(finding.get("version") or ""))
        if len(vendors_by_component[key]) < 2:
            kept.append(finding)  # no fan-out signature: leave a single attribution alone
            continue
        known = {g for g in _groups_for(finding, groups) if names_an_owner(g)}
        if not known:
            kept.append(finding)
            continue
        vendor = str(finding["vendor"])
        artifact = str(finding.get("product") or "")
        if any(vendor_matches_group(vendor, g, artifact) for g in known):
            kept.append(finding)
            continue
        dropped.append(
            dict(
                finding,
                dropped_reason=(
                    f"vendor '{vendor}' is not corroborated by groupId "
                    f"{', '.join(sorted(known))} (name collision)"
                ),
            )
        )
    return kept, dropped


def summarize_dropped(dropped: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse dropped findings per (vendor, product, version) with a CVE count.

    492 dropped findings on CYBERSEC-14277 collapse to a handful of rows, which
    is what belongs in a report: enough to audit the decision, not the noise.
    """
    rows: dict[tuple[str, str, str], dict[str, Any]] = {}
    for f in dropped:
        key = (str(f.get("vendor") or ""), str(f.get("product") or ""), str(f.get("version") or ""))
        row = rows.setdefault(
            key,
            {
                "vendor": key[0],
                "product": key[1],
                "version": key[2],
                "cves": 0,
                "reason": f.get("dropped_reason", ""),
            },
        )
        row["cves"] += 1
    return [rows[k] for k in sorted(rows)]


__all__ = [
    "filter_vendor_collisions",
    "maven_groups_from_sbom",
    "names_an_owner",
    "summarize_dropped",
    "vendor_matches_group",
]
