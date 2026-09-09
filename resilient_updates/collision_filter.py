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

import gzip
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

_MAVEN_PURL = re.compile(r"^pkg:maven/(?P<group>[^/@?#]+)/(?P<name>[^/@?#]+)(?:@(?P<version>[^?#]+))?")
_PURL_TYPE = re.compile(r"^pkg:(?P<type>[a-z0-9.+-]+)/")

# ── Component ecosystem vs the CPE's target_sw ───────────────────────────
#
# A project name often lives in several ecosystems at once: OpenTelemetry ships
# for Go, .NET, Node.js and C++; pgvector is both a PostgreSQL extension and a
# .NET client.  cve-bin-tool matches on the bare product name and hands the
# component another implementation's CVEs.  NVD, however, records the platform
# in the 11th CPE field (``target_sw``):
# ``cpe:2.3:a:opentelemetry:opentelemetry:*:*:*:*:*:go:*:*``.  When that field
# names a platform and it does not match the component's ecosystem from its
# purl, the attribution is disproved by the very source the finding came from.
_ECOSYSTEM_TARGET_SW: dict[str, frozenset[str]] = {
    "nuget": frozenset({".net", "dotnet", ".net_framework", "asp.net", "asp.net_core", "c#"}),
    "maven": frozenset({"java", "jre", "jdk", "kotlin", "scala"}),
    "npm": frozenset({"node.js", "nodejs", "javascript", "browser", "typescript"}),
    "pypi": frozenset({"python"}),
    "gem": frozenset({"ruby", "rails", "ruby_on_rails"}),
    "golang": frozenset({"go", "golang"}),
    "composer": frozenset({"php"}),
    "cargo": frozenset({"rust"}),
    "conan": frozenset({"c", "c++", "c\\+\\+"}),
    "cocoapods": frozenset({"swift", "objective-c", "ios"}),
}

# target_sw values that actually name a platform.  Anything not listed here
# (``*`` and the empty string included) counts as uninformative: such a CPE
# disproves nothing.
_MEANINGFUL_TARGET_SW: frozenset[str] = frozenset(
    set().union(*_ECOSYSTEM_TARGET_SW.values())
    | {
        "jenkins",
        "wordpress",
        "drupal",
        "joomla",
        "moodle",
        "magento",
        "postgresql",
        "mysql",
        "mariadb",
        "mongodb",
        "kubernetes",
        "docker",
        "android",
        "ios",
        "erlang",
        "elixir",
        "perl",
        "lua",
        "r",
        "haskell",
    }
)


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


def _is_cve_bin_tool(finding: dict[str, Any]) -> bool:
    return finding.get("tool") == "cve-bin-tool"


def has_synthesised_coordinates(product: str, group_ids: set[str]) -> bool:
    """Did Syft invent the groupId from the file name rather than read a pom?

    A jar built in-house carries no ``META-INF/maven/**/pom.properties``, so Syft
    falls back to the artifact name for both coordinates and the purl comes back
    as ``pkg:maven/core/core@3.29.3-SNAPSHOT``.  A published artifact never looks
    like this: ``com.google.zxing/core``, ``io.netty/netty-codec-http``.  The
    legacy bare groupIds this must not catch -- ``log4j:log4j``, ``junit:junit``
    -- are published releases and are excluded by the version test below.
    """
    if not group_ids:
        return False
    return all(g.lower() == product.lower() for g in group_ids)


def is_inhouse_version(version: str) -> bool:
    """A ``-SNAPSHOT`` version is a build that was never published to a registry."""
    return "SNAPSHOT" in version.upper()


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

    Two further signatures are handled, because the groupId rule alone left the
    bulk of CYBERSEC-14277 standing (462 of 534 findings, every CRITICAL):

    * *The component was never published.*  An in-house ``-SNAPSHOT`` jar has no
      Maven coordinates, so Syft synthesises the groupId from the file name
      (``pkg:maven/core/core@3.29.3-SNAPSHOT``).  Nothing with that name exists
      in any registry, so no NVD vendor can own it and every attribution by bare
      name is a collision -- including ``vendor=unknown``.
    * *``unknown`` riding along with a disproved fan-out.*  ``vendor=unknown`` is
      cve-bin-tool's normal output for a component it matched correctly, so it is
      never dropped on its own.  But when named vendors on the *same*
      (product, version) were just disproved by the groupId, the unknown ones
      come from that same bare-name fan-out and go with them.  A component with
      no disproved siblings -- ``unknown/netty-codec-http`` -- is untouched.
    """
    vendors_by_component: dict[tuple[str, str], set[str]] = defaultdict(set)
    for finding in findings:
        if _is_real_vendor(finding):
            key = (str(finding.get("product") or "").lower(), str(finding.get("version") or ""))
            vendors_by_component[key].add(str(finding["vendor"]).lower())

    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []  # vendor=unknown, decided in the second pass
    disproved_components: set[tuple[str, str]] = set()

    for finding in findings:
        if not _is_cve_bin_tool(finding):
            kept.append(finding)
            continue

        product = str(finding.get("product") or "")
        version = str(finding.get("version") or "")
        key = (product.lower(), version)
        component_groups = _groups_for(finding, groups)

        # Signature 1: the component was never published, whatever the vendor.
        if is_inhouse_version(version) and has_synthesised_coordinates(product, component_groups):
            dropped.append(
                dict(
                    finding,
                    dropped_reason=(
                        f"'{product} {version}' is an in-house build with no Maven "
                        "coordinates (groupId synthesised from the file name), so it "
                        "is not the registry artifact this vendor owns (name collision)"
                    ),
                    dropped_evidence="no Maven coordinates (-SNAPSHOT build)",
                )
            )
            disproved_components.add(key)
            continue

        if not _is_real_vendor(finding):
            deferred.append(finding)
            continue

        if len(vendors_by_component[key]) < 2:
            kept.append(finding)  # no fan-out signature: leave a single attribution alone
            continue
        known = {g for g in component_groups if names_an_owner(g)}
        if not known:
            kept.append(finding)
            continue
        vendor = str(finding["vendor"])
        if any(vendor_matches_group(vendor, g, product) for g in known):
            kept.append(finding)
            continue
        dropped.append(
            dict(
                finding,
                dropped_reason=(
                    f"vendor '{vendor}' is not corroborated by groupId "
                    f"{', '.join(sorted(known))} (name collision)"
                ),
                dropped_evidence=", ".join(sorted(known)),
            )
        )
        disproved_components.add(key)

    # Signature 2: unknown-vendor findings on a component whose named vendors
    # were just disproved belong to the same bare-name fan-out.
    for finding in deferred:
        key = (str(finding.get("product") or "").lower(), str(finding.get("version") or ""))
        if key in disproved_components:
            dropped.append(
                dict(
                    finding,
                    dropped_reason=(
                        "no vendor attribution, and every named vendor on "
                        f"'{finding.get('product')} {finding.get('version')}' was "
                        "disproved by the groupId (same bare-name collision)"
                    ),
                    dropped_evidence="named vendors on this component disproved",
                )
            )
        else:
            kept.append(finding)
    return kept, dropped


def ecosystems_from_sbom(syft: Any) -> dict[tuple[str, str], set[str]]:
    """Map ``(name, version)`` -> purl types seen in a Syft JSON SBOM.

    The version-less key is filled too, mirroring :func:`maven_groups_from_sbom`,
    so a version string cve-bin-tool rendered differently can still resolve.
    """
    out: dict[tuple[str, str], set[str]] = defaultdict(set)
    artifacts = syft.get("artifacts") if isinstance(syft, dict) else None
    for art in artifacts or []:
        if not isinstance(art, dict):
            continue
        m = _PURL_TYPE.match(str(art.get("purl") or ""))
        if not m:
            continue
        name = str(art.get("name") or "").lower()
        if not name:
            continue
        out[(name, str(art.get("version") or ""))].add(m.group("type"))
        out[(name, "")].add(m.group("type"))
    return dict(out)


def target_sw_from_cpe(criteria: str) -> str:
    """Pull ``target_sw`` (11th field) out of a CPE 2.3 string."""
    parts = str(criteria or "").split(":")
    return parts[10].lower() if len(parts) > 10 else ""


def platform_disproves(ecosystems: set[str], target_sw: set[str]) -> bool:
    """Do these CPE platforms rule out a component from these ecosystems?

    Only when *every* platform is one we recognise (so ``*`` or an unfamiliar
    value never disproves anything) and none of them matches any ecosystem the
    component actually belongs to.  A component in an ecosystem we have no
    mapping for is left alone.
    """
    known = {e for e in ecosystems if e in _ECOSYSTEM_TARGET_SW}
    if not known or not target_sw:
        return False
    if not target_sw <= _MEANINGFUL_TARGET_SW:
        return False
    allowed: set[str] = set()
    for eco in known:
        allowed |= _ECOSYSTEM_TARGET_SW[eco]
    return not (target_sw & allowed)


def cve_platforms_from_feeds(cve_ids: set[str], feeds_dir: Path | str) -> dict[str, set[str]]:
    """Read ``target_sw`` per CVE from the local NVD 2.0 year feeds.

    Only the year files the requested CVEs belong to are opened (plus
    ``modified``), so a report costs a couple of files rather than all 26.
    Missing or unreadable feeds simply yield no evidence — the caller then
    drops nothing, which is the safe direction.
    """
    root = Path(feeds_dir)
    if not cve_ids or not root.is_dir():
        return {}
    years = {cid.split("-")[1] for cid in cve_ids if cid.count("-") >= 2}
    wanted = [root / f"nvdcve-2.0-{y}.json.gz" for y in sorted(years)]
    wanted.append(root / "nvdcve-2.0-modified.json.gz")

    platforms: dict[str, set[str]] = defaultdict(set)
    for path in wanted:
        if not path.is_file():
            continue
        try:
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            continue
        for item in data.get("vulnerabilities", []) or []:
            cve = (item or {}).get("cve") or {}
            cid = cve.get("id")
            if cid not in cve_ids:
                continue
            for config in cve.get("configurations", []) or []:
                for node in config.get("nodes", []) or []:
                    for match in node.get("cpeMatch", []) or []:
                        tsw = target_sw_from_cpe(match.get("criteria"))
                        if tsw:
                            platforms[cid].add(tsw)
    return dict(platforms)


def filter_platform_mismatches(
    findings: list[dict[str, Any]],
    ecosystems: dict[tuple[str, str], set[str]],
    platforms: dict[str, set[str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split cve-bin-tool findings into (kept, dropped) by CPE platform.

    Complements the groupId rule, which cannot help where the package name is
    the whole identity: a NuGet ``OpenTelemetry`` and a Go ``opentelemetry``
    are the same string.  NVD's own ``target_sw`` separates them.
    """
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for finding in findings:
        if not _is_cve_bin_tool(finding):
            kept.append(finding)
            continue
        product = str(finding.get("product") or "").lower()
        version = str(finding.get("version") or "")
        eco = ecosystems.get((product, version)) or ecosystems.get((product, "")) or set()
        tsw = platforms.get(str(finding.get("id") or ""), set())
        if platform_disproves(eco, tsw):
            dropped.append(
                dict(
                    finding,
                    dropped_reason=(
                        f"NVD marks this CVE as affecting {', '.join(sorted(tsw))}, "
                        f"but the component ships as {', '.join(sorted(eco))} "
                        "(different implementation of the same project name)"
                    ),
                    dropped_evidence=f"CPE target_sw={', '.join(sorted(tsw))} ≠ {'/'.join(sorted(eco))}",
                )
            )
        else:
            kept.append(finding)
    return kept, dropped


def summarize_dropped(dropped: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse dropped findings per (vendor, product, version) with a CVE count.

    492 dropped findings on CYBERSEC-14277 collapse to a handful of rows, which
    is what belongs in a report: enough to audit the decision, not the noise.
    """
    rows: dict[tuple[str, str, str], dict[str, Any]] = {}
    seen: dict[tuple[str, str, str], list[str]] = defaultdict(list)
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
                "evidence": "",
            },
        )
        row["cves"] += 1
        # One (product, version) can be disproved on several grounds: some of
        # OpenTelemetry 1.15.3's CVEs are tagged go, others c++ and node.js.
        # Collapsing that into a single reason would misrepresent it, so keep all.
        ev = str(f.get("dropped_evidence") or "")
        if ev and ev not in seen[key]:
            seen[key].append(ev)
    for key, row in rows.items():
        row["evidence"] = "; ".join(seen[key])
    return [rows[k] for k in sorted(rows)]


__all__ = [
    "cve_platforms_from_feeds",
    "ecosystems_from_sbom",
    "filter_platform_mismatches",
    "filter_vendor_collisions",
    "has_synthesised_coordinates",
    "is_inhouse_version",
    "maven_groups_from_sbom",
    "names_an_owner",
    "platform_disproves",
    "summarize_dropped",
    "target_sw_from_cpe",
    "vendor_matches_group",
]
