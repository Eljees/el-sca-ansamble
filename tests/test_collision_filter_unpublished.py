"""Две дополнительные подписи фильтра коллизий (CYBERSEC-14277, второй заход).

Правило по groupId закрыло лишь 8 находок из 534: на реальном артефакте
у собственных модулей вендора вообще нет Maven-координат, а основная масса
находок приходит с ``vendor=unknown``, которому нечего опровергать.
Здесь проверяются обе добавленные подписи и, что важнее, — что они не трогают
законные находки.
"""

from __future__ import annotations

from resilient_updates.collision_filter import (
    filter_vendor_collisions,
    has_synthesised_coordinates,
    is_inhouse_version,
    maven_groups_from_sbom,
)

# Syft не нашёл pom.properties во внутреннем jar и подставил имя файла в обе
# координаты; у опубликованных артефактов groupId всегда осмысленный.
SBOM = {
    "artifacts": [
        {
            "name": "core",
            "version": "3.29.3-SNAPSHOT",
            "purl": "pkg:maven/core/core@3.29.3-SNAPSHOT",
        },
        {"name": "core", "version": "3.4.0", "purl": "pkg:maven/com.google.zxing/core@3.4.0"},
        {
            "name": "netty-codec-http",
            "version": "4.1.135.Final",
            "purl": "pkg:maven/io.netty/netty-codec-http@4.1.135.Final",
        },
        {"name": "log4j", "version": "1.2.13", "purl": "pkg:maven/log4j/log4j@1.2.13"},
    ]
}


def _cbt(vendor, product, version, cve="CVE-2016-9450", severity="CRITICAL"):
    return {
        "tool": "cve-bin-tool",
        "id": cve,
        "severity": severity,
        "vendor": vendor,
        "product": product,
        "version": version,
    }


def _groups():
    return maven_groups_from_sbom(SBOM)


# ── вспомогательные предикаты ────────────────────────────────────────────


def test_synthesised_coordinates_detected():
    assert has_synthesised_coordinates("core", {"core"}) is True


def test_published_coordinates_not_synthesised():
    assert has_synthesised_coordinates("core", {"com.google.zxing"}) is False


def test_no_coordinates_is_not_evidence():
    assert has_synthesised_coordinates("core", set()) is False


def test_snapshot_is_inhouse():
    assert is_inhouse_version("3.29.3-SNAPSHOT") is True
    assert is_inhouse_version("1.2.13") is False


# ── подпись 1: непубликуемая сборка ──────────────────────────────────────


def test_unpublished_snapshot_dropped_for_named_vendor():
    kept, dropped = filter_vendor_collisions(
        [_cbt("mobileiron", "core", "3.29.3-SNAPSHOT")], _groups()
    )
    assert kept == []
    assert len(dropped) == 1
    assert "in-house build" in dropped[0]["dropped_reason"]


def test_unpublished_snapshot_dropped_for_unknown_vendor():
    """Главная дыра прежнего правила: 462 находки приходили без вендора."""
    kept, dropped = filter_vendor_collisions(
        [_cbt("unknown", "core", "3.29.3-SNAPSHOT")], _groups()
    )
    assert kept == []
    assert len(dropped) == 1


def test_legacy_bare_groupid_release_is_kept():
    """``log4j:log4j 1.2.13`` — bare groupId, но это публикация, не SNAPSHOT."""
    kept, dropped = filter_vendor_collisions([_cbt("apache", "log4j", "1.2.13")], _groups())
    assert dropped == []
    assert len(kept) == 1


# ── подпись 2: unknown рядом с опровергнутым веером ──────────────────────


def test_unknown_dropped_when_named_vendors_disproved():
    findings = [
        _cbt("mobileiron", "core", "3.4.0"),
        _cbt("onlyoffice", "core", "3.4.0"),
        _cbt("unknown", "core", "3.4.0", cve="CVE-2017-6920"),
    ]
    kept, dropped = filter_vendor_collisions(findings, _groups())
    assert kept == []
    assert len(dropped) == 3
    assert any("every named vendor" in d["dropped_reason"] for d in dropped)


def test_unknown_kept_without_disproved_siblings():
    """netty: вендора нет, но и опровергать нечего — находка настоящая."""
    findings = [_cbt("unknown", "netty-codec-http", "4.1.135.Final", cve="CVE-2025-1", severity="HIGH")]
    kept, dropped = filter_vendor_collisions(findings, _groups())
    assert dropped == []
    assert len(kept) == 1


def test_corroborated_vendor_survives_the_fan_out():
    """zxing подтверждён groupId — остаётся, хотя соседи по вееру отсеяны."""
    findings = [
        _cbt("zxing", "core", "3.4.0", cve="CVE-2021-1", severity="HIGH"),
        _cbt("mobileiron", "core", "3.4.0"),
        _cbt("unknown", "core", "3.4.0", cve="CVE-2017-6920"),
    ]
    kept, dropped = filter_vendor_collisions(findings, _groups())
    assert [k["vendor"] for k in kept] == ["zxing"]
    assert len(dropped) == 2


def test_other_tools_untouched():
    grype = {"tool": "grype", "id": "GHSA-x", "severity": "HIGH", "product": "core", "version": "3.29.3-SNAPSHOT"}
    kept, dropped = filter_vendor_collisions([grype], _groups())
    assert dropped == []
    assert kept == [grype]
