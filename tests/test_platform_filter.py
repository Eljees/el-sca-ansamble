"""Отсев находок cve-bin-tool по платформе из CPE (CYBERSEC-13702).

Правило по Maven groupId бессильно там, где имя пакета и есть вся личность:
NuGet ``OpenTelemetry`` и Go ``opentelemetry`` — одна и та же строка. NVD
хранит платформу в 11-м поле CPE (``target_sw``), и она их разводит.

Формы взяты с боевого артефакта: у CVE-2026-39883 в NVD стоит
``cpe:2.3:a:opentelemetry:opentelemetry:*:*:*:*:*:go:*:*``, у CVE-2026-18022 —
``postgresql``, а в поставке — ``pkg:nuget/OpenTelemetry@1.15.3`` и
``pkg:nuget/Pgvector@0.3.2``.
"""

from __future__ import annotations

import gzip
import json

from resilient_updates.collision_filter import (
    cve_platforms_from_feeds,
    ecosystems_from_sbom,
    filter_platform_mismatches,
    platform_disproves,
    target_sw_from_cpe,
)

SBOM = {
    "artifacts": [
        {"name": "OpenTelemetry", "version": "1.15.3", "purl": "pkg:nuget/OpenTelemetry@1.15.3"},
        {"name": "Pgvector", "version": "0.3.2", "purl": "pkg:nuget/Pgvector@0.3.2"},
        {"name": "NLog", "version": "5.5.1", "purl": "pkg:nuget/NLog@5.5.1"},
        {
            "name": "netty-codec",
            "version": "4.1.135.Final",
            "purl": "pkg:maven/io.netty/netty-codec@4.1.135.Final",
        },
        {"name": "libfoo", "version": "1.0", "purl": ""},  # без purl — экосистема неизвестна
    ]
}


def _cbt(cve, product, version, severity="HIGH", vendor="unknown"):
    return {
        "tool": "cve-bin-tool",
        "id": cve,
        "severity": severity,
        "vendor": vendor,
        "product": product,
        "version": version,
    }


# ── разбор CPE ───────────────────────────────────────────────────────────


def test_target_sw_extracted():
    assert target_sw_from_cpe("cpe:2.3:a:opentelemetry:opentelemetry:*:*:*:*:*:go:*:*") == "go"


def test_target_sw_of_short_string_is_empty():
    assert target_sw_from_cpe("cpe:2.3:a:vendor:product") == ""


# ── само правило ─────────────────────────────────────────────────────────


def test_go_cve_disproves_nuget_component():
    assert platform_disproves({"nuget"}, {"go"}) is True


def test_postgresql_cve_disproves_nuget_component():
    assert platform_disproves({"nuget"}, {"postgresql"}) is True


def test_matching_platform_does_not_disprove():
    assert platform_disproves({"nuget"}, {".net"}) is False


def test_wildcard_platform_never_disproves():
    """``cpe:…:*:*:*`` — платформа не указана, опровергать нечем."""
    assert platform_disproves({"nuget"}, {"*"}) is False


def test_unknown_platform_never_disproves():
    assert platform_disproves({"nuget"}, {"something-we-do-not-know"}) is False


def test_mixed_platforms_keep_when_one_matches():
    assert platform_disproves({"nuget"}, {"go", ".net"}) is False


def test_unknown_ecosystem_is_left_alone():
    assert platform_disproves(set(), {"go"}) is False
    assert platform_disproves({"deb"}, {"go"}) is False


# ── фильтр целиком ───────────────────────────────────────────────────────


def test_real_shape_from_pix_process_studio():
    eco = ecosystems_from_sbom(SBOM)
    platforms = {
        "CVE-2026-39883": {"go"},
        "CVE-2026-18022": {"postgresql"},
        "CVE-2025-58460": {"jenkins"},
        "CVE-1999-1278": {"*"},
    }
    findings = [
        _cbt("CVE-2026-39883", "opentelemetry", "1.15.3"),
        _cbt("CVE-2026-18022", "pgvector", "0.3.2"),
        _cbt("CVE-2025-58460", "opentelemetry", "1.15.3", severity="MEDIUM"),
        _cbt("CVE-1999-1278", "nlog", "5.5.1", severity="UNKNOWN"),
    ]
    kept, dropped = filter_platform_mismatches(findings, eco, platforms)
    assert [k["id"] for k in kept] == ["CVE-1999-1278"]
    assert len(dropped) == 3
    assert all("target_sw" in d["dropped_evidence"] for d in dropped)


def test_summary_keeps_every_distinct_evidence():
    """Одна пара может быть опровергнута разными платформами — показываем все."""
    from resilient_updates.collision_filter import summarize_dropped

    eco = ecosystems_from_sbom(SBOM)
    platforms = {"CVE-A": {"go"}, "CVE-B": {"c++"}, "CVE-C": {"node.js"}}
    findings = [
        _cbt("CVE-A", "opentelemetry", "1.15.3", vendor="opentelemetry"),
        _cbt("CVE-B", "opentelemetry", "1.15.3", vendor="opentelemetry"),
        _cbt("CVE-C", "opentelemetry", "1.15.3", vendor="opentelemetry"),
    ]
    _, dropped = filter_platform_mismatches(findings, eco, platforms)
    rows = summarize_dropped(dropped)
    assert len(rows) == 1
    assert rows[0]["cves"] == 3
    for token in ("go", "c++", "node.js"):
        assert token in rows[0]["evidence"]


def test_no_platform_evidence_drops_nothing():
    eco = ecosystems_from_sbom(SBOM)
    findings = [_cbt("CVE-2026-39883", "opentelemetry", "1.15.3")]
    kept, dropped = filter_platform_mismatches(findings, eco, {})
    assert dropped == []
    assert len(kept) == 1


def test_other_tools_untouched():
    grype = {
        "tool": "grype",
        "id": "GHSA-x",
        "severity": "HIGH",
        "product": "opentelemetry",
        "version": "1.15.3",
    }
    kept, dropped = filter_platform_mismatches([grype], ecosystems_from_sbom(SBOM), {"GHSA-x": {"go"}})
    assert dropped == []
    assert kept == [grype]


def test_component_without_purl_is_kept():
    eco = ecosystems_from_sbom(SBOM)
    findings = [_cbt("CVE-2026-39883", "libfoo", "1.0")]
    kept, dropped = filter_platform_mismatches(findings, eco, {"CVE-2026-39883": {"go"}})
    assert dropped == []
    assert len(kept) == 1


# ── чтение фидов ─────────────────────────────────────────────────────────


def _write_feed(path, entries):
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cid,
                    "configurations": [{"nodes": [{"cpeMatch": [{"criteria": c} for c in crits]}]}],
                }
            }
            for cid, crits in entries.items()
        ]
    }
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump(payload, fh)


def test_feeds_are_read_per_year(tmp_path):
    _write_feed(
        tmp_path / "nvdcve-2.0-2026.json.gz",
        {"CVE-2026-39883": ["cpe:2.3:a:opentelemetry:opentelemetry:*:*:*:*:*:go:*:*"]},
    )
    # год, который не запрашивали — не должен попасть в результат
    _write_feed(tmp_path / "nvdcve-2.0-2020.json.gz", {"CVE-2020-1": ["cpe:2.3:a:x:y:*:*:*:*:*:php:*:*"]})
    got = cve_platforms_from_feeds({"CVE-2026-39883"}, tmp_path)
    assert got == {"CVE-2026-39883": {"go"}}


def test_missing_feeds_dir_yields_no_evidence(tmp_path):
    assert cve_platforms_from_feeds({"CVE-2026-39883"}, tmp_path / "нет") == {}


def test_empty_request_reads_nothing(tmp_path):
    assert cve_platforms_from_feeds(set(), tmp_path) == {}
