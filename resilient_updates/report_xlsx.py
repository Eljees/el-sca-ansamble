"""Excel (.xlsx) rendering of a scan result.

Fourth output format alongside the Markdown report, the HTML overview and the
raw scanner JSON.  Analysts asked for it because triage happens in a
spreadsheet: sort by severity, filter to one component, cut a slice for the
customer, paste into a ticket.

Parsing is deliberately NOT reimplemented here — the per-scanner normalisers
live in :mod:`resilient_updates.reporting` and are reused as-is, so a schema
change in Grype/Trivy/cve-bin-tool output is fixed once and every format
follows.  This module only decides layout.

Sheets:
  Сводка          object of analysis, hashes, DB provenance, severity totals
  Находки         every finding, frozen header + autofilter
  High-Critical   pre-cut slice for the customer-facing conversation
  SBOM            components Syft catalogued
"""

from __future__ import annotations

import contextlib
from collections import Counter
from pathlib import Path
from typing import Any

from .collision_filter import filter_vendor_collisions, maven_groups_from_sbom
from .reporting import (
    _collect_json_from_paths,
    _cve_bin_tool_findings,
    _dedup_findings,
    _find_json_by_name,
    _get_nested,
    _grype_findings,
    _syft_count,
    _trivy_findings,
    target_digest,
)
from .xlsx_writer import (
    SEVERITY_STYLE,
    STYLE_HEADER,
    STYLE_MUTED,
    STYLE_TITLE,
    Sheet,
    write_workbook,
)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NEGLIGIBLE": 4, "UNKNOWN": 5}

_FINDING_COLUMNS: list[tuple[str, str, int]] = [
    # (header, key in the finding dict, column width)
    ("Инструмент", "tool", 14),
    ("CVE / GHSA", "id", 22),
    ("Severity", "severity", 12),
    ("Score", "score", 8),
    ("EPSS", "epss_probability", 10),
    ("KEV", "kev", 7),
    ("Вендор", "vendor", 18),
    ("Продукт", "product", 34),
    ("Версия", "version", 22),
    ("Исправлено в", "fixed", 22),
    ("Источник", "source", 30),
]


def _sort_key(finding: dict[str, Any]) -> tuple[int, float, str]:
    """Worst first; within a severity, highest CVSS first."""
    try:
        score = float(finding.get("score") or 0)
    except (TypeError, ValueError):
        score = 0.0
    return (SEVERITY_ORDER.get(finding.get("severity", "UNKNOWN"), 9), -score, str(finding.get("id", "")))


def _finding_rows(findings: list[dict[str, Any]]) -> list[list[Any]]:
    rows: list[list[Any]] = [[(header, STYLE_HEADER) for header, _, _ in _FINDING_COLUMNS]]
    for finding in sorted(findings, key=_sort_key):
        severity = finding.get("severity", "UNKNOWN")
        style = SEVERITY_STYLE.get(severity, 0)
        row: list[Any] = []
        for _, key, _ in _FINDING_COLUMNS:
            value = finding.get(key, "")
            if key == "kev":
                value = "да" if value else ""
            elif key == "score":
                with contextlib.suppress(TypeError, ValueError):
                    value = float(value) if value not in ("", None) else ""
            row.append((value, style) if key == "severity" else value)
        rows.append(row)
    return rows


def _summary_sheet(
    *,
    case_id: str,
    display_target: str,
    input_hashes: dict[str, str],
    target_hashes: dict[str, str],
    final_sha: str,
    counts: Counter,
    per_tool: dict[str, int],
    syft_components: int,
    db_snapshot: Any,
    status: Any,
    summary: Any,
    extraction: Any,
    dropped_collisions: int = 0,
) -> Sheet:
    sheet = Sheet("Сводка", widths=[34, 78])
    sheet.add((f"{case_id}: SCA-отчёт", STYLE_TITLE))
    sheet.add()

    sheet.add(("Объект анализа", STYLE_HEADER), ("", STYLE_HEADER))
    sheet.add("Файл", display_target)
    sheet.add("SHA-256 (входной архив)", input_hashes.get("sha256") or "—")
    sheet.add("SHA-1 (входной архив)", input_hashes.get("sha1") or "—")
    sheet.add("MD5 (входной архив)", input_hashes.get("md5") or "—")
    sheet.add("SHA-256 (распакованная цель)", target_hashes.get("sha256") or final_sha or "—")
    if isinstance(extraction, dict) and extraction:
        sheet.add("Статус распаковки", extraction.get("status") or "—")
        sheet.add("Извлечено объектов", extraction.get("extracted_count") or 0)
        failures = extraction.get("failures") or []
        if failures:
            # Skipped members mean the report does NOT cover them — this must be
            # visible, not buried in extraction_manifest.json.
            sheet.add(("Пропущено при распаковке", STYLE_MUTED), (len(failures), STYLE_MUTED))
    sheet.add()

    sheet.add(("Итог сканирования", STYLE_HEADER), ("", STYLE_HEADER))
    sheet.add("Компонентов в SBOM", syft_components)
    for tool in ("grype", "trivy", "cve-bin-tool"):
        sheet.add(f"Находок: {tool}", per_tool.get(tool, 0))
    if dropped_collisions:
        sheet.add(
            ("Отсеяно как коллизии имён (cve-bin-tool)", STYLE_MUTED), (dropped_collisions, STYLE_MUTED)
        )
    sheet.add("Всего находок", sum(per_tool.values()))
    sheet.add()

    sheet.add(("Severity", STYLE_HEADER), ("Количество", STYLE_HEADER))
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"):
        count = int(counts.get(severity, 0))
        if count:
            sheet.add((severity, SEVERITY_STYLE.get(severity, 0)), count)
    if isinstance(summary, dict) and summary.get("policy_decision"):
        sheet.add("Политика", summary["policy_decision"])
    sheet.add()

    sheet.add(("Базы уязвимостей", STYLE_HEADER), ("", STYLE_HEADER))
    tools = _get_nested(db_snapshot, ["tools"], {}) if isinstance(db_snapshot, dict) else {}
    if isinstance(tools, dict) and tools:
        for name, meta in tools.items():
            if not isinstance(meta, dict):
                continue
            bits = [f"состояние={meta.get('state', '—')}"]
            if meta.get("built"):
                bits.append(f"собрана={meta['built']}")
            if meta.get("source"):
                bits.append(f"источник={meta['source']}")
            sheet.add(str(name), ", ".join(bits))
    else:
        sheet.add("Метаданные БД", "недоступны")
    if isinstance(status, dict):
        if status.get("db_snapshot"):
            sheet.add("DB snapshot", status["db_snapshot"])
        if status.get("tool_failures"):
            sheet.add("Сбои инструментов", status["tool_failures"])
    sheet.add()
    sheet.add(
        (
            "Находки — сигнал сканеров, а не подтверждённая применимость. "
            "Проверяйте High/Critical в контексте поставки.",
            STYLE_MUTED,
        )
    )
    return sheet


def build_xlsx_report(
    reports_dir: str | Path,
    output_path: str | Path,
    target_path: str | Path | None = None,
    display_target: str | None = None,
    case_id: str = "CYBERSEC-UNKNOWN",
) -> Path:
    """Render the current scan artefacts to an .xlsx workbook."""
    root = Path(reports_dir).resolve()

    syft = _collect_json_from_paths(
        root, ["sbom/syft.json", "sbom/syft.syft.json"], ["syft.json", "syft.syft.json"]
    )
    grype = _collect_json_from_paths(
        root, ["reports/grype/grype_report.json", "reports/grype/report.json"], ["grype_report.json"]
    )
    trivy = _collect_json_from_paths(
        root,
        ["reports/trivy/trivy_report.json", "reports/trivy/trivy.json", "reports/trivy/report.json"],
        ["trivy_report.json", "trivy.json"],
    )
    cve = _collect_json_from_paths(
        root,
        [
            "reports/cve-bin-tool/cve-bin-tool_report.json",
            "reports/cve-bin-tool/cve_raw.json",
            "reports/cve-bin-tool/report.json",
        ],
        ["cve-bin-tool_report.json", "cve_raw.json"],
    )
    status = _find_json_by_name(root, ["status.json"]) or {}
    summary = _find_json_by_name(root, ["summary.json"]) or {}
    run_manifest = _find_json_by_name(root, ["run_manifest.json"]) or {}
    db_snapshot = _find_json_by_name(root, ["db_snapshot.json"]) or {}
    extraction = _find_json_by_name(root, ["extraction_manifest.json"]) or {}

    grype_findings = _grype_findings(grype)
    trivy_findings = _trivy_findings(trivy)
    cve_findings, dropped_collisions = filter_vendor_collisions(
        _cve_bin_tool_findings(cve), maven_groups_from_sbom(syft)
    )
    raw = grype_findings + trivy_findings + cve_findings
    findings = _dedup_findings(raw)
    try:  # EPSS / KEV columns when the offline feeds are present
        from .enrichment import enrich_findings

        enrich_findings(findings)
    except Exception:
        pass

    # Headline totals follow the raw per-tool counts, exactly as the Markdown
    # report does — the deduped list is for reading, not for counting.
    counts = Counter(item["severity"] for item in raw)
    per_tool = {
        "grype": len(grype_findings),
        "trivy": len(trivy_findings),
        "cve-bin-tool": len(cve_findings),
    }

    input_hashes: dict[str, str] = {}
    for holder in (summary, run_manifest):
        if isinstance(holder, dict) and isinstance(holder.get("input_hashes"), dict):
            input_hashes = holder["input_hashes"]
            break
    target_hashes: dict[str, str] = {}
    for holder in (summary, run_manifest):
        if isinstance(holder, dict) and isinstance(holder.get("target_hashes"), dict):
            target_hashes = holder["target_hashes"]
            break
    final_sha = (target_digest(target_path) or "") if target_path else ""
    shown_target = display_target or (str(target_path) if target_path else "UNKNOWN")

    sheets = [
        _summary_sheet(
            case_id=case_id,
            display_target=shown_target,
            input_hashes=input_hashes,
            target_hashes=target_hashes,
            final_sha=final_sha,
            counts=counts,
            per_tool=per_tool,
            syft_components=_syft_count(syft),
            db_snapshot=db_snapshot,
            status=status,
            summary=summary,
            extraction=extraction,
            dropped_collisions=len(dropped_collisions),
        )
    ]

    widths = [width for _, _, width in _FINDING_COLUMNS]
    all_sheet = Sheet("Находки", widths=widths, freeze_header=True, autofilter=True)
    all_sheet.rows = _finding_rows(findings)
    sheets.append(all_sheet)

    high_critical = [f for f in findings if f.get("severity") in {"CRITICAL", "HIGH"}]
    hc_sheet = Sheet("High-Critical", widths=widths, freeze_header=True, autofilter=True)
    hc_sheet.rows = _finding_rows(high_critical)
    sheets.append(hc_sheet)

    sbom_sheet = Sheet("SBOM", widths=[44, 26, 18, 60], freeze_header=True, autofilter=True)
    sbom_sheet.add(*[(h, STYLE_HEADER) for h in ("Компонент", "Версия", "Тип", "purl")])
    for artifact in (syft or {}).get("artifacts", []) if isinstance(syft, dict) else []:
        if not isinstance(artifact, dict):
            continue
        sbom_sheet.add(
            artifact.get("name", ""),
            artifact.get("version", ""),
            artifact.get("type", ""),
            artifact.get("purl", ""),
        )
    sheets.append(sbom_sheet)

    return write_workbook(output_path, sheets)


__all__ = ["build_xlsx_report"]
