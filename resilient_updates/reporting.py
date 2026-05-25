from __future__ import annotations

from collections import Counter
from datetime import date
import re
from pathlib import Path
from typing import Any

from ._io import (
    sha256_file as _sha256_file,
    sha256_dir as _sha256_dir,
    read_json as _read_json,
)


DEFAULT_CASE_ID = "CYBERSEC-UNKNOWN"
_CASE_ID_RE = re.compile(r"\b(CYBERSEC-\d+)\b", re.IGNORECASE)
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

# Hash + JSON helpers used to be inlined here; they were duplicated across
# reporting.py / run_summary.py / extractor.py / scanner_diff.py.  Moved to
# resilient_updates._io for shared use.  Module-level aliases above keep
# call sites unchanged.  See docs/audit/20-architecture.md section 1.


def target_digest(path: str | Path) -> str | None:
    resolved = Path(path)
    if not resolved.exists():
        return None
    if resolved.is_file():
        return _sha256_file(resolved)
    return _sha256_dir(resolved)


def _normalize_severity(value: Any) -> str:
    if not value:
        return "UNKNOWN"
    return str(value).upper()


def _syft_count(data: Any) -> int:
    if not isinstance(data, dict):
        return 0
    if isinstance(data.get("artifacts"), list):
        return len(data["artifacts"])
    if isinstance(data.get("components"), list):
        return len(data["components"])
    return 0


def _grype_findings(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    findings = []
    for match in data.get("matches", []) or []:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        findings.append(
            {
                "tool": "grype",
                "id": vuln.get("id") or vuln.get("name") or "UNKNOWN",
                "severity": _normalize_severity(vuln.get("severity")),
                "score": vuln.get("cvss", [{}])[0].get("metrics", {}).get("baseScore") if vuln.get("cvss") else "",
                "vendor": artifact.get("type") or "",
                "product": artifact.get("name") or "",
                "version": artifact.get("version") or "",
                "source": "grype",
            }
        )
    return findings


def _trivy_findings(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    findings = []
    for result in data.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(
                {
                    "tool": "trivy",
                    "id": vuln.get("VulnerabilityID") or "UNKNOWN",
                    "severity": _normalize_severity(vuln.get("Severity")),
                    "score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", ""),
                    "vendor": result.get("Type") or "",
                    "product": vuln.get("PkgName") or "",
                    "version": vuln.get("InstalledVersion") or "",
                    "source": vuln.get("PrimaryURL") or "trivy",
                }
            )
    return findings


def _cve_bin_tool_findings(data: Any) -> list[dict[str, Any]]:
    findings = []
    if isinstance(data, dict):
        candidates = data.get("findings") or data.get("results") or data.get("cves") or data.get("vulnerabilities") or []
    elif isinstance(data, list):
        candidates = data
    else:
        candidates = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        findings.append(
            {
                "tool": "cve-bin-tool",
                "id": item.get("cve_number") or item.get("cve") or item.get("id") or item.get("CVE") or "UNKNOWN",
                "severity": _normalize_severity(item.get("severity") or item.get("cvss_severity")),
                "score": item.get("score") or item.get("cvss_score") or item.get("CVSSv3_Severity") or "",
                "vendor": item.get("vendor") or "",
                "product": item.get("product") or item.get("package") or "",
                "version": item.get("version") or "",
                "source": item.get("source") or "cve-bin-tool",
            }
        )
    return findings


def _collect_json(root: Path, names: list[str]) -> Any:
    for name in names:
        found = sorted(root.rglob(name))
        if found:
            return _read_json(found[-1])
    return None


def _collect_json_from_paths(root: Path, relative_paths: list[str], fallback_names: list[str] | None = None) -> Any:
    for relative_path in relative_paths:
        data = _read_json(root / relative_path)
        if data is not None:
            return data
    if fallback_names:
        return _collect_json(root, fallback_names)
    return None


def _get_nested(data: Any, keys: list[str], default: Any = None) -> Any:
    current = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def _collect_paths(root: Path) -> list[str]:
    if not root.exists():
        return []
    paths = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if "extracted" in relative.parts and path.name != "extraction_manifest.json":
            continue
        paths.append(str(path))
    return paths


def _required_report_paths(root: Path) -> dict[str, Path]:
    return {
        "syft": root / "sbom" / "syft.json",
        "grype": root / "reports" / "grype" / "report.json",
        "trivy": root / "reports" / "trivy" / "report.json",
        "cve-bin-tool": root / "reports" / "cve-bin-tool" / "report.json",
    }


def _markdown_table(findings: list[dict[str, Any]]) -> str:
    """Render High/Critical findings as a Markdown table.

    The legacy columns (Tool / CVE / Severity / Score / Vendor / Product /
    Version / Source) are always rendered.  When EPSS or KEV data is
    available for at least one row (rows enriched by
    ``resilient_updates.enrichment.enrich_findings``), two extra columns —
    EPSS and KEV — are appended so triagers can sort by exploit likelihood
    and known-exploited status at a glance.
    """
    if not findings:
        return "High/Critical findings не обнаружены.\n"

    has_enrichment = any(item.get("epss") not in (None, "") or item.get("kev") for item in findings)
    if has_enrichment:
        header = (
            "| Tool | CVE/GHSA | Severity | Score | Vendor | Product | Version | "
            "Source | EPSS | KEV |"
        )
        rule = "|---|---|---|---:|---|---|---|---|---:|:---:|"
    else:
        header = "| Tool | CVE/GHSA | Severity | Score | Vendor | Product | Version | Source |"
        rule = "|---|---|---|---:|---|---|---|---|"
    lines: list[str] = [header, rule]
    for item in sorted(findings, key=lambda row: (SEVERITY_ORDER.get(row["severity"], 9), row["id"], row["tool"])):
        cells = {key: str(value).replace("|", "\\|") for key, value in item.items()}
        # Provide blank defaults so .format() never raises KeyError.
        for fallback in ("tool", "id", "severity", "score", "vendor", "product", "version", "source"):
            cells.setdefault(fallback, "")
        if has_enrichment:
            epss_raw = item.get("epss", "")
            try:
                epss_display = f"{float(epss_raw):.3f}" if epss_raw not in (None, "") else ""
            except (TypeError, ValueError):
                epss_display = str(epss_raw)
            cells["epss"] = epss_display
            cells["kev"] = "yes" if item.get("kev") in ("yes", True, "true", "True") else ""
            lines.append(
                "| {tool} | {id} | {severity} | {score} | {vendor} | {product} | {version} | "
                "{source} | {epss} | {kev} |".format(**cells)
            )
        else:
            lines.append(
                "| {tool} | {id} | {severity} | {score} | {vendor} | {product} | "
                "{version} | {source} |".format(**cells)
            )
    return "\n".join(lines) + "\n"


def _dedup_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate findings that differ only by artifact location.

    When a target contains multiple executables built from the same source
    (e.g. Prometheus ships both `prometheus` and `promtool`), every scanner
    reports the same CVE once per binary.  We deduplicate on the tuple
    (id, product, version, tool) — keeping the first occurrence — so the
    final report counts and table reflect unique vulnerabilities, not
    occurrences-per-binary.
    """
    seen: set[tuple[str, str, str, str]] = set()
    result: list[dict[str, Any]] = []
    for item in findings:
        key = (
            str(item.get("id", "")),
            str(item.get("product", "")),
            str(item.get("version", "")),
            str(item.get("tool", "")),
        )
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _resolve_case_id(
    case_id: str | None,
    target_path: str | Path | None = None,
    display_target: str | None = None,
) -> str:
    explicit = (case_id or "").strip()
    if explicit and explicit.upper() != DEFAULT_CASE_ID:
        return explicit
    for candidate in (display_target, target_path):
        if candidate is None:
            continue
        match = _CASE_ID_RE.search(str(candidate))
        if match:
            return match.group(1).upper()
    return DEFAULT_CASE_ID


def build_report(
    reports_dir: str | Path,
    output_path: str | Path,
    target_path: str | Path | None = None,
    display_target: str | None = None,
    case_id: str = DEFAULT_CASE_ID,
) -> Path:
    root = Path(reports_dir).resolve()
    output = Path(output_path)
    required_paths = _required_report_paths(root)
    missing_required = [f"{name}: {path}" for name, path in required_paths.items() if not path.exists()]
    if missing_required:
        missing_text = "; ".join(missing_required)
        raise FileNotFoundError(f"missing required scan artifacts: {missing_text}")
    syft = _collect_json_from_paths(root, ["sbom/syft.json", "sbom/syft.syft.json"], ["syft.json", "syft.syft.json"])
    grype = _collect_json_from_paths(root, ["reports/grype/grype_report.json", "reports/grype/report.json"], ["grype_report.json"])
    trivy = _collect_json_from_paths(root, ["reports/trivy/trivy_report.json", "reports/trivy/trivy.json", "reports/trivy/report.json"], ["trivy_report.json", "trivy.json"])
    cve = _collect_json_from_paths(
        root,
        ["reports/cve-bin-tool/cve-bin-tool_report.json", "reports/cve-bin-tool/cve_raw.json", "reports/cve-bin-tool/report.json"],
        ["cve-bin-tool_report.json", "cve_raw.json"],
    )
    status = _collect_json(root, ["status.json"]) or {}
    summary = _collect_json(root, ["summary.json"]) or {}
    run_manifest = _collect_json(root, ["run_manifest.json"]) or {}
    db_snapshot = _collect_json(root, ["db_snapshot.json"]) or {}
    extraction_manifest = _collect_json(root, ["extraction_manifest.json"]) or {}

    # Phase 5.8 — when the sidecar JSONs aren't on disk (the historical
    # default — no stage writes them) derive them in-memory from the
    # artefacts that DO exist so the report header stops showing UNKNOWN.
    # The derive call is cheap (one Path.read_text per scanner output) and
    # never raises: missing inputs leave fields blank.
    if not (status and summary and run_manifest and db_snapshot):
        try:
            from .run_summary import derive as _derive_run_summary
            _auto = _derive_run_summary(root)
            if not summary:       summary       = _auto["summary"]
            if not status:        status        = _auto["status"]
            if not run_manifest:  run_manifest  = _auto["run_manifest"]
            if not db_snapshot:   db_snapshot   = _auto["db_snapshot"]
        except Exception:  # noqa: BLE001 — never let derivation block a report
            pass
    provenance = sorted({*(root / "provenance").glob("*.json"), *root.rglob("provenance/*.json")})

    # Detect whether cve-bin-tool scan was cut short by the timeout wrapper.
    # When it times out, update_cve_bin_tool.sh writes timeout.flag alongside report.json.
    # Without this flag the report shows "0 findings" indistinguishably from a genuine clean scan.
    cve_timeout_flag = root / "reports" / "cve-bin-tool" / "timeout.flag"
    cve_timed_out = cve_timeout_flag.exists()
    cve_timeout_seconds: str = "unknown"
    if cve_timed_out:
        try:
            for line in cve_timeout_flag.read_text(encoding="utf-8").splitlines():
                if line.startswith("timed_out_after="):
                    cve_timeout_seconds = line.split("=", 1)[1].strip()
        except Exception:  # noqa: BLE001
            pass

    all_findings_raw = _grype_findings(grype) + _trivy_findings(trivy) + _cve_bin_tool_findings(cve)
    all_findings = _dedup_findings(all_findings_raw)
    # Phase 5.2 — annotate with EPSS exploit-likelihood scores and CISA KEV flag
    # when the on-disk feeds are available.  Best-effort; missing feeds leave
    # the columns blank and the legacy table format is rendered.
    try:
        from .enrichment import enrich_findings
        enrich_findings(all_findings)
    except Exception:  # noqa: BLE001 — never let enrichment block a report
        pass
    high_critical = [item for item in all_findings if item["severity"] in {"CRITICAL", "HIGH"}]
    severity_counts = Counter(item["severity"] for item in all_findings)
    syft_count = _get_nested(summary, ["coverage", "sbom_components"], _syft_count(syft))
    grype_count = summary.get("estimated_grype_matches", len(_grype_findings(grype))) if isinstance(summary, dict) else len(_grype_findings(grype))
    cve_count = summary.get("estimated_cve_bin_tool_matches", len(_cve_bin_tool_findings(cve))) if isinstance(summary, dict) else len(_cve_bin_tool_findings(cve))
    parsed_counts = {
        "grype": len(_grype_findings(grype)),
        "trivy": len(_trivy_findings(trivy)),
        "cve-bin-tool": len(_cve_bin_tool_findings(cve)),
    }
    summary_counts = {"grype": grype_count, "trivy": parsed_counts["trivy"], "cve-bin-tool": cve_count}
    warnings = [
        f"{tool}: summary={summary_counts[tool]}, parsed_raw={parsed_counts[tool]}"
        for tool in parsed_counts
        if int(summary_counts[tool] or 0) != parsed_counts[tool]
    ]
    if syft_count == 0:
        warnings.append(
            "syft: 0 components -- extraction may not have run or target has no recognized"
            " package manifests/binaries; run scan_archive.sh or run-scan.ps1 -Extract"
        )
    if cve_timed_out:
        warnings.append(
            f"cve-bin-tool: scan timed out after {cve_timeout_seconds}s -- results show"
            " 0 findings but scan did not complete; increase"
            " CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS or reduce scan target size"
        )

    target = str(display_target or target_path or "UNKNOWN")
    digest = target_digest(target_path) if target_path else None
    input_sha = summary.get("input_sha256") or _get_nested(run_manifest, ["input", "sha256"])
    db_snapshot_id = summary.get("db_snapshot_id") or run_manifest.get("db_snapshot_id") or db_snapshot.get("snapshot_id")
    tool_failures = status.get("tool_failures", summary.get("tool_failures", "UNKNOWN")) if isinstance(status, dict) else "UNKNOWN"
    db_drift = status.get("db_drift", summary.get("db_drift", "UNKNOWN")) if isinstance(status, dict) else "UNKNOWN"
    evidence_files = _collect_paths(root)
    resolved_case_id = _resolve_case_id(case_id, target_path, display_target)

    report = [
        f"# {resolved_case_id}: контейнерный SCA-отчет",
        "",
        f"Дата анализа: {date.today().isoformat()}",
        "",
        "## Объект анализа",
        "",
        f"- Target: `{target}`",
        f"- SHA-256: `{digest or 'UNKNOWN'}`",
        f"- Input archive SHA-256: `{input_sha or 'UNKNOWN'}`",
        f"- DB snapshot: `{db_snapshot_id or 'UNKNOWN'}`",
        f"- DB drift: `{db_drift}`",
        f"- Tool failures: `{tool_failures}`",
        f"- Update policy: `grype={summary.get('update_grype_db', 'UNKNOWN')}`, `cve-bin-tool={summary.get('update_cve_db', 'UNKNOWN')}`",
        f"- Extraction status: `{extraction_manifest.get('status', 'UNKNOWN')}`",
        f"- Extracted archives: `{extraction_manifest.get('extracted_count', 'UNKNOWN')}`",
        "",
        "## Evidence",
        "",
    ]
    if evidence_files:
        report.extend([f"- `{item}`" for item in evidence_files])
    else:
        report.append("- Evidence files not found.")
    report.extend(
        [
            "",
            "## Scanner summary",
            "",
            f"- Syft components: `{syft_count}`",
            f"- Grype findings: `{grype_count}`",
            f"- Trivy findings: `{len(_trivy_findings(trivy))}`",
            f"- cve-bin-tool findings: `{cve_count}`",
            f"- Total findings: `{int(grype_count or 0) + len(_trivy_findings(trivy)) + int(cve_count or 0)}`",
            f"- Severity counts: `{dict(severity_counts)}`",
            f"- Policy decision: `{summary.get('policy_decision', 'UNKNOWN')}`",
            "",
            "## Consistency warnings",
            "",
        ]
    )
    if warnings:
        report.extend([f"- `{item}`" for item in warnings])
    else:
        report.append("- No discrepancies between summary and raw JSON.")
    report.extend(
        [
            "",
            "## High / Critical findings",
            "",
            _markdown_table(high_critical),
            "## Provenance",
            "",
        ]
    )
    if provenance:
        report.extend([f"- `{item}`" for item in provenance])
    else:
        report.append("- Provenance JSON not found.")
    report.extend(
        [
            "",
            "## Interpretation",
            "",
            "Отчет агрегирует raw evidence из контейнерного пайплайна. Находки являются сигналом сканеров, а не подтвержденной применимостью уязвимостей.",
            "",
            "## Recommendations",
            "",
            "1. Вручную проверить High/Critical находки в контексте поставки.",
            "2. Хранить raw JSON рядом с итоговым Markdown-отчетом.",
            "3. Фиксировать DB snapshot ID и версии инструментов для воспроизводимых сравнений.",
            "",
        ]
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(report), encoding="utf-8")
    return output
