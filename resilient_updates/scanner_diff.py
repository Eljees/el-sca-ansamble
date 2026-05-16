"""Compare two scanner runs (SBOMs + raw report JSON) and produce a structured diff.

Use cases:
- "What new vulnerabilities appeared after a dependency bump?"
- "Did we actually fix CVE-X-Y, or did we just hide it behind a different binary?"
- "What components changed between v1.2.3 and v1.2.4 of the same artifact?"

The diff is computed across three layers:

1. **SBOM components** — packages observed by Syft.  Keyed by (name, version).
2. **Findings** — CVE/GHSA matches reported by Grype/Trivy/cve-bin-tool.
   Keyed by (id, product, version, tool) so the same CVE reported by two
   scanners on the same component shows up once per (CVE, tool) pair —
   which is what humans usually want when triaging "did scanner X also catch
   this?".
3. **Severity counts** — quick at-a-glance summary.

No network access, no external dependencies; reads two scan directories and
writes either JSON (machine-readable, default) or Markdown (human-readable,
``--format md``).  Each scan directory is the same ``artifacts/`` layout the
rest of the pipeline produces, so the typical invocation is:

    python -m resilient_updates.cli scanner-diff \\
        --before snapshot/run-2026-05-10/artifacts \\
        --after  artifacts \\
        --output artifacts/reports/diff.json
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json


# ---------------------------------------------------------------------------
# JSON loaders (mirror reporting._read_json / _collect_json_from_paths)
# ---------------------------------------------------------------------------

def _read_json(path: Path) -> Any:
    if not path.exists() or path.is_dir():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _first_json(root: Path, relpaths: list[str]) -> Any:
    for rel in relpaths:
        data = _read_json(root / rel)
        if data is not None:
            return data
    return None


# ---------------------------------------------------------------------------
# Extraction helpers — return normalised "row" lists with the same keys as
# reporting.py so a diff entry shows the same columns as the main report.
# ---------------------------------------------------------------------------

def _normalize_severity(value: Any) -> str:
    if not value:
        return "UNKNOWN"
    return str(value).upper()


def _components_from_syft(syft: Any) -> list[dict[str, str]]:
    if not isinstance(syft, dict):
        return []
    rows: list[dict[str, str]] = []
    for item in syft.get("artifacts") or []:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "name": str(item.get("name", "")),
                "version": str(item.get("version", "")),
                "type": str(item.get("type", "")),
                "purl": str(item.get("purl", "")),
            }
        )
    return rows


def _findings_from_grype(grype: Any) -> list[dict[str, str]]:
    if not isinstance(grype, dict):
        return []
    rows: list[dict[str, str]] = []
    for match in grype.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        rows.append(
            {
                "tool": "grype",
                "id": str(vuln.get("id") or vuln.get("name") or "UNKNOWN"),
                "severity": _normalize_severity(vuln.get("severity")),
                "product": str(artifact.get("name", "")),
                "version": str(artifact.get("version", "")),
            }
        )
    return rows


def _findings_from_trivy(trivy: Any) -> list[dict[str, str]]:
    if not isinstance(trivy, dict):
        return []
    rows: list[dict[str, str]] = []
    for result in trivy.get("Results") or []:
        for entry in result.get("Vulnerabilities") or []:
            rows.append(
                {
                    "tool": "trivy",
                    "id": str(entry.get("VulnerabilityID", "UNKNOWN")),
                    "severity": _normalize_severity(entry.get("Severity")),
                    "product": str(entry.get("PkgName", "")),
                    "version": str(entry.get("InstalledVersion", "")),
                }
            )
    return rows


def _findings_from_cve_bin_tool(cve: Any) -> list[dict[str, str]]:
    if not isinstance(cve, list):
        return []
    rows: list[dict[str, str]] = []
    for entry in cve:
        if not isinstance(entry, dict):
            continue
        rows.append(
            {
                "tool": "cve-bin-tool",
                "id": str(entry.get("cve_number") or entry.get("CVE", "UNKNOWN")),
                "severity": _normalize_severity(entry.get("severity")),
                "product": str(entry.get("product", "")),
                "version": str(entry.get("version", "")),
            }
        )
    return rows


def _load_findings(root: Path) -> list[dict[str, str]]:
    grype = _first_json(root, [
        "reports/grype/report.json",
        "reports/grype/grype_report.json",
    ])
    trivy = _first_json(root, [
        "reports/trivy/report.json",
        "reports/trivy/trivy_report.json",
    ])
    cve = _first_json(root, [
        "reports/cve-bin-tool/report.json",
        "reports/cve-bin-tool/cve-bin-tool_report.json",
    ])
    return (
        _findings_from_grype(grype)
        + _findings_from_trivy(trivy)
        + _findings_from_cve_bin_tool(cve)
    )


def _load_components(root: Path) -> list[dict[str, str]]:
    syft = _first_json(root, [
        "sbom/syft.json",
        "sbom/syft.syft.json",
    ])
    return _components_from_syft(syft)


# ---------------------------------------------------------------------------
# Diff engine
# ---------------------------------------------------------------------------

def _comp_key(row: dict[str, str]) -> tuple[str, str]:
    return (row["name"], row["version"])


def _finding_key(row: dict[str, str]) -> tuple[str, str, str, str]:
    return (row["id"], row["product"], row["version"], row["tool"])


@dataclass
class DiffSummary:
    components_added: list[dict[str, str]]
    components_removed: list[dict[str, str]]
    components_unchanged: int

    findings_added: list[dict[str, str]]
    findings_removed: list[dict[str, str]]
    findings_unchanged: int

    severity_delta: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "components": {
                "added": self.components_added,
                "removed": self.components_removed,
                "unchanged_count": self.components_unchanged,
                "added_count": len(self.components_added),
                "removed_count": len(self.components_removed),
            },
            "findings": {
                "added": self.findings_added,
                "removed": self.findings_removed,
                "unchanged_count": self.findings_unchanged,
                "added_count": len(self.findings_added),
                "removed_count": len(self.findings_removed),
            },
            "severity_delta": self.severity_delta,
        }


def diff_runs(before_root: str | Path, after_root: str | Path) -> DiffSummary:
    before = Path(before_root)
    after = Path(after_root)

    # ── Components ────────────────────────────────────────────────────────
    before_comps = _load_components(before)
    after_comps = _load_components(after)
    before_keys = {_comp_key(c) for c in before_comps}
    after_keys = {_comp_key(c) for c in after_comps}
    added_comp_keys = after_keys - before_keys
    removed_comp_keys = before_keys - after_keys
    unchanged_comp_count = len(before_keys & after_keys)

    added_comps = [c for c in after_comps if _comp_key(c) in added_comp_keys]
    removed_comps = [c for c in before_comps if _comp_key(c) in removed_comp_keys]

    # ── Findings ─────────────────────────────────────────────────────────
    before_finds = _load_findings(before)
    after_finds = _load_findings(after)
    before_fkeys = {_finding_key(f) for f in before_finds}
    after_fkeys = {_finding_key(f) for f in after_finds}
    added_fkeys = after_fkeys - before_fkeys
    removed_fkeys = before_fkeys - after_fkeys
    unchanged_find_count = len(before_fkeys & after_fkeys)

    added_finds = [f for f in after_finds if _finding_key(f) in added_fkeys]
    removed_finds = [f for f in before_finds if _finding_key(f) in removed_fkeys]

    # ── Severity delta (after - before) ───────────────────────────────────
    before_sev = Counter(f["severity"] for f in before_finds)
    after_sev = Counter(f["severity"] for f in after_finds)
    all_severities = sorted(set(before_sev) | set(after_sev))
    severity_delta = {
        s: int(after_sev.get(s, 0)) - int(before_sev.get(s, 0)) for s in all_severities
    }

    return DiffSummary(
        components_added=added_comps,
        components_removed=removed_comps,
        components_unchanged=unchanged_comp_count,
        findings_added=added_finds,
        findings_removed=removed_finds,
        findings_unchanged=unchanged_find_count,
        severity_delta=severity_delta,
    )


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def to_markdown(summary: DiffSummary, *, before_label: str, after_label: str) -> str:
    lines: list[str] = []
    lines.append(f"# scanner-diff: {before_label} → {after_label}")
    lines.append("")

    sev = summary.severity_delta
    if sev:
        lines.append("## Severity delta")
        lines.append("")
        lines.append("| Severity | Δ |")
        lines.append("|---|---:|")
        for s, delta in sorted(sev.items(), key=lambda kv: (-abs(kv[1]), kv[0])):
            sign = "+" if delta > 0 else ""
            lines.append(f"| {s} | {sign}{delta} |")
        lines.append("")

    lines.append("## Components")
    lines.append("")
    lines.append(
        f"- Added: **{len(summary.components_added)}** "
        f"| Removed: **{len(summary.components_removed)}** "
        f"| Unchanged: **{summary.components_unchanged}**"
    )
    lines.append("")
    if summary.components_added:
        lines.append("### Added components")
        lines.append("")
        lines.append("| Name | Version | Type |")
        lines.append("|---|---|---|")
        for c in sorted(summary.components_added, key=lambda r: (r["name"], r["version"])):
            lines.append(f"| {c['name']} | {c['version']} | {c.get('type', '')} |")
        lines.append("")
    if summary.components_removed:
        lines.append("### Removed components")
        lines.append("")
        lines.append("| Name | Version | Type |")
        lines.append("|---|---|---|")
        for c in sorted(summary.components_removed, key=lambda r: (r["name"], r["version"])):
            lines.append(f"| {c['name']} | {c['version']} | {c.get('type', '')} |")
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    lines.append(
        f"- Added: **{len(summary.findings_added)}** "
        f"| Removed: **{len(summary.findings_removed)}** "
        f"| Unchanged: **{summary.findings_unchanged}**"
    )
    lines.append("")
    if summary.findings_added:
        lines.append("### New findings")
        lines.append("")
        lines.append("| Tool | CVE/GHSA | Severity | Product | Version |")
        lines.append("|---|---|---|---|---|")
        for f in sorted(summary.findings_added, key=lambda r: (r["severity"], r["id"])):
            lines.append(
                f"| {f['tool']} | {f['id']} | {f['severity']} | {f['product']} | {f['version']} |"
            )
        lines.append("")
    if summary.findings_removed:
        lines.append("### Resolved findings")
        lines.append("")
        lines.append("| Tool | CVE/GHSA | Severity | Product | Version |")
        lines.append("|---|---|---|---|---|")
        for f in sorted(summary.findings_removed, key=lambda r: (r["severity"], r["id"])):
            lines.append(
                f"| {f['tool']} | {f['id']} | {f['severity']} | {f['product']} | {f['version']} |"
            )
        lines.append("")

    return "\n".join(lines) + "\n"


__all__ = [
    "DiffSummary",
    "diff_runs",
    "to_markdown",
]
