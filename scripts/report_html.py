#!/usr/bin/env python3
"""Generate a self-contained HTML vulnerability report from SCA scanner artifacts.

Usage:
    python scripts/report_html.py --artifacts-dir artifacts --output report.html --target /path/to/file
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime
from html import escape
from pathlib import Path


TOOL_ORDER = ["grype", "trivy", "cve-bin-tool"]
TOOL_COLOR = {"grype": "#7c3aed", "trivy": "#0369a1", "cve-bin-tool": "#b45309", "syft": "#0f766e"}
TOOL_LABEL = {"grype": "Grype", "trivy": "Trivy", "cve-bin-tool": "cve-bin-tool", "syft": "Syft"}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NEGLIGIBLE": 4, "UNKNOWN": 5}
SEV_STYLE = {
    "CRITICAL": ("#b91c1c", "#fee2e2", "#fca5a5"),
    "HIGH": ("#c2410c", "#ffedd5", "#fdba74"),
    "MEDIUM": ("#a16207", "#fef9c3", "#fde047"),
    "LOW": ("#15803d", "#dcfce7", "#86efac"),
    "NEGLIGIBLE": ("#4b5563", "#f3f4f6", "#d1d5db"),
    "UNKNOWN": ("#4b5563", "#f3f4f6", "#d1d5db"),
}


def load_json(path: str | os.PathLike[str] | None):
    if not path or not os.path.exists(path):
        return None


def hash_target(path: str | os.PathLike[str] | None) -> dict[str, str]:
    if not path:
        return {}
    candidate = Path(path)
    if not candidate.exists() or not candidate.is_file():
        return {}
    sha1_digest = hashlib.sha1()
    sha256_digest = hashlib.sha256()
    with candidate.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha1_digest.update(chunk)
            sha256_digest.update(chunk)
    return {
        "sha1": sha1_digest.hexdigest(),
        "sha256": sha256_digest.hexdigest(),
    }
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] could not load {path}: {exc}", file=sys.stderr)
        return None


def parse_grype(data):
    if not data:
        return []
    findings = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        score = ""
        for item in vuln.get("cvss", []):
            value = (item.get("metrics") or {}).get("baseScore")
            if value is not None:
                score = str(value)
                break
        fix_versions = (vuln.get("fix") or {}).get("versions") or []
        cve = vuln.get("id", "")
        findings.append(
            {
                "tool": "grype",
                "cve": cve,
                "severity": (vuln.get("severity") or "UNKNOWN").upper(),
                "score": score,
                "product": artifact.get("name", ""),
                "version": artifact.get("version", ""),
                "pkg_type": artifact.get("type", ""),
                "fix": ", ".join(fix_versions),
                "fix_state": (vuln.get("fix") or {}).get("state", ""),
                "url": (
                    f"https://nvd.nist.gov/vuln/detail/{cve}"
                    if cve.startswith("CVE-")
                    else f"https://github.com/advisories/{cve}"
                    if cve.startswith("GHSA-")
                    else ""
                ),
            }
        )
    return findings


def parse_trivy(data):
    if not data:
        return []
    findings = []
    for result in data.get("Results", []):
        pkg_type = result.get("Type", "")
        for vuln in result.get("Vulnerabilities") or []:
            score = ""
            for source in ("nvd", "redhat"):
                values = (vuln.get("CVSS") or {}).get(source, {})
                score_value = values.get("V3Score") or values.get("V2Score")
                if score_value is not None:
                    score = str(score_value)
                    break
            findings.append(
                {
                    "tool": "trivy",
                    "cve": vuln.get("VulnerabilityID", ""),
                    "severity": (vuln.get("Severity") or "UNKNOWN").upper(),
                    "score": score,
                    "product": vuln.get("PkgName", ""),
                    "version": vuln.get("InstalledVersion", ""),
                    "pkg_type": pkg_type,
                    "fix": vuln.get("FixedVersion", ""),
                    "fix_state": "fixed" if vuln.get("FixedVersion") else "",
                    "url": vuln.get("PrimaryURL", ""),
                }
            )
    return findings


def parse_cvebt(data):
    rows = data if isinstance(data, list) else []
    findings = []
    for row in rows:
        cve = row.get("cve_number", "")
        findings.append(
            {
                "tool": "cve-bin-tool",
                "cve": cve,
                "severity": (row.get("severity") or "UNKNOWN").upper(),
                "score": str(row.get("score") or ""),
                "product": row.get("product", ""),
                "version": row.get("version", ""),
                "pkg_type": "",
                "fix": "",
                "fix_state": "",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}" if cve.startswith("CVE-") else "",
            }
        )
    return findings


def parse_syft_components(data):
    if not data:
        return []
    components = []
    for artifact in data.get("artifacts", []):
        components.append(
            {
                "name": artifact.get("name", ""),
                "version": artifact.get("version", ""),
                "type": artifact.get("type", ""),
                "purl": artifact.get("purl", ""),
                "locations": len(artifact.get("locations") or []),
            }
        )
    components.sort(key=lambda item: (item["name"], item["version"], item["type"]))
    return components


def severity_badge(severity):
    fg, bg, _ = SEV_STYLE.get(severity, SEV_STYLE["UNKNOWN"])
    return (
        f'<span class="badge" style="color:{fg};background:{bg};border:1px solid {fg}40">'
        f"{escape(severity)}</span>"
    )


def score_html(score):
    if not score or score in ("", "None"):
        return '<span class="muted">-</span>'
    try:
        value = float(score)
    except ValueError:
        return escape(score)
    if value >= 9.0:
        color = "#b91c1c"
    elif value >= 7.0:
        color = "#c2410c"
    elif value >= 4.0:
        color = "#a16207"
    else:
        color = "#15803d"
    return f'<span style="font-weight:700;color:{color}">{value:.1f}</span>'


def dedupe_findings(findings):
    seen = set()
    deduped = []
    for finding in findings:
        key = (
            finding["tool"],
            finding["cve"],
            finding["product"],
            finding["version"],
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def sort_findings(findings):
    def sort_key(item):
        try:
            score = -float(item["score"])
        except (ValueError, TypeError):
            score = 0
        return (SEV_ORDER.get(item["severity"], 5), score, item["cve"], item["product"])

    return sorted(findings, key=sort_key)


def build_page_paths(output_path: str | os.PathLike[str]):
    output = Path(output_path)
    if output.stem == "index":
        return {
            "overview": output,
            "grype": output.with_name("grype.html"),
            "trivy": output.with_name("trivy.html"),
            "cve-bin-tool": output.with_name("cve-bin-tool.html"),
            "syft": output.with_name("syft.html"),
        }
    return {
        "overview": output,
        "grype": output.with_name(f"{output.stem}_grype{output.suffix}"),
        "trivy": output.with_name(f"{output.stem}_trivy{output.suffix}"),
        "cve-bin-tool": output.with_name(f"{output.stem}_cve-bin-tool{output.suffix}"),
        "syft": output.with_name(f"{output.stem}_syft{output.suffix}"),
    }


def load_report_metadata(artifacts_dir: str | os.PathLike[str], target_display: str):
    artifacts = Path(artifacts_dir)
    summary = load_json(artifacts / "summary.json") or {}
    run_manifest = load_json(artifacts / "run_manifest.json") or {}
    db_snapshot = load_json(artifacts / "db_snapshot.json") or {}
    status = load_json(artifacts / "status.json") or {}
    target_hashes = hash_target(target_display)
    input_hashes = summary.get("input_hashes") or run_manifest.get("input_hashes") or {}
    tools = {}
    raw_tools = db_snapshot.get("tools") or {}
    if isinstance(raw_tools, dict):
        for tool_name, payload in raw_tools.items():
            if not isinstance(payload, dict):
                continue
            tools[tool_name] = {
                "db_version": str(payload.get("db_version") or "UNKNOWN"),
                "db_source": str(payload.get("db_source") or "UNKNOWN"),
                "updated_at": str(payload.get("updated_at") or "UNKNOWN"),
                "built_at": str(payload.get("built_at") or "UNKNOWN"),
                "update_state": str(payload.get("update_state") or "UNKNOWN"),
            }
    for tool_name, key in (("trivy", "update_trivy_db"), ("grype", "update_grype_db"), ("cve-bin-tool", "update_cve_db")):
        tools.setdefault(tool_name, {})
        tools[tool_name].setdefault("update_state", str(summary.get(key) or "UNKNOWN"))
        tools[tool_name].setdefault("db_version", "UNKNOWN")
        tools[tool_name].setdefault("db_source", "UNKNOWN")
        tools[tool_name].setdefault("updated_at", "UNKNOWN")
        tools[tool_name].setdefault("built_at", "UNKNOWN")
    return {
        "db_snapshot_id": str(summary.get("db_snapshot_id") or run_manifest.get("db_snapshot_id") or db_snapshot.get("snapshot_id") or "UNKNOWN"),
        "db_drift": str(status.get("db_drift") or summary.get("db_drift") or "UNKNOWN"),
        "tool_failures": str(status.get("tool_failures") or summary.get("tool_failures") or "UNKNOWN"),
        "input_sha256": str(summary.get("input_sha256") or (run_manifest.get("input") or {}).get("sha256") or "UNKNOWN"),
        "input_hashes": {
            "sha1": str(input_hashes.get("sha1") or "UNKNOWN"),
            "sha256": str(input_hashes.get("sha256") or summary.get("input_sha256") or "UNKNOWN"),
        },
        "target_hashes": {
            "sha1": str(target_hashes.get("sha1") or "UNKNOWN"),
            "sha256": str(target_hashes.get("sha256") or "UNKNOWN"),
        },
        "tools": tools,
    }


def nav_html(page_paths, active_key):
    items = [
        ("overview", "Overview"),
        ("grype", "Grype"),
        ("trivy", "Trivy"),
        ("cve-bin-tool", "cve-bin-tool"),
        ("syft", "Syft"),
    ]
    links = []
    current_dir = page_paths[active_key].parent
    for key, label in items:
        href = os.path.relpath(page_paths[key], current_dir).replace("\\", "/")
        cls = "nav-link active" if key == active_key else "nav-link"
        links.append(f'<a class="{cls}" href="{escape(href)}">{escape(label)}</a>')
    return "".join(links)


def render_findings_rows(findings):
    rows = []
    for finding in findings:
        cve = escape(finding["cve"])
        cve_html = (
            f'<a href="{escape(finding["url"])}" target="_blank" class="cve-link">{cve}</a>'
            if finding["url"]
            else f'<span class="mono">{cve}</span>'
        )
        fix_html = ""
        if finding["fix"]:
            fix_html = f'<span class="fix-yes">yes: {escape(finding["fix"])}</span>'
        elif finding["fix_state"] == "wont-fix":
            fix_html = '<span class="fix-no">wont-fix</span>'
        rows.append(
            f"""
        <tr data-sev="{escape(finding['severity'])}">
          <td><span class="tool-tag" style="color:{TOOL_COLOR.get(finding['tool'], '#6b7280')};border-color:{TOOL_COLOR.get(finding['tool'], '#6b7280')}40;background:{TOOL_COLOR.get(finding['tool'], '#6b7280')}10">{escape(finding['tool'])}</span></td>
          <td class="mono">{cve_html}</td>
          <td>{severity_badge(finding['severity'])}</td>
          <td class="score-cell">{score_html(finding['score'])}</td>
          <td><span class="pkg-name">{escape(finding['product'])}</span>{f'<br><span class="pkg-type">{escape(finding["pkg_type"])}</span>' if finding["pkg_type"] else ""}</td>
          <td class="mono ver">{escape(finding['version'])}</td>
          <td>{fix_html}</td>
        </tr>"""
        )
    return "".join(rows)


def render_component_rows(components):
    rows = []
    for component in components:
        rows.append(
            f"""
        <tr>
          <td><span class="pkg-name">{escape(component['name'])}</span>{f'<br><span class="pkg-type">{escape(component["type"])}</span>' if component["type"] else ""}</td>
          <td class="mono ver">{escape(component['version'])}</td>
          <td class="mono">{escape(component['purl']) if component['purl'] else '<span class="muted">-</span>'}</td>
          <td class="score-cell">{component['locations']}</td>
        </tr>"""
        )
    return "".join(rows)


def render_summary_cards(total, severity_counts, components):
    return f"""
  <div class="cards">
    <div class="card" style="border-color:#334155">
      <div class="card-num" style="color:#0f172a">{total}</div>
      <div class="card-label">Findings</div>
    </div>
    <div class="card" style="border-color:#b91c1c">
      <div class="card-num" style="color:#b91c1c">{severity_counts.get("CRITICAL", 0)}</div>
      <div class="card-label">Critical</div>
    </div>
    <div class="card" style="border-color:#c2410c">
      <div class="card-num" style="color:#c2410c">{severity_counts.get("HIGH", 0)}</div>
      <div class="card-label">High</div>
    </div>
    <div class="card" style="border-color:#a16207">
      <div class="card-num" style="color:#a16207">{severity_counts.get("MEDIUM", 0)}</div>
      <div class="card-label">Medium</div>
    </div>
    <div class="card" style="border-color:#0f766e">
      <div class="card-num" style="color:#0f766e">{components}</div>
      <div class="card-label">Syft components</div>
    </div>
  </div>"""


def render_bars(severity_counts, total):
    bars = []
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(severity, 0)
        pct = (count / total * 100) if total else 0
        fg, _, _ = SEV_STYLE.get(severity, SEV_STYLE["UNKNOWN"])
        bars.append(
            f"""
          <div class="bar-row">
            <div class="bar-label" style="color:{fg}">{severity}</div>
            <div class="bar-track">
              <div class="bar-fill" style="width:{pct:.1f}%;background:{fg}"></div>
            </div>
            <div class="bar-count" style="color:{fg}">{count}</div>
          </div>"""
        )
    return "".join(bars)


def render_tool_breakdown(tool_counts):
    rows = []
    for tool in TOOL_ORDER:
        count = tool_counts.get(tool, 0)
        rows.append(
            f'<div class="tool-item"><span style="color:{TOOL_COLOR[tool]};font-weight:700">{escape(TOOL_LABEL[tool])}</span><span class="tool-cnt">{count}</span></div>'
        )
    return "".join(rows)


def render_metadata(metadata):
    tool_rows = []
    for tool_name in ("trivy", "grype", "cve-bin-tool"):
        tool = metadata["tools"].get(tool_name, {})
        tool_rows.append(
            f"""
          <div class="stat-row"><span class="stat-label">{escape(tool_name)} state</span><span class="stat-value">{escape(tool.get('update_state', 'UNKNOWN'))}</span></div>
          <div class="stat-row"><span class="stat-label">{escape(tool_name)} version</span><span class="stat-value mono">{escape(tool.get('db_version', 'UNKNOWN'))}</span></div>
          <div class="stat-row"><span class="stat-label">{escape(tool_name)} updated</span><span class="stat-value mono">{escape(tool.get('updated_at', 'UNKNOWN'))}</span></div>
        """
        )
        if tool.get("built_at", "UNKNOWN") != "UNKNOWN":
            tool_rows.append(
                f'<div class="stat-row"><span class="stat-label">{escape(tool_name)} built</span><span class="stat-value mono">{escape(tool.get("built_at", "UNKNOWN"))}</span></div>'
            )
    return f"""
  <div class="section">
    <div class="section-title">Hashes and DB metadata</div>
    <div class="charts-row">
      <div class="section" style="margin-bottom:0">
        <div class="section-title">Artifact hashes</div>
        <div class="stats-block">
          <div class="stat-row"><span class="stat-label">Final target SHA-1</span><span class="stat-value mono">{escape(metadata['target_hashes']['sha1'])}</span></div>
          <div class="stat-row"><span class="stat-label">Final target SHA-256</span><span class="stat-value mono">{escape(metadata['target_hashes']['sha256'])}</span></div>
          <div class="stat-row"><span class="stat-label">Input artifact SHA-1</span><span class="stat-value mono">{escape(metadata['input_hashes']['sha1'])}</span></div>
          <div class="stat-row"><span class="stat-label">Input artifact SHA-256</span><span class="stat-value mono">{escape(metadata['input_hashes']['sha256'])}</span></div>
        </div>
      </div>
      <div class="section" style="margin-bottom:0">
        <div class="section-title">DB snapshot</div>
        <div class="stats-block">
          <div class="stat-row"><span class="stat-label">Snapshot ID</span><span class="stat-value mono">{escape(metadata['db_snapshot_id'])}</span></div>
          <div class="stat-row"><span class="stat-label">DB drift</span><span class="stat-value">{escape(metadata['db_drift'])}</span></div>
          <div class="stat-row"><span class="stat-label">Tool failures</span><span class="stat-value">{escape(metadata['tool_failures'])}</span></div>
        </div>
      </div>
    </div>
    <div class="section" style="margin-bottom:0">
      <div class="section-title">Tool database versions and update times</div>
      <div class="stats-block">
        {''.join(tool_rows)}
      </div>
    </div>
  </div>"""


def page_template(title, target_display, date_str, nav, body_html, base_name):
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{escape(title)} - {escape(base_name)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f1f5f9;
    color: #0f172a;
    font-size: 14px;
    line-height: 1.5;
  }}
  .header {{
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
    color: white;
    padding: 28px 40px 24px;
  }}
  .header-title {{ font-size: 22px; font-weight: 800; letter-spacing: -0.3px; }}
  .header-target {{
    font-size: 13px;
    color: #94a3b8;
    font-family: "Courier New", monospace;
    margin-top: 6px;
    word-break: break-all;
  }}
  .header-meta {{
    display: flex;
    gap: 24px;
    font-size: 12px;
    color: #cbd5e1;
    margin-top: 12px;
    flex-wrap: wrap;
  }}
  .nav {{
    display: flex;
    gap: 10px;
    margin-top: 18px;
    flex-wrap: wrap;
  }}
  .nav-link {{
    color: #cbd5e1;
    text-decoration: none;
    border: 1px solid #475569;
    border-radius: 999px;
    padding: 6px 12px;
    font-size: 12px;
    font-weight: 700;
  }}
  .nav-link.active {{
    background: white;
    color: #0f172a;
    border-color: white;
  }}
  .container {{
    max-width: 1440px;
    margin: 0 auto;
    padding: 24px 40px;
  }}
  .cards {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 14px;
    margin-bottom: 20px;
  }}
  .card {{
    background: white;
    border-radius: 12px;
    padding: 18px 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,.07), 0 1px 2px rgba(0,0,0,.04);
    border-top: 3px solid;
  }}
  .card-num {{ font-size: 38px; font-weight: 900; line-height: 1; letter-spacing: -1px; }}
  .card-label {{ font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .07em; color: #64748b; margin-top: 4px; }}
  .section {{
    background: white;
    border-radius: 12px;
    padding: 22px 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,.07);
    margin-bottom: 20px;
  }}
  .section-title {{
    font-size: 14px;
    font-weight: 700;
    color: #0f172a;
    margin-bottom: 16px;
    padding-bottom: 10px;
    border-bottom: 1px solid #e2e8f0;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .section-title .count {{
    font-size: 12px;
    background: #f1f5f9;
    color: #64748b;
    padding: 2px 8px;
    border-radius: 999px;
    font-weight: 600;
  }}
  .charts-row {{
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 20px;
    margin-bottom: 20px;
  }}
  .bar-row {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 8px;
  }}
  .bar-label {{
    width: 90px;
    font-size: 12px;
    font-weight: 700;
    text-align: right;
  }}
  .bar-track {{
    flex: 1;
    background: #f1f5f9;
    border-radius: 4px;
    height: 22px;
    overflow: hidden;
  }}
  .bar-fill {{
    height: 100%;
    border-radius: 4px;
  }}
  .bar-count {{
    width: 32px;
    text-align: right;
    font-weight: 800;
    font-size: 13px;
  }}
  .stats-block {{ padding: 4px 0; }}
  .stat-row {{
    display: flex;
    justify-content: space-between;
    padding: 6px 0;
    border-bottom: 1px solid #f1f5f9;
    font-size: 13px;
  }}
  .stat-row:last-child {{ border-bottom: none; }}
  .stat-label {{ color: #64748b; }}
  .stat-value {{ font-weight: 700; color: #0f172a; }}
  .tool-item {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 7px 10px;
    background: #f8fafc;
    border-radius: 6px;
    margin-bottom: 6px;
    font-size: 13px;
  }}
  .tool-cnt {{
    font-weight: 800;
    font-size: 15px;
    color: #374151;
  }}
  .filter-bar {{
    display: flex;
    gap: 10px;
    margin-bottom: 14px;
    flex-wrap: wrap;
    align-items: center;
  }}
  .search-input {{
    flex: 1;
    min-width: 220px;
    padding: 8px 14px;
    border: 1.5px solid #e2e8f0;
    border-radius: 8px;
    font-size: 13px;
    outline: none;
  }}
  .sev-btn {{
    padding: 6px 14px;
    border-radius: 999px;
    border: 1.5px solid transparent;
    font-size: 12px;
    font-weight: 700;
    cursor: pointer;
    background: #f1f5f9;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: .05em;
  }}
  .sev-btn.active {{
    background: #0f172a;
    color: white;
  }}
  .table-wrap {{ overflow-x: auto; max-height: 640px; overflow-y: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  thead th {{
    position: sticky;
    top: 0;
    background: #f8fafc;
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .06em;
    color: #64748b;
    padding: 10px 12px;
    border-bottom: 2px solid #e2e8f0;
    white-space: nowrap;
    z-index: 1;
  }}
  tbody td {{
    padding: 9px 12px;
    border-bottom: 1px solid #f1f5f9;
    vertical-align: middle;
  }}
  tbody tr:hover td {{ background: #f8fafc; }}
  .tool-tag {{
    display: inline-block;
    font-size: 11px;
    font-weight: 700;
    padding: 2px 7px;
    border-radius: 4px;
    border: 1px solid;
    white-space: nowrap;
  }}
  .badge {{
    display: inline-block;
    font-size: 11px;
    font-weight: 800;
    padding: 2px 8px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: .04em;
    white-space: nowrap;
  }}
  .cve-link {{
    color: #2563eb;
    text-decoration: none;
    font-family: "Courier New", monospace;
    font-size: 12px;
  }}
  .cve-link:hover {{ text-decoration: underline; }}
  .mono {{ font-family: "Courier New", monospace; font-size: 12px; }}
  .ver {{ color: #475569; }}
  .score-cell {{ text-align: right; }}
  .pkg-name {{ font-weight: 600; }}
  .pkg-type {{ font-size: 11px; color: #94a3b8; }}
  .fix-yes {{ color: #15803d; font-size: 12px; font-weight: 600; }}
  .fix-no {{ color: #b91c1c; font-size: 12px; }}
  .muted {{ color: #94a3b8; }}
  .footer {{
    text-align: center;
    padding: 20px;
    color: #94a3b8;
    font-size: 12px;
  }}
  @media (max-width: 900px) {{
    .cards {{ grid-template-columns: repeat(2, 1fr); }}
    .charts-row {{ grid-template-columns: 1fr; }}
    .container {{ padding: 16px; }}
    .header {{ padding: 20px 16px; }}
  }}
</style>
</head>
<body>
<div class="header">
  <div class="header-title">{escape(title)}</div>
  <div class="header-target">{escape(target_display or "Unknown")}</div>
  <div class="header-meta">
    <span>{escape(date_str)}</span>
    <span>Trivy + Grype + cve-bin-tool + Syft</span>
  </div>
  <div class="nav">{nav}</div>
</div>
<div class="container">
{body_html}
</div>
<div class="footer">Generated by el-sca-ansamble · {escape(date_str)}</div>
<script>
  function bindFilters(rootId) {{
    var root = document.getElementById(rootId);
    if (!root) return;
    var activeSev = 'all';
    var searchQ = '';
    function applyFilters() {{
      var rows = root.querySelectorAll('tbody tr');
      var hidden = 0;
      rows.forEach(function(row) {{
        var sevMatch = activeSev === 'all' || row.dataset.sev === activeSev;
        var textMatch = !searchQ || row.textContent.toLowerCase().includes(searchQ);
        var show = sevMatch && textMatch;
        row.style.display = show ? '' : 'none';
        if (!show) hidden++;
      }});
      var empty = root.querySelector('.no-results');
      if (empty) {{
        empty.style.display = hidden === rows.length ? '' : 'none';
      }}
    }}
    var search = root.querySelector('.search-input');
    if (search) {{
      search.addEventListener('input', function() {{
        searchQ = this.value.toLowerCase();
        applyFilters();
      }});
    }}
    root.querySelectorAll('.sev-btn').forEach(function(btn) {{
      btn.addEventListener('click', function() {{
        activeSev = btn.dataset.sev;
        root.querySelectorAll('.sev-btn').forEach(function(item) {{ item.classList.remove('active'); }});
        btn.classList.add('active');
        applyFilters();
      }});
    }});
  }}
  bindFilters('findings-root');
</script>
</body>
</html>"""


def build_finding_page(page_key, page_title, findings, target_display, page_paths, components_total, tool_counts, metadata):
    deduped = sort_findings(dedupe_findings(findings))
    severity_counts = {}
    for finding in deduped:
        severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1
    total = len(deduped)
    body = (
        render_summary_cards(total, severity_counts, components_total)
        + render_metadata(metadata)
        + f"""
  <div class="charts-row">
    <div class="section">
      <div class="section-title">Severity distribution</div>
      {render_bars(severity_counts, total)}
    </div>
    <div>
      <div class="section" style="margin-bottom:14px">
        <div class="section-title">Quick stats</div>
        <div class="stats-block">
          <div class="stat-row"><span class="stat-label">Unique findings</span><span class="stat-value">{total}</span></div>
          <div class="stat-row"><span class="stat-label">Critical + High</span><span class="stat-value" style="color:#b91c1c">{severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)}</span></div>
          <div class="stat-row"><span class="stat-label">Syft components</span><span class="stat-value">{components_total}</span></div>
          <div class="stat-row"><span class="stat-label">Fix versions known</span><span class="stat-value" style="color:#15803d">{sum(1 for item in deduped if item["fix"])}</span></div>
        </div>
      </div>
      <div class="section">
        <div class="section-title">By tool</div>
        {render_tool_breakdown(tool_counts)}
      </div>
    </div>
  </div>
  <div class="section" id="findings-root">
    <div class="section-title">Findings <span class="count">{total}</span></div>
    <div class="filter-bar">
      <input type="text" class="search-input" placeholder="Search by CVE, package, version">
      <button class="sev-btn active" data-sev="all">All</button>
      <button class="sev-btn" data-sev="CRITICAL" style="color:#b91c1c">Critical</button>
      <button class="sev-btn" data-sev="HIGH" style="color:#c2410c">High</button>
      <button class="sev-btn" data-sev="MEDIUM" style="color:#a16207">Medium</button>
      <button class="sev-btn" data-sev="LOW" style="color:#15803d">Low</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Tool</th>
            <th>CVE / GHSA</th>
            <th>Severity</th>
            <th style="text-align:right">Score</th>
            <th>Package</th>
            <th>Version</th>
            <th>Fix</th>
          </tr>
        </thead>
        <tbody>
          {render_findings_rows(deduped)}
        </tbody>
      </table>
    </div>
    <div class="no-results" style="display:none;text-align:center;padding:32px;color:#94a3b8">No matching rows</div>
  </div>"""
    )
    html = page_template(
        page_title,
        target_display,
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        nav_html(page_paths, page_key),
        body,
        os.path.basename(target_display or "Unknown"),
    )
    page_paths[page_key].parent.mkdir(parents=True, exist_ok=True)
    page_paths[page_key].write_text(html, encoding="utf-8")


def build_syft_page(page_paths, target_display, components, all_findings, metadata):
    severity_counts = {}
    for finding in all_findings:
        severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1
    body = (
        render_summary_cards(len(all_findings), severity_counts, len(components))
        + render_metadata(metadata)
        + f"""
  <div class="charts-row">
    <div class="section">
      <div class="section-title">SBOM component inventory</div>
      <div class="stats-block">
        <div class="stat-row"><span class="stat-label">Components</span><span class="stat-value">{len(components)}</span></div>
        <div class="stat-row"><span class="stat-label">Findings across all tools</span><span class="stat-value">{len(all_findings)}</span></div>
      </div>
    </div>
    <div class="section">
      <div class="section-title">By tool</div>
      {render_tool_breakdown({tool: sum(1 for item in all_findings if item["tool"] == tool) for tool in TOOL_ORDER})}
    </div>
  </div>
  <div class="section">
    <div class="section-title">Syft components <span class="count">{len(components)}</span></div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Version</th>
            <th>PURL</th>
            <th style="text-align:right">Locations</th>
          </tr>
        </thead>
        <tbody>
          {render_component_rows(components)}
        </tbody>
      </table>
    </div>
  </div>"""
    )
    html = page_template(
        "Syft components",
        target_display,
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        nav_html(page_paths, "syft"),
        body,
        os.path.basename(target_display or "Unknown"),
    )
    page_paths["syft"].parent.mkdir(parents=True, exist_ok=True)
    page_paths["syft"].write_text(html, encoding="utf-8")


def generate_html_site(findings, target_display, artifacts_dir, output_path, components):
    page_paths = build_page_paths(output_path)
    deduped_all = sort_findings(dedupe_findings(findings))
    tool_counts = {tool: sum(1 for item in deduped_all if item["tool"] == tool) for tool in TOOL_ORDER}
    metadata = load_report_metadata(artifacts_dir, target_display)
    build_finding_page("overview", "SCA report overview", deduped_all, target_display, page_paths, len(components), tool_counts, metadata)
    for tool in TOOL_ORDER:
        build_finding_page(
            tool,
            f"{TOOL_LABEL[tool]} findings",
            [item for item in deduped_all if item["tool"] == tool],
            target_display,
            page_paths,
            len(components),
            tool_counts,
            metadata,
        )
    build_syft_page(page_paths, target_display, components, deduped_all, metadata)
    print(f"HTML report → {page_paths['overview']}")
    for key in ("grype", "trivy", "cve-bin-tool", "syft"):
        print(f"HTML page   → {page_paths[key]}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Generate HTML SCA vulnerability report")
    parser.add_argument("--artifacts-dir", required=True, help="Path to artifacts/ directory")
    parser.add_argument("--output", required=True, help="Output .html file path for the overview page")
    parser.add_argument("--target", default="", help="Display name of the scanned target")
    args = parser.parse_args()

    artifacts_dir = args.artifacts_dir
    syft_data = load_json(os.path.join(artifacts_dir, "sbom", "syft.json"))
    findings = []
    findings += parse_grype(load_json(os.path.join(artifacts_dir, "reports", "grype", "report.json")))
    findings += parse_trivy(load_json(os.path.join(artifacts_dir, "reports", "trivy", "report.json")))
    findings += parse_cvebt(load_json(os.path.join(artifacts_dir, "reports", "cve-bin-tool", "report.json")))
    components = parse_syft_components(syft_data)

    if not findings:
        print("[warn] no findings loaded — check artifacts/ structure", file=sys.stderr)

    return generate_html_site(findings, args.target, artifacts_dir, args.output, components)


if __name__ == "__main__":
    sys.exit(main())
