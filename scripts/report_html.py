#!/usr/bin/env python3
"""Generate a self-contained HTML vulnerability report from SCA scanner artifacts.

Usage:
    python scripts/report_html.py --artifacts-dir artifacts --output report.html --target /path/to/file
"""

import argparse
import json
import os
import sys
from datetime import datetime
from html import escape
from pathlib import Path


# ── JSON loaders ─────────────────────────────────────────────────────────────

def load_json(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[warn] could not load {path}: {e}", file=sys.stderr)
        return None


# ── Parser: Grype ─────────────────────────────────────────────────────────────

def parse_grype(data):
    if not data:
        return []
    findings = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        pkg = artifact.get("name", "")
        version = artifact.get("version", "")
        cve = vuln.get("id", "")
        severity = (vuln.get("severity") or "UNKNOWN").upper()
        # best CVSS score
        score = ""
        for s in vuln.get("cvss", []):
            v = (s.get("metrics") or {}).get("baseScore")
            if v is not None:
                score = str(v)
                break
        fix_versions = (vuln.get("fix") or {}).get("versions") or []
        fix = ", ".join(fix_versions)
        fix_state = (vuln.get("fix") or {}).get("state", "")
        pkg_type = artifact.get("type", "")
        url = f"https://nvd.nist.gov/vuln/detail/{cve}" if cve.startswith("CVE-") else \
              f"https://github.com/advisories/{cve}" if cve.startswith("GHSA-") else ""
        findings.append(dict(tool="grype", cve=cve, severity=severity, score=score,
                             product=pkg, version=version, pkg_type=pkg_type,
                             fix=fix, fix_state=fix_state, url=url))
    return findings


# ── Parser: Trivy ─────────────────────────────────────────────────────────────

def parse_trivy(data):
    if not data:
        return []
    findings = []
    for result in data.get("Results", []):
        pkg_type = result.get("Type", "")
        for vuln in result.get("Vulnerabilities") or []:
            cve = vuln.get("VulnerabilityID", "")
            severity = (vuln.get("Severity") or "UNKNOWN").upper()
            cvss_map = (vuln.get("CVSS") or {})
            score = ""
            for src in ("nvd", "redhat"):
                s = cvss_map.get(src, {})
                v = s.get("V3Score") or s.get("V2Score")
                if v is not None:
                    score = str(v)
                    break
            findings.append(dict(
                tool="trivy",
                cve=cve, severity=severity, score=score,
                product=vuln.get("PkgName", ""),
                version=vuln.get("InstalledVersion", ""),
                pkg_type=pkg_type,
                fix=vuln.get("FixedVersion", ""),
                fix_state="fixed" if vuln.get("FixedVersion") else "",
                url=vuln.get("PrimaryURL", ""),
            ))
    return findings


# ── Parser: cve-bin-tool ──────────────────────────────────────────────────────

def parse_cvebt(data):
    if not data:
        return []
    rows = data if isinstance(data, list) else []
    findings = []
    for row in rows:
        cve = row.get("cve_number", "")
        severity = (row.get("severity") or "UNKNOWN").upper()
        score = str(row.get("score") or "")
        findings.append(dict(
            tool="cve-bin-tool",
            cve=cve, severity=severity, score=score,
            product=row.get("product", ""),
            version=row.get("version", ""),
            pkg_type="",
            fix="", fix_state="",
            url=f"https://nvd.nist.gov/vuln/detail/{cve}" if cve.startswith("CVE-") else "",
        ))
    return findings


# ── Severity helpers ──────────────────────────────────────────────────────────

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NEGLIGIBLE": 4, "UNKNOWN": 5}

SEV_STYLE = {
    "CRITICAL":   ("#b91c1c", "#fee2e2", "#fca5a5"),
    "HIGH":       ("#c2410c", "#ffedd5", "#fdba74"),
    "MEDIUM":     ("#a16207", "#fef9c3", "#fde047"),
    "LOW":        ("#15803d", "#dcfce7", "#86efac"),
    "NEGLIGIBLE": ("#4b5563", "#f3f4f6", "#d1d5db"),
    "UNKNOWN":    ("#4b5563", "#f3f4f6", "#d1d5db"),
}


def severity_badge(sev):
    fg, bg, _ = SEV_STYLE.get(sev, SEV_STYLE["UNKNOWN"])
    return (f'<span class="badge" '
            f'style="color:{fg};background:{bg};border:1px solid {fg}40">'
            f'{escape(sev)}</span>')


def score_html(score):
    if not score or score in ("", "None"):
        return '<span style="color:#9ca3af">—</span>'
    try:
        v = float(score)
    except ValueError:
        return escape(score)
    if v >= 9.0:
        color = "#b91c1c"
    elif v >= 7.0:
        color = "#c2410c"
    elif v >= 4.0:
        color = "#a16207"
    else:
        color = "#15803d"
    return f'<span style="font-weight:700;color:{color}">{v:.1f}</span>'


# ── HTML generation ───────────────────────────────────────────────────────────

TOOL_COLOR = {"grype": "#7c3aed", "trivy": "#0369a1", "cve-bin-tool": "#b45309"}


def generate_html(findings, target_display, artifacts_dir, output_path):
    # Deduplicate
    seen, deduped = set(), []
    for f in findings:
        key = (f["tool"], f["cve"], f["product"], f["version"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Sort: severity → score desc
    def sort_key(f):
        try:
            s = -float(f["score"])
        except (ValueError, TypeError):
            s = 0
        return (SEV_ORDER.get(f["severity"], 5), s)

    deduped.sort(key=sort_key)

    counts = {}
    for f in deduped:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    total    = len(deduped)
    critical = counts.get("CRITICAL", 0)
    high     = counts.get("HIGH", 0)
    medium   = counts.get("MEDIUM", 0)
    low      = counts.get("LOW", 0)

    # Component count from syft
    components = 0
    syft = load_json(os.path.join(artifacts_dir, "sbom", "syft.json"))
    if syft:
        components = len(syft.get("artifacts", []))

    date_str  = datetime.now().strftime("%Y-%m-%d %H:%M")
    base_name = os.path.basename(target_display) if target_display else "Unknown"

    # ── Severity bar chart ──
    bars = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        c = counts.get(sev, 0)
        pct = c / total * 100 if total else 0
        fg, bg, _ = SEV_STYLE.get(sev, SEV_STYLE["UNKNOWN"])
        bars += f"""
          <div class="bar-row">
            <div class="bar-label" style="color:{fg}">{sev}</div>
            <div class="bar-track">
              <div class="bar-fill" style="width:{pct:.1f}%;background:{fg}"></div>
            </div>
            <div class="bar-count" style="color:{fg}">{c}</div>
          </div>"""

    # ── Tool breakdown ──
    tool_counts = {}
    for f in deduped:
        tool_counts[f["tool"]] = tool_counts.get(f["tool"], 0) + 1

    tool_rows = ""
    for tool, cnt in sorted(tool_counts.items()):
        tc = TOOL_COLOR.get(tool, "#6b7280")
        tool_rows += f'<div class="tool-item"><span style="color:{tc};font-weight:700">{escape(tool)}</span><span class="tool-cnt">{cnt}</span></div>'

    # ── Table rows ──
    rows_html = ""
    for f in deduped:
        cve = escape(f["cve"])
        cve_html = (f'<a href="{escape(f["url"])}" target="_blank" class="cve-link">{cve}</a>'
                    if f["url"] else f'<span class="mono">{cve}</span>')
        fix_html = ""
        if f["fix"]:
            fix_html = f'<span class="fix-yes">✓ {escape(f["fix"])}</span>'
        elif f["fix_state"] == "wont-fix":
            fix_html = '<span class="fix-no">won\'t fix</span>'

        tc = TOOL_COLOR.get(f["tool"], "#6b7280")
        rows_html += f"""
        <tr data-sev="{escape(f['severity'])}">
          <td><span class="tool-tag" style="color:{tc};border-color:{tc}40;background:{tc}10">{escape(f['tool'])}</span></td>
          <td class="mono">{cve_html}</td>
          <td>{severity_badge(f['severity'])}</td>
          <td class="score-cell">{score_html(f['score'])}</td>
          <td><span class="pkg-name">{escape(f['product'])}</span>
              {f'<br><span class="pkg-type">{escape(f["pkg_type"])}</span>' if f["pkg_type"] else ""}
          </td>
          <td class="mono ver">{escape(f['version'])}</td>
          <td>{fix_html}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SCA Report — {escape(base_name)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f1f5f9;
    color: #0f172a;
    font-size: 14px;
    line-height: 1.5;
  }}

  /* Header */
  .header {{
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
    color: white;
    padding: 28px 40px 24px;
  }}
  .header-top {{
    display: flex;
    align-items: flex-start;
    gap: 16px;
    margin-bottom: 12px;
  }}
  .header-icon {{ font-size: 32px; line-height: 1; }}
  .header-title {{ font-size: 22px; font-weight: 800; letter-spacing: -0.3px; }}
  .header-target {{
    font-size: 13px;
    color: #94a3b8;
    font-family: "Courier New", monospace;
    margin-top: 4px;
    word-break: break-all;
  }}
  .header-meta {{
    display: flex;
    gap: 24px;
    font-size: 12px;
    color: #64748b;
    margin-top: 8px;
  }}
  .header-meta span {{ display: flex; align-items: center; gap: 6px; }}

  /* Layout */
  .container {{
    max-width: 1440px;
    margin: 0 auto;
    padding: 24px 40px;
  }}

  /* Summary cards */
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
    transition: transform .15s, box-shadow .15s;
  }}
  .card:hover {{
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,.1);
  }}
  .card-num  {{ font-size: 38px; font-weight: 900; line-height: 1; letter-spacing: -1px; }}
  .card-label {{ font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .07em; color: #64748b; margin-top: 4px; }}

  /* Section */
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

  /* Charts row */
  .charts-row {{
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 20px;
    margin-bottom: 20px;
  }}

  /* Bar chart */
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
    transition: width .4s ease;
  }}
  .bar-count {{
    width: 32px;
    text-align: right;
    font-weight: 800;
    font-size: 13px;
  }}

  /* Stats block */
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

  /* Tool breakdown */
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

  /* Filter bar */
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
    transition: border-color .15s, box-shadow .15s;
  }}
  .search-input:focus {{
    border-color: #3b82f6;
    box-shadow: 0 0 0 3px #3b82f620;
  }}
  .sev-btn {{
    padding: 6px 14px;
    border-radius: 999px;
    border: 1.5px solid transparent;
    font-size: 12px;
    font-weight: 700;
    cursor: pointer;
    transition: all .15s;
    background: #f1f5f9;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: .05em;
  }}
  .sev-btn:hover, .sev-btn.active {{
    background: #0f172a;
    color: white;
  }}

  /* Table */
  .table-wrap {{ overflow-x: auto; max-height: 600px; overflow-y: auto; }}
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

  /* Cells */
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
  .fix-no  {{ color: #b91c1c; font-size: 12px; }}

  /* Footer */
  .footer {{
    text-align: center;
    padding: 20px;
    color: #94a3b8;
    font-size: 12px;
  }}

  @media (max-width: 900px) {{
    .cards {{ grid-template-columns: repeat(3, 1fr); }}
    .charts-row {{ grid-template-columns: 1fr; }}
    .container {{ padding: 16px; }}
    .header {{ padding: 20px 16px; }}
  }}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div class="header-top">
    <div class="header-icon">🔬</div>
    <div>
      <div class="header-title">SCA Security Report</div>
      <div class="header-target">{escape(target_display or "Unknown")}</div>
    </div>
  </div>
  <div class="header-meta">
    <span>📅 {date_str}</span>
    <span>📦 {components} компонентов</span>
    <span>🔍 Trivy · Grype · cve-bin-tool · Syft</span>
  </div>
</div>

<div class="container">

  <!-- Cards -->
  <div class="cards">
    <div class="card" style="border-color:#334155">
      <div class="card-num" style="color:#0f172a">{total}</div>
      <div class="card-label">Всего</div>
    </div>
    <div class="card" style="border-color:#b91c1c">
      <div class="card-num" style="color:#b91c1c">{critical}</div>
      <div class="card-label">Critical</div>
    </div>
    <div class="card" style="border-color:#c2410c">
      <div class="card-num" style="color:#c2410c">{high}</div>
      <div class="card-label">High</div>
    </div>
    <div class="card" style="border-color:#a16207">
      <div class="card-num" style="color:#a16207">{medium}</div>
      <div class="card-label">Medium</div>
    </div>
    <div class="card" style="border-color:#15803d">
      <div class="card-num" style="color:#15803d">{low}</div>
      <div class="card-label">Low</div>
    </div>
  </div>

  <!-- Charts row -->
  <div class="charts-row">
    <div class="section">
      <div class="section-title">📊 Распределение по критичности</div>
      {bars}
    </div>

    <div>
      <div class="section" style="margin-bottom:14px">
        <div class="section-title">📈 Статистика</div>
        <div class="stats-block">
          <div class="stat-row"><span class="stat-label">Компонентов (Syft)</span><span class="stat-value">{components}</span></div>
          <div class="stat-row"><span class="stat-label">Уникальных CVE</span><span class="stat-value">{total}</span></div>
          <div class="stat-row"><span class="stat-label">Critical + High</span><span class="stat-value" style="color:#b91c1c">{critical + high}</span></div>
          <div class="stat-row"><span class="stat-label">С исправлением</span><span class="stat-value" style="color:#15803d">{sum(1 for f in deduped if f["fix"])}</span></div>
        </div>
      </div>
      <div class="section">
        <div class="section-title">🛠 По инструментам</div>
        {tool_rows}
      </div>
    </div>
  </div>

  <!-- Findings table -->
  <div class="section">
    <div class="section-title">
      🐛 Уязвимости
      <span class="count">{total}</span>
    </div>
    <div class="filter-bar">
      <input type="text" id="search" class="search-input" placeholder="Поиск по CVE, пакету, версии...">
      <button class="sev-btn active" onclick="filterSev('all',this)">Все</button>
      <button class="sev-btn" onclick="filterSev('CRITICAL',this)" style="color:#b91c1c">Critical</button>
      <button class="sev-btn" onclick="filterSev('HIGH',this)" style="color:#c2410c">High</button>
      <button class="sev-btn" onclick="filterSev('MEDIUM',this)" style="color:#a16207">Medium</button>
      <button class="sev-btn" onclick="filterSev('LOW',this)" style="color:#15803d">Low</button>
    </div>
    <div class="table-wrap">
      <table id="tbl">
        <thead>
          <tr>
            <th>Инструмент</th>
            <th>CVE / GHSA</th>
            <th>Уровень</th>
            <th style="text-align:right">Score</th>
            <th>Пакет</th>
            <th>Версия</th>
            <th>Исправление</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </div>
    <div id="no-results" style="display:none;text-align:center;padding:32px;color:#94a3b8">
      Ничего не найдено
    </div>
  </div>

</div>

<div class="footer">
  Сгенерировано el-sca-ansamble &nbsp;·&nbsp; {date_str}
</div>

<script>
  var activeSev = 'all';
  var searchQ   = '';

  function applyFilters() {{
    var rows = document.querySelectorAll('#tbl tbody tr');
    var hidden = 0;
    rows.forEach(function(row) {{
      var sevMatch = activeSev === 'all' || row.dataset.sev === activeSev;
      var textMatch = !searchQ || row.textContent.toLowerCase().includes(searchQ);
      var show = sevMatch && textMatch;
      row.style.display = show ? '' : 'none';
      if (!show) hidden++;
    }});
    document.getElementById('no-results').style.display =
      hidden === rows.length ? '' : 'none';
  }}

  function filterSev(sev, btn) {{
    activeSev = sev;
    document.querySelectorAll('.sev-btn').forEach(function(b) {{ b.classList.remove('active'); }});
    btn.classList.add('active');
    applyFilters();
  }}

  document.getElementById('search').addEventListener('input', function() {{
    searchQ = this.value.toLowerCase();
    applyFilters();
  }});
</script>

</body>
</html>
"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"HTML report → {output_path}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Generate HTML SCA vulnerability report")
    ap.add_argument("--artifacts-dir", required=True, help="Path to artifacts/ directory")
    ap.add_argument("--output",        required=True, help="Output .html file path")
    ap.add_argument("--target",        default="",   help="Display name of the scanned target")
    args = ap.parse_args()

    adir = args.artifacts_dir
    findings = []
    findings += parse_grype(load_json(os.path.join(adir, "reports", "grype",        "report.json")))
    findings += parse_trivy(load_json(os.path.join(adir, "reports", "trivy",        "report.json")))
    findings += parse_cvebt(load_json(os.path.join(adir, "reports", "cve-bin-tool", "report.json")))

    if not findings:
        print("[warn] no findings loaded — check artifacts/ structure", file=sys.stderr)

    return generate_html(findings, args.target, adir, args.output)


if __name__ == "__main__":
    sys.exit(main())
