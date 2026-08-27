"""XLSX report: the hand-rolled OOXML writer and the workbook layout.

The writer is stdlib-only on purpose (see resilient_updates/xlsx_writer.py), so
these tests are the only thing standing between a malformed part and Excel's
"unreadable content" dialog on an analyst's machine. Where openpyxl is
available it is used as an independent reader — never as a runtime dependency.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from xml.dom.minidom import parseString

import pytest

from resilient_updates.report_xlsx import build_xlsx_report
from resilient_updates.xlsx_writer import (
    STYLE_HEADER,
    Sheet,
    column_letter,
    safe_sheet_name,
    write_workbook,
)


# ─────────────────────────────────────────────────────────────────────────────
# xlsx_writer primitives
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("index", "expected"),
    [(1, "A"), (2, "B"), (26, "Z"), (27, "AA"), (28, "AB"), (52, "AZ"), (53, "BA"), (702, "ZZ")],
)
def test_column_letter(index, expected):
    assert column_letter(index) == expected


def test_column_letter_rejects_zero():
    with pytest.raises(ValueError):
        column_letter(0)


def test_safe_sheet_name_strips_forbidden_chars_and_truncates():
    assert safe_sheet_name("a/b:c*d?e[f]g") == "a b c d e f g"
    assert len(safe_sheet_name("x" * 60)) == 31


def test_safe_sheet_name_disambiguates_duplicates():
    used: set[str] = set()
    first = safe_sheet_name("Находки", used)
    second = safe_sheet_name("Находки", used)
    assert first == "Находки"
    assert second != first
    assert len(second) <= 31


def test_write_workbook_produces_parsable_ooxml(tmp_path: Path):
    sheet = Sheet("Лист", widths=[20, 10], freeze_header=True, autofilter=True)
    sheet.add(("Заголовок", STYLE_HEADER), ("Число", STYLE_HEADER))
    sheet.add("значение", 42)

    out = write_workbook(tmp_path / "wb.xlsx", [sheet])

    assert out.is_file()
    with zipfile.ZipFile(out) as zf:
        assert zf.testzip() is None
        names = set(zf.namelist())
        assert {
            "[Content_Types].xml",
            "_rels/.rels",
            "xl/workbook.xml",
            "xl/_rels/workbook.xml.rels",
            "xl/styles.xml",
            "xl/worksheets/sheet1.xml",
        } <= names
        for name in names:
            parseString(zf.read(name))  # raises on malformed XML


def test_write_workbook_escapes_xml_and_drops_control_chars(tmp_path: Path):
    """Scanner output contains both — either one makes Excel call the file corrupt."""
    sheet = Sheet("S")
    sheet.add('<tag> & "quote" \x07bell')

    out = write_workbook(tmp_path / "wb.xlsx", [sheet])

    with zipfile.ZipFile(out) as zf:
        xml = zf.read("xl/worksheets/sheet1.xml").decode("utf-8")
        parseString(xml)
    assert "&lt;tag&gt;" in xml
    assert "&amp;" in xml
    assert "\x07" not in xml


def test_write_workbook_rejects_empty(tmp_path: Path):
    with pytest.raises(ValueError):
        write_workbook(tmp_path / "empty.xlsx", [])


# ─────────────────────────────────────────────────────────────────────────────
# build_xlsx_report layout
# ─────────────────────────────────────────────────────────────────────────────


def _populate(root: Path) -> None:
    (root / "sbom").mkdir(parents=True, exist_ok=True)
    for tool in ("grype", "trivy", "cve-bin-tool"):
        (root / "reports" / tool).mkdir(parents=True, exist_ok=True)
    (root / "sbom" / "syft.json").write_text(
        json.dumps(
            {
                "artifacts": [
                    {
                        "name": "log4j",
                        "version": "1.2.13",
                        "type": "java-archive",
                        "purl": "pkg:maven/log4j/log4j@1.2.13",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (root / "reports" / "grype" / "report.json").write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {
                            "id": "GHSA-critical",
                            "severity": "Critical",
                            "cvss": [{"metrics": {"baseScore": 9.8}}],
                            "fix": {"versions": ["2.0"]},
                        },
                        "artifact": {"name": "log4j", "version": "1.2.13", "type": "java-archive"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (root / "reports" / "trivy" / "report.json").write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Type": "pom",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-medium",
                                "Severity": "MEDIUM",
                                "PkgName": "jackson",
                                "InstalledVersion": "2.17.2",
                                "CVSS": {"nvd": {"V3Score": 5.3}},
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (root / "reports" / "cve-bin-tool" / "report.json").write_text(
        json.dumps(
            [
                {
                    "cve_number": "CVE-high",
                    "severity": "HIGH",
                    "score": 7.5,
                    "vendor": "apache",
                    "product": "log4j",
                    "version": "1.2.13",
                }
            ]
        ),
        encoding="utf-8",
    )
    (root / "summary.json").write_text(
        json.dumps({"input_hashes": {"sha256": "deadbeef", "sha1": "cafe", "md5": "f00d"}}),
        encoding="utf-8",
    )


def test_build_xlsx_report_lays_out_four_sheets(tmp_path: Path):
    root = tmp_path / "artifacts"
    _populate(root)

    out = build_xlsx_report(root, tmp_path / "report.xlsx", display_target="agent.tar.gz", case_id="CYBERSEC-1")

    openpyxl = pytest.importorskip("openpyxl")
    wb = openpyxl.load_workbook(out)
    assert wb.sheetnames == ["Сводка", "Находки", "High-Critical", "SBOM"]

    findings = wb["Находки"]
    assert findings.freeze_panes == "A2"
    assert findings.auto_filter.ref
    # header + one finding per tool
    assert findings.max_row == 4
    # Worst first: Critical, then High, then Medium.
    severities = [findings.cell(row=r, column=3).value for r in range(2, 5)]
    assert severities == ["CRITICAL", "HIGH", "MEDIUM"]

    hc = wb["High-Critical"]
    assert hc.max_row == 3  # header + Critical + High; Medium excluded
    assert "MEDIUM" not in [hc.cell(row=r, column=3).value for r in range(2, hc.max_row + 1)]

    sbom = wb["SBOM"]
    assert [c.value for c in sbom[2]] == [
        "log4j",
        "1.2.13",
        "java-archive",
        "pkg:maven/log4j/log4j@1.2.13",
    ]


def test_build_xlsx_report_summary_carries_hashes_and_counts(tmp_path: Path):
    root = tmp_path / "artifacts"
    _populate(root)

    out = build_xlsx_report(root, tmp_path / "report.xlsx", display_target="agent.tar.gz", case_id="CYBERSEC-1")

    openpyxl = pytest.importorskip("openpyxl")
    summary = openpyxl.load_workbook(out)["Сводка"]
    flat = {
        row[0]: row[1]
        for row in summary.iter_rows(values_only=True)
        if row and row[0] is not None
    }
    assert flat["Файл"] == "agent.tar.gz"
    assert flat["SHA-256 (входной архив)"] == "deadbeef"
    assert flat["Компонентов в SBOM"] == 1
    assert flat["Всего находок"] == 3
    assert flat["CRITICAL"] == 1
    assert flat["HIGH"] == 1
    assert flat["MEDIUM"] == 1
    assert summary.cell(row=1, column=1).value == "CYBERSEC-1: SCA-отчёт"


def test_build_xlsx_report_survives_missing_scanner_outputs(tmp_path: Path):
    """A tool can fail mid-pipeline; the workbook must still be produced."""
    root = tmp_path / "artifacts"
    (root / "sbom").mkdir(parents=True)
    (root / "sbom" / "syft.json").write_text(json.dumps({"artifacts": []}), encoding="utf-8")

    out = build_xlsx_report(root, tmp_path / "report.xlsx", case_id="CYBERSEC-2")

    assert out.is_file()
    openpyxl = pytest.importorskip("openpyxl")
    wb = openpyxl.load_workbook(out)
    assert wb["Находки"].max_row == 1  # header only
