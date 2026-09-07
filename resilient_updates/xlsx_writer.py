"""Minimal OOXML (.xlsx) writer — standard library only.

Why not openpyxl/xlsxwriter: this stack is built to run offline and in air-gapped
installations (see docs/airgap.md).  The report stage runs on the *host* python,
not inside a container, so any third-party import there becomes a deployment
prerequisite that fails closed on a machine without an index — exactly the
situation the rest of the project is designed to survive.  An .xlsx is a zip of
XML parts, and the subset needed for a readable report (several sheets, a bold
frozen header, autofilter, column widths, coloured severity cells) is small
enough to own outright.

Deliberately NOT implemented: formulas, merged cells, charts, images, shared
strings.  Values are written as inline strings or numbers.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

# Excel hard limits worth guarding: a sheet name is <= 31 chars and cannot
# contain []:*?/\, and the grid stops at 1,048,576 rows.
_SHEET_NAME_FORBIDDEN = set(r"[]:*?/\'")
_MAX_SHEET_NAME = 31
_MAX_ROWS = 1_048_576

# Style indices baked into _STYLES_XML below.
STYLE_DEFAULT = 0
STYLE_HEADER = 1
STYLE_TITLE = 2
STYLE_CRITICAL = 3
STYLE_HIGH = 4
STYLE_MEDIUM = 5
STYLE_LOW = 6
STYLE_MUTED = 7

SEVERITY_STYLE = {
    "CRITICAL": STYLE_CRITICAL,
    "HIGH": STYLE_HIGH,
    "MEDIUM": STYLE_MEDIUM,
    "LOW": STYLE_LOW,
    "NEGLIGIBLE": STYLE_MUTED,
    "UNKNOWN": STYLE_MUTED,
}

_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
{sheet_overrides}
</Types>"""

_ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

# Fonts: 0 default, 1 bold header (white), 2 bold title.
# Fills:  0/1 reserved by spec, 2 header slate, 3..6 severity tints.
_STYLES_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="4">
<font><sz val="11"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
<font><b/><sz val="12"/><name val="Calibri"/></font>
<font><sz val="11"/><color rgb="FF6B7280"/><name val="Calibri"/></font>
</fonts>
<fills count="7">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF334155"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFEE2E2"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFFEDD5"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFEF9C3"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFDCFCE7"/><bgColor indexed="64"/></patternFill></fill>
</fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="8">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment vertical="center"/></xf>
<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="0" fillId="3" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="5" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="6" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"""


def column_letter(index: int) -> str:
    """1 -> A, 26 -> Z, 27 -> AA."""
    if index < 1:
        raise ValueError(f"column index must be >= 1, got {index}")
    letters = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def safe_sheet_name(name: str, used: set[str] | None = None) -> str:
    """Excel refuses []:*?/\\ and names longer than 31 chars; it also refuses
    duplicates, so disambiguate against ``used`` when given."""
    cleaned = "".join(" " if ch in _SHEET_NAME_FORBIDDEN else ch for ch in name).strip()
    cleaned = cleaned[:_MAX_SHEET_NAME] or "Sheet"
    if used is None:
        return cleaned
    candidate, suffix = cleaned, 2
    while candidate.casefold() in {u.casefold() for u in used}:
        tail = f"_{suffix}"
        candidate = cleaned[: _MAX_SHEET_NAME - len(tail)] + tail
        suffix += 1
    used.add(candidate)
    return candidate


def _cell_xml(ref: str, value: Any, style: int) -> str:
    style_attr = f' s="{style}"' if style else ""
    if value is None or value == "":
        return f'<c r="{ref}"{style_attr}/>'
    if isinstance(value, bool):  # bool before int: bool IS an int in Python
        value = "да" if value else "нет"
    elif isinstance(value, (int, float)):
        return f'<c r="{ref}"{style_attr}><v>{value}</v></c>'
    text = escape(str(value))
    # Control characters other than tab/newline/CR are illegal in XML 1.0 and
    # make Excel declare the file corrupt — scanner output does contain them.
    text = "".join(ch for ch in text if ch in "\t\n\r" or ord(ch) >= 0x20)
    return f'<c r="{ref}"{style_attr} t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>'


@dataclass
class Sheet:
    """One worksheet: a title, optional column widths, and rows of cells.

    A row is a list of either raw values or ``(value, style)`` pairs.
    """

    name: str
    rows: list[list[Any]] = field(default_factory=list)
    widths: list[int] = field(default_factory=list)
    freeze_header: bool = False
    autofilter: bool = False

    def add(self, *values: Any) -> None:
        self.rows.append(list(values))

    def _to_xml(self) -> str:
        parts = [
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
        ]
        if self.freeze_header:
            parts.append(
                '<sheetViews><sheetView workbookViewId="0">'
                '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
                "</sheetView></sheetViews>"
            )
        if self.widths:
            cols = "".join(
                f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>'
                for i, w in enumerate(self.widths, start=1)
            )
            parts.append(f"<cols>{cols}</cols>")

        max_col = 0
        body = []
        for row_index, row in enumerate(self.rows[:_MAX_ROWS], start=1):
            cells = []
            for col_index, item in enumerate(row, start=1):
                value, style = item if isinstance(item, tuple) else (item, STYLE_DEFAULT)
                cells.append(_cell_xml(f"{column_letter(col_index)}{row_index}", value, style))
            max_col = max(max_col, len(row))
            body.append(f'<row r="{row_index}">{"".join(cells)}</row>')
        parts.append(f"<sheetData>{''.join(body)}</sheetData>")

        if self.autofilter and self.rows and max_col:
            last = f"{column_letter(max_col)}{min(len(self.rows), _MAX_ROWS)}"
            parts.append(f'<autoFilter ref="A1:{last}"/>')
        parts.append("</worksheet>")
        return "".join(parts)


def write_workbook(path: str | Path, sheets: list[Sheet]) -> Path:
    """Write *sheets* to an .xlsx at *path*. Returns the path written."""
    if not sheets:
        raise ValueError("a workbook needs at least one sheet")

    used: set[str] = set()
    for sheet in sheets:
        sheet.name = safe_sheet_name(sheet.name, used)

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    overrides = "\n".join(
        f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for i in range(1, len(sheets) + 1)
    )
    workbook_sheets = "".join(
        f'<sheet name="{escape(s.name)}" sheetId="{i}" r:id="rId{i}"/>' for i, s in enumerate(sheets, start=1)
    )
    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{workbook_sheets}</sheets></workbook>"
    )
    rel_entries = "".join(
        f'<Relationship Id="rId{i}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{i}.xml"/>'
        for i in range(1, len(sheets) + 1)
    )
    styles_rid = len(sheets) + 1
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f"{rel_entries}"
        f'<Relationship Id="rId{styles_rid}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
        "</Relationships>"
    )

    # Deterministic timestamps keep reruns byte-comparable for evidence diffing.
    stamp = (2026, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:

        def write(name: str, data: str) -> None:
            info = zipfile.ZipInfo(name, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)

        write("[Content_Types].xml", _CONTENT_TYPES.format(sheet_overrides=overrides))
        write("_rels/.rels", _ROOT_RELS)
        write("xl/workbook.xml", workbook_xml)
        write("xl/_rels/workbook.xml.rels", workbook_rels)
        write("xl/styles.xml", _STYLES_XML)
        for i, sheet in enumerate(sheets, start=1):
            write(f"xl/worksheets/sheet{i}.xml", sheet._to_xml())
    return out


def utc_stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


__all__ = [
    "SEVERITY_STYLE",
    "STYLE_DEFAULT",
    "STYLE_HEADER",
    "STYLE_MUTED",
    "STYLE_TITLE",
    "Sheet",
    "column_letter",
    "safe_sheet_name",
    "utc_stamp",
    "write_workbook",
]
