"""Write simple Excel (.xlsx) files with the standard library only.

An .xlsx file is a zip of XML parts. GRC-pal only ever *writes* spreadsheets (it never reads uploaded ones),
so a small writer is enough and adds no dependency. Every cell is written as plain text ("inline string"),
never as a formula, so text that starts with = + - @ cannot run as a formula when the file is opened.

    data = workbook([{"name": "Questions", "rows": [[("ID", HEADER), ("Question", HEADER)], ["Q-001", "..."]],
                      "widths": [10, 80], "freeze_row": 1, "protect": True,
                      "lists": [("C2:C50", ["Yes", "No", "N/A"])]}])
"""
from __future__ import annotations

import io
import re
import zipfile
from xml.sax.saxutils import escape

# Cell styles (indexes into cellXfs below)
PLAIN, HEADER, LOCKED, ANSWER, TITLE, TEXT = 0, 1, 2, 3, 4, 5

_BAD_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")
_SHEET_NAME = re.compile(r"[\[\]:*?/\\]")
MAX_CELL = 32000  # Excel's limit is 32,767 characters per cell

_STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="3"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font>
<font><b/><sz val="14"/><name val="Calibri"/></font></fonts>
<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFE7EEF0"/><bgColor indexed="64"/></patternFill></fill></fills>
<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border>
<border><left style="thin"><color rgb="FFC9D3D7"/></left><right style="thin"><color rgb="FFC9D3D7"/></right>
<top style="thin"><color rgb="FFC9D3D7"/></top><bottom style="thin"><color rgb="FFC9D3D7"/></bottom><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="6">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1" applyProtection="1"><alignment vertical="top" wrapText="1"/><protection locked="0"/></xf>
<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"""


def col_letter(n: int) -> str:
    """1 -> A, 27 -> AA."""
    out = ""
    while n:
        n, r = divmod(n - 1, 26)
        out = chr(65 + r) + out
    return out


def _text(value) -> str:
    text = "" if value is None else str(value)
    return escape(_BAD_XML.sub("", text)[:MAX_CELL])


def _sheet_xml(sheet: dict) -> str:
    rows = sheet.get("rows", [])
    parts = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">']
    freeze = int(sheet.get("freeze_row") or 0)
    if freeze:
        parts.append(f'<sheetViews><sheetView workbookViewId="0"><pane ySplit="{freeze}" topLeftCell="A{freeze + 1}" '
                     'activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>')
    widths = sheet.get("widths") or []
    if widths:
        parts.append("<cols>" + "".join(f'<col min="{i}" max="{i}" width="{float(w):g}" customWidth="1"/>'
                                         for i, w in enumerate(widths, 1)) + "</cols>")
    parts.append("<sheetData>")
    for r, row in enumerate(rows, 1):
        cells = []
        for c, cell in enumerate(row, 1):
            value, style = cell if isinstance(cell, tuple) else (cell, LOCKED)
            ref = f"{col_letter(c)}{r}"
            if value is None or value == "":
                cells.append(f'<c r="{ref}" s="{style}"/>')
            else:
                cells.append(f'<c r="{ref}" s="{style}" t="inlineStr"><is><t xml:space="preserve">{_text(value)}</t></is></c>')
        parts.append(f'<row r="{r}">' + "".join(cells) + "</row>")
    parts.append("</sheetData>")
    if sheet.get("protect"):
        # No password: this stops accidental edits to the questions, it is not a security control.
        parts.append('<sheetProtection sheet="1" objects="1" scenarios="1" formatColumns="0" formatRows="0"/>')
    lists = sheet.get("lists") or []
    if lists:
        parts.append(f'<dataValidations count="{len(lists)}">')
        for sqref, values in lists:
            joined = _text(",".join(values))
            parts.append(f'<dataValidation type="list" allowBlank="1" showErrorMessage="1" sqref="{escape(sqref)}">'
                         f'<formula1>"{joined}"</formula1></dataValidation>')
        parts.append("</dataValidations>")
    parts.append('<pageMargins left="0.5" right="0.5" top="0.6" bottom="0.6" header="0.3" footer="0.3"/></worksheet>')
    return "".join(parts)


def workbook(sheets: list[dict]) -> bytes:
    """Build an .xlsx file from sheets: {name, rows, widths, freeze_row, protect, lists}."""
    if not sheets:
        raise ValueError("a workbook needs at least one sheet")
    names = []
    for i, s in enumerate(sheets, 1):
        name = _SHEET_NAME.sub(" ", str(s.get("name") or f"Sheet{i}")).strip()[:31] or f"Sheet{i}"
        names.append(name)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                   '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
                   + "".join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
                             'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                             for i in range(1, len(sheets) + 1)) + "</Types>")
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                   "</Relationships>")
        z.writestr("xl/workbook.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
                   + "".join(f'<sheet name="{escape(n)}" sheetId="{i}" r:id="rId{i}"/>' for i, n in enumerate(names, 1))
                   + "</sheets></workbook>")
        z.writestr("xl/_rels/workbook.xml.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   + "".join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
                             f'Target="worksheets/sheet{i}.xml"/>' for i in range(1, len(sheets) + 1))
                   + f'<Relationship Id="rId{len(sheets) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
                   "</Relationships>")
        z.writestr("xl/styles.xml", _STYLES)
        for i, s in enumerate(sheets, 1):
            z.writestr(f"xl/worksheets/sheet{i}.xml", _sheet_xml(s))
    return out.getvalue()
