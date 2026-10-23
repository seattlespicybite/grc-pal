"""Write and read simple Excel (.xlsx) files with the standard library only.

An .xlsx file is a zip of XML parts. A small writer is enough and adds no dependency. Every cell is written as
plain text ("inline string"), never as a formula, so text that starts with = + - @ cannot run as a formula when
the file is opened.

    data = workbook([{"name": "Questions", "rows": [[("ID", HEADER), ("Question", HEADER)], ["Q-001", "..."]],
                      "widths": [10, 80], "freeze_row": 1, "protect": True, "hidden": False,
                      "lists": [("C2:C50", ["Yes", "No", "N/A"])]}])

`read_values` reads cell *values* back from an uploaded workbook (the control matrix import). Uploaded files
are untrusted, so it is deliberately narrow: size and zip limits (zip bombs), no DOCTYPE or entities (XML
bombs), only workbook, shared strings and worksheet parts are parsed, formulas are refused, macros, links and
everything else in the file are never opened.
"""
from __future__ import annotations

import io
import re
import zipfile
import xml.etree.ElementTree as ET
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
                   + "".join(f'<sheet name="{escape(n)}" sheetId="{i}"'
                             + (' state="hidden"' if sheets[i - 1].get("hidden") else "") + f' r:id="rId{i}"/>'
                             for i, n in enumerate(names, 1))
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


# ------------------------------------------------------------------------------------------------ reading
_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
       "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
       "pr": "http://schemas.openxmlformats.org/package/2006/relationships"}
_REF = re.compile(r"^([A-Z]{1,3})(\d+)$")
MAX_READ_BYTES = 5 * 1024 * 1024        # the uploaded file
MAX_PART_BYTES = 20 * 1024 * 1024       # one XML part, unpacked
MAX_TOTAL_BYTES = 60 * 1024 * 1024      # everything we unpack
MAX_ENTRIES = 300
MAX_ROWS = 5000
MAX_COLS = 80


class ReadError(ValueError):
    """The file is not a workbook we are willing to read. The message is safe to show the person."""


def _col_number(letters: str) -> int:
    n = 0
    for ch in letters:
        n = n * 26 + ord(ch) - 64
    return n


def _xml(z: zipfile.ZipFile, name: str, budget: list[int]):
    try:
        info = z.getinfo(name)
    except KeyError:
        return None
    if info.file_size > MAX_PART_BYTES or info.file_size > budget[0]:
        raise ReadError("The file is too large once unpacked. Export a fresh matrix and edit that.")
    with z.open(info) as fh:
        raw = fh.read(MAX_PART_BYTES + 1)
    if len(raw) > MAX_PART_BYTES:  # the size in the zip directory lied
        raise ReadError("The file is too large once unpacked.")
    budget[0] -= len(raw)
    head = raw[:4096].upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in raw.upper():
        raise ReadError("The file contains XML features GRC-pal does not accept (DOCTYPE or entities).")
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ReadError("The file is damaged or not an Excel workbook.") from exc


def read_values(data: bytes) -> dict[str, list[list[str]]]:
    """Cell values of every sheet, by sheet name: {name: [[row 1 cells], [row 2 cells], ...]} as text.
    Raises ReadError for anything unexpected. Never evaluates formulas: a formula cell is an error."""
    if not data:
        raise ReadError("The file is empty.")
    if len(data) > MAX_READ_BYTES:
        raise ReadError(f"The file is larger than {MAX_READ_BYTES // (1024 * 1024)} MB.")
    if not data.startswith(b"PK"):
        raise ReadError("This is not an .xlsx workbook. Save it as Excel Workbook (.xlsx), not .xls or .csv.")
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        infos = z.infolist()
    except zipfile.BadZipFile as exc:
        raise ReadError("The file is damaged or not an Excel workbook.") from exc
    if len(infos) > MAX_ENTRIES:
        raise ReadError("The workbook has too many parts.")
    if sum(i.file_size for i in infos) > MAX_TOTAL_BYTES:
        raise ReadError("The file is too large once unpacked.")
    if any(i.flag_bits & 0x1 for i in infos):
        raise ReadError("The workbook is password protected. Remove the password and upload it again.")
    budget = [MAX_TOTAL_BYTES]
    book = _xml(z, "xl/workbook.xml", budget)
    rels = _xml(z, "xl/_rels/workbook.xml.rels", budget)
    if book is None or rels is None:
        raise ReadError("The file is not an Excel workbook.")
    targets = {r.get("Id"): r.get("Target", "") for r in rels.findall("pr:Relationship", _NS)}
    shared: list[str] = []
    sst = _xml(z, "xl/sharedStrings.xml", budget)
    if sst is not None:
        for si in sst.findall("m:si", _NS):
            # rich text has several <r><t> runs; phonetic hints (<rPh>) are not part of the value
            parts = si.findall("m:t", _NS) + si.findall("m:r/m:t", _NS)
            shared.append("".join(t.text or "" for t in parts))
    out: dict[str, list[list[str]]] = {}
    for sheet in book.findall("m:sheets/m:sheet", _NS):
        target = targets.get(sheet.get(f"{{{_NS['r']}}}id"), "")
        target = target.lstrip("/")
        part = target if target.startswith("xl/") else "xl/" + target
        if ".." in part or not part.startswith("xl/worksheets/") or not part.endswith(".xml"):
            continue  # chartsheets, macro sheets and anything odd are never opened
        root = _xml(z, part, budget)
        if root is None:
            continue
        rows: list[list[str]] = []
        for r_i, row in enumerate(root.findall("m:sheetData/m:row", _NS), 1):
            r_num = int(row.get("r") or r_i)
            if r_num > MAX_ROWS:
                raise ReadError(f"The sheet '{sheet.get('name')}' has more than {MAX_ROWS} rows.")
            cells: dict[int, str] = {}
            for c_i, c in enumerate(row.findall("m:c", _NS), 1):
                m = _REF.match(c.get("r") or "")
                col = _col_number(m.group(1)) if m else c_i
                if col > MAX_COLS:
                    continue
                if c.find("m:f", _NS) is not None:
                    raise ReadError(f"Cell {col_letter(col)}{r_num} on '{sheet.get('name')}' contains a formula. "
                                    "Formulas are not accepted; type the value instead.")
                kind = c.get("t", "n")
                if kind == "inlineStr":
                    node = c.find("m:is", _NS)
                    value = "".join(t.text or "" for t in node.iter(f"{{{_NS['m']}}}t")) if node is not None else ""
                else:
                    v = c.find("m:v", _NS)
                    value = v.text or "" if v is not None else ""
                    if kind == "s":
                        try:
                            value = shared[int(value)]
                        except (ValueError, IndexError) as exc:
                            raise ReadError("The file is damaged (bad shared text reference).") from exc
                    elif kind == "b":
                        value = "TRUE" if value == "1" else "FALSE"
                    elif kind == "n" and value.endswith(".0"):
                        value = value[:-2]
                cells[col] = value[:MAX_CELL]
            if cells:
                while len(rows) < r_num - 1:
                    rows.append([])
                rows.append([cells.get(i, "") for i in range(1, max(cells) + 1)])
        out[str(sheet.get("name") or "")] = rows
    return out
