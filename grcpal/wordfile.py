"""Write simple Word (.docx) files with the standard library only.

Like xlsx.py: a .docx is a zip of XML parts, and GRC-pal only needs titles, headings, paragraphs, tables and
page breaks, so a small writer avoids a runtime dependency (python-docx is used only by the developer tool
that builds the policy templates). All text is XML-escaped; nothing in the file can run code.

    doc = Document()
    doc.title("Control matrix"); doc.heading("Controls", 1); doc.para("Text")
    doc.table(["A", "B"], [["1", "2"]], widths=(30, 70)); data = doc.save()
"""
from __future__ import annotations

import io
import re
import zipfile
from xml.sax.saxutils import escape

_BAD_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")
_W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
TEXT_WIDTH = 9638  # A4/Letter text width with 2 cm margins, in twentieths of a point

_STYLES = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles {_W}>
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="21"/></w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:qFormat/>
<w:pPr><w:spacing w:after="200"/></w:pPr><w:rPr><w:b/><w:color w:val="1F3A44"/><w:sz w:val="44"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>
<w:pPr><w:keepNext/><w:spacing w:before="280" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:color w:val="1F3A44"/><w:sz w:val="32"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>
<w:pPr><w:keepNext/><w:spacing w:before="220" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:color w:val="1F3A44"/><w:sz w:val="25"/></w:rPr></w:style>
<w:style w:type="table" w:styleId="Grid"><w:name w:val="Grid"/><w:tblPr><w:tblBorders>
<w:top w:val="single" w:sz="4" w:color="C9D3D7"/><w:left w:val="single" w:sz="4" w:color="C9D3D7"/>
<w:bottom w:val="single" w:sz="4" w:color="C9D3D7"/><w:right w:val="single" w:sz="4" w:color="C9D3D7"/>
<w:insideH w:val="single" w:sz="4" w:color="C9D3D7"/><w:insideV w:val="single" w:sz="4" w:color="C9D3D7"/></w:tblBorders>
<w:tblCellMar><w:top w:w="40" w:type="dxa"/><w:left w:w="80" w:type="dxa"/><w:bottom w:w="40" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
</w:styles>"""


def _runs(text: str, bold: bool = False) -> str:
    rpr = "<w:rPr><w:b/></w:rPr>" if bold else ""
    lines = _BAD_XML.sub("", "" if text is None else str(text)).split("\n")
    out = []
    for i, line in enumerate(lines):
        if i:
            out.append(f"<w:r>{rpr}<w:br/></w:r>")
        out.append(f'<w:r>{rpr}<w:t xml:space="preserve">{escape(line)}</w:t></w:r>')
    return "".join(out)


class Document:
    def __init__(self) -> None:
        self._body: list[str] = []

    def _p(self, text: str, style: str = "", bold: bool = False) -> None:
        ppr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
        self._body.append(f"<w:p>{ppr}{_runs(text, bold)}</w:p>")

    def title(self, text: str) -> None:
        self._p(text, "Title")

    def heading(self, text: str, level: int = 1) -> None:
        self._p(text, f"Heading{1 if level <= 1 else 2}")

    def para(self, text: str) -> None:
        self._p(text)

    def page_break(self) -> None:
        self._body.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')

    def table(self, header: list[str] | None, rows: list[list[str]], widths: tuple = ()) -> None:
        ncols = len(header or (rows[0] if rows else [""]))
        pct = list(widths) if len(widths) == ncols else [100 / ncols] * ncols
        tw = [int(TEXT_WIDTH * p / 100) for p in pct]
        parts = ['<w:tbl><w:tblPr><w:tblStyle w:val="Grid"/><w:tblW w:w="5000" w:type="pct"/>'
                 '<w:tblLayout w:type="fixed"/></w:tblPr><w:tblGrid>'
                 + "".join(f'<w:gridCol w:w="{w}"/>' for w in tw) + "</w:tblGrid>"]

        def row(cells, head=False):
            trpr = "<w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>" if head else "<w:trPr><w:cantSplit/></w:trPr>"
            shade = '<w:shd w:val="clear" w:color="auto" w:fill="E7EEF0"/>' if head else ""
            out = [f"<w:tr>{trpr}"]
            for i in range(ncols):
                value = cells[i] if i < len(cells) else ""
                bold = head or (header is None and i == 0)  # a key/value table: keys in bold
                fill = shade or ('<w:shd w:val="clear" w:color="auto" w:fill="F4F7F8"/>' if header is None and i == 0 else "")
                out.append(f'<w:tc><w:tcPr><w:tcW w:w="{tw[i]}" w:type="dxa"/>{fill}</w:tcPr>'
                           f'<w:p><w:pPr><w:spacing w:after="0"/></w:pPr>{_runs(value, bold)}</w:p></w:tc>')
            out.append("</w:tr>")
            return "".join(out)

        if header:
            parts.append(row(header, True))
        parts += [row(r) for r in rows]
        parts.append("</w:tbl>")
        self._body.append("".join(parts))
        self._body.append('<w:p><w:pPr><w:spacing w:after="60"/></w:pPr></w:p>')  # Word needs a paragraph after a table

    def save(self) -> bytes:
        body = "".join(self._body) + (
            '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
            '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567" w:gutter="0"/>'
            "</w:sectPr>")
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml",
                       '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                       '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                       '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                       '<Default Extension="xml" ContentType="application/xml"/>'
                       '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                       '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
                       "</Types>")
            z.writestr("_rels/.rels",
                       '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                       '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                       '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
                       "</Relationships>")
            z.writestr("word/_rels/document.xml.rels",
                       '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                       '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                       '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
                       "</Relationships>")
            z.writestr("word/styles.xml", _STYLES)
            z.writestr("word/document.xml",
                       f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {_W}><w:body>{body}</w:body></w:document>')
        return out.getvalue()
