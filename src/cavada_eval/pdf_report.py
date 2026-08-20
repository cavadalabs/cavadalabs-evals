from __future__ import annotations

import html
import importlib
import importlib.util
import os
import tempfile
from functools import partial
from pathlib import Path
from typing import Any

from .protocol import ProtocolError


def require_pdf_support() -> None:
    if importlib.util.find_spec("reportlab") is None:
        raise ProtocolError("professional PDF reporting requires: pip install 'cavadalabs-evals[reports]'")
    try:
        importlib.import_module("reportlab.platypus")
    except (ImportError, OSError) as exc:
        raise ProtocolError("professional PDF reporting is installed but cannot be imported") from exc


def render_pdf(
    path: Path,
    *,
    title: str,
    subtitle: str,
    status: str,
    report_id: str,
    classification: str,
    scope: str,
    kpis: list[tuple[str, str, str]],
    sections: list[dict[str, Any]],
    metadata: dict[str, str],
) -> None:
    require_pdf_support()
    from reportlab.graphics.shapes import Drawing, Rect, String  # type: ignore[import-untyped]
    from reportlab.lib import colors  # type: ignore[import-untyped]
    from reportlab.lib.enums import TA_CENTER, TA_LEFT  # type: ignore[import-untyped]
    from reportlab.lib.pagesizes import A4  # type: ignore[import-untyped]
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # type: ignore[import-untyped]
    from reportlab.lib.units import mm  # type: ignore[import-untyped]
    from reportlab.pdfgen import canvas as pdfcanvas  # type: ignore[import-untyped]
    from reportlab.platypus import (  # type: ignore[import-untyped]
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    navy = colors.HexColor("#101828")
    blue = colors.HexColor("#155EEF")
    blue_light = colors.HexColor("#EFF4FF")
    green = colors.HexColor("#067647")
    green_light = colors.HexColor("#ECFDF3")
    red = colors.HexColor("#B42318")
    red_light = colors.HexColor("#FEF3F2")
    amber = colors.HexColor("#B54708")
    amber_light = colors.HexColor("#FFFAEB")
    gray = colors.HexColor("#475467")
    gray_light = colors.HexColor("#F2F4F7")
    border = colors.HexColor("#D0D5DD")
    white = colors.white

    styles = getSampleStyleSheet()
    body = ParagraphStyle("ReportBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=9, leading=13, textColor=navy, spaceAfter=6)
    small = ParagraphStyle("ReportSmall", parent=body, fontSize=7.5, leading=10, textColor=gray, wordWrap="CJK")
    table_text = ParagraphStyle("ReportTable", parent=body, fontSize=6.8, leading=8.4, spaceAfter=0, wordWrap="CJK")
    table_head = ParagraphStyle("ReportTableHead", parent=table_text, fontName="Helvetica-Bold", textColor=white, alignment=TA_LEFT)
    section_heading = ParagraphStyle("ReportSection", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=14, leading=17, textColor=navy, spaceBefore=12, spaceAfter=8)
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=25, leading=29, textColor=navy, alignment=TA_LEFT, spaceAfter=7)
    subtitle_style = ParagraphStyle("ReportSubtitle", parent=body, fontSize=10.5, leading=15, textColor=gray, spaceAfter=11, wordWrap="CJK")
    eyebrow_style = ParagraphStyle("ReportEyebrow", parent=small, fontName="Helvetica-Bold", fontSize=7, leading=9, textColor=blue, spaceAfter=7)
    kpi_label = ParagraphStyle("KpiLabel", parent=small, fontName="Helvetica-Bold", fontSize=7, leading=9, textColor=gray, alignment=TA_CENTER)
    kpi_value = ParagraphStyle("KpiValue", parent=body, fontName="Helvetica-Bold", fontSize=15, leading=18, textColor=navy, alignment=TA_CENTER, spaceAfter=1)
    kpi_detail = ParagraphStyle("KpiDetail", parent=small, fontSize=6.5, leading=8, alignment=TA_CENTER)
    warning = ParagraphStyle("ReportWarning", parent=body, fontName="Helvetica-Bold", textColor=amber, leftIndent=5, rightIndent=5, spaceAfter=0)

    def paragraph(value: object, style: Any = body) -> Any:
        return Paragraph(html.escape(str(value)).replace("\n", "<br/>"), style)

    def status_palette(value: str) -> tuple[Any, Any]:
        folded = value.casefold()
        if any(word in folded for word in ("fail", "error", "cancel", "invalid")):
            return red, red_light
        if any(word in folded for word in ("pass", "complete", "valid")):
            return green, green_light
        if "comparison" in folded:
            return blue, blue_light
        return amber, amber_light

    def value_table(rows: list[tuple[object, object]]) -> Any:
        data = [[paragraph(label, small), paragraph(value, table_text)] for label, value in rows]
        table = Table(data, colWidths=[42 * mm, 137 * mm], hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BACKGROUND", (0, 0), (0, -1), gray_light),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.4, border),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        return table

    def data_table(spec: dict[str, Any]) -> Any:
        headers = [paragraph(value, table_head) for value in spec["headers"]]
        rows = [[paragraph(value, table_text) for value in row] for row in spec.get("rows", [])]
        widths = spec.get("widths")
        col_widths = [float(value) * mm for value in widths] if widths else None
        table = Table([headers, *rows], colWidths=col_widths, repeatRows=1, hAlign="LEFT", splitByRow=True)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), navy),
                    ("TEXTCOLOR", (0, 0), (-1, 0), white),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.35, border),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, gray_light]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        return table

    def bars(spec: dict[str, Any]) -> Any:
        rows = [(str(label), float(value)) for label, value in spec.get("rows", [])]
        unit = str(spec.get("unit", ""))
        maximum = max((value for _, value in rows), default=0.0) or 1.0
        width = 179 * mm
        row_height = 8 * mm
        height = 8 * mm + row_height * max(1, len(rows))
        drawing = Drawing(width, height)
        bar_x = 54 * mm
        bar_width = 96 * mm
        for index, (label, value) in enumerate(rows):
            y = height - (index + 1) * row_height + 1.5 * mm
            drawing.add(String(0, y + 1.2 * mm, label[:36], fontName="Helvetica", fontSize=7, fillColor=navy))
            drawing.add(Rect(bar_x, y, bar_width, 4.5 * mm, fillColor=gray_light, strokeColor=None))
            drawing.add(Rect(bar_x, y, bar_width * max(0.0, value) / maximum, 4.5 * mm, fillColor=blue, strokeColor=None))
            drawing.add(String(153 * mm, y + 1.2 * mm, f"{value:,.2f} {unit}".strip(), fontName="Helvetica-Bold", fontSize=7, fillColor=navy))
        return drawing

    status_color, status_background = status_palette(status)
    story: list[Any] = [
        paragraph(f"CAVADALABS / {classification.upper()} EVIDENCE", eyebrow_style),
        paragraph(title, title_style),
        paragraph(subtitle, subtitle_style),
    ]
    badge = Table([[paragraph(status.upper(), ParagraphStyle("Badge", parent=small, fontName="Helvetica-Bold", textColor=status_color, alignment=TA_CENTER))]], colWidths=[52 * mm])
    badge.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), status_background), ("BOX", (0, 0), (-1, -1), 0.8, status_color), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    story.extend([badge, Spacer(1, 8), Table([[paragraph(f"SCOPE  {scope}", warning)]], colWidths=[179 * mm], style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), amber_light), ("BOX", (0, 0), (-1, -1), 0.6, amber), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)])), Spacer(1, 12)])

    for index in range(0, len(kpis), 3):
        chunk = kpis[index : index + 3]
        cells: list[list[Any]] = []
        for label, value, detail in chunk:
            cells.append([paragraph(label.upper(), kpi_label), paragraph(value, kpi_value), paragraph(detail, kpi_detail)])
        while len(cells) < 3:
            cells.append([])
        table = Table([cells], colWidths=[59.6 * mm] * 3)
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), blue_light), ("BOX", (0, 0), (-1, -1), 0.5, border), ("INNERGRID", (0, 0), (-1, -1), 0.5, white), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
        story.extend([table, Spacer(1, 5)])

    for section in sections:
        if section.get("page_break"):
            story.append(PageBreak())
        elements: list[Any] = [paragraph(section["title"], section_heading)]
        for value in section.get("paragraphs", []):
            elements.append(paragraph(value))
        if section.get("warning"):
            box = Table([[paragraph(section["warning"], warning)]], colWidths=[179 * mm])
            box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), amber_light), ("BOX", (0, 0), (-1, -1), 0.6, amber), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
            elements.extend([box, Spacer(1, 6)])
        if section.get("key_values"):
            elements.extend([value_table(section["key_values"]), Spacer(1, 7)])
        if section.get("table"):
            elements.extend([data_table(section["table"]), Spacer(1, 7)])
        for chart in section.get("charts", []):
            chart_title = paragraph(chart["title"], ParagraphStyle("ChartTitle", parent=body, fontName="Helvetica-Bold", textColor=navy, spaceBefore=5, spaceAfter=3))
            elements.extend([KeepTogether([chart_title, bars(chart)]), Spacer(1, 6)])
        story.append(KeepTogether(elements) if section.get("keep_together", False) else elements[0])
        if not section.get("keep_together", False):
            story.extend(elements[1:])

    metadata_items = list(metadata.items())
    metadata_rows: list[list[Any]] = []
    for index in range(0, len(metadata_items), 2):
        left = metadata_items[index]
        right = metadata_items[index + 1] if index + 1 < len(metadata_items) else ("", "")
        metadata_rows.append([paragraph(left[0], small), paragraph(left[1], table_text), paragraph(right[0], small), paragraph(right[1], table_text)])
    metadata_table = Table(metadata_rows, colWidths=[30 * mm, 59 * mm, 30 * mm, 60 * mm], hAlign="LEFT")
    metadata_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (0, -1), gray_light),
                ("BACKGROUND", (2, 0), (2, -1), gray_light),
                ("GRID", (0, 0), (-1, -1), 0.35, border),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.extend([Spacer(1, 10), KeepTogether([paragraph("Evidence metadata", section_heading), metadata_table])])

    def page(canvas: Any, document: Any) -> None:
        canvas.saveState()
        canvas.setTitle(title)
        canvas.setAuthor("CavadaLabs")
        canvas.setSubject(scope)
        canvas.setCreator("cavadalabs-evals")
        canvas.setFillColor(navy)
        canvas.rect(0, A4[1] - 12 * mm, A4[0], 12 * mm, fill=True, stroke=False)
        canvas.setFillColor(white)
        canvas.setFont("Helvetica-Bold", 7)
        canvas.drawString(15 * mm, A4[1] - 7.7 * mm, "CAVADALABS EVALUATION PROTOCOL")
        canvas.drawRightString(A4[0] - 15 * mm, A4[1] - 7.7 * mm, classification.upper())
        canvas.setStrokeColor(border)
        canvas.line(15 * mm, 14 * mm, A4[0] - 15 * mm, 14 * mm)
        canvas.setFillColor(gray)
        canvas.setFont("Helvetica", 6.5)
        canvas.drawString(15 * mm, 9 * mm, report_id[:88])
        canvas.drawRightString(A4[0] - 15 * mm, 9 * mm, f"Page {document.page}")
        canvas.restoreState()

    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.stem}-", suffix=".pdf", dir=path.parent)
    os.close(fd)
    try:
        document = SimpleDocTemplate(
            temporary_name,
            pagesize=A4,
            rightMargin=15 * mm,
            leftMargin=15 * mm,
            topMargin=20 * mm,
            bottomMargin=19 * mm,
            title=title,
            author="CavadaLabs",
            subject=scope,
            pageCompression=1,
            invariant=1,
        )
        document.build(story, onFirstPage=page, onLaterPages=page, canvasmaker=partial(pdfcanvas.Canvas, invariant=1))
        os.replace(temporary_name, path)
        os.chmod(path, 0o600)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()
