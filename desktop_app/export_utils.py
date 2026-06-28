import csv
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

from security_utils import SEVERITY_COLORS, SEVERITY_ORDER
from version import APP_VERSION, APP_AUTHOR

CSV_FIELDS = [
    "severity", "cve", "title", "description", "recommendation",
    "category", "module", "affected_url", "cvss_score", "owasp_category",
]


def export_csv(result: dict, path: str) -> None:
    findings = sorted(
        result.get("findings", []),
        key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)


def export_pdf(result: dict, url: str, path: str) -> None:
    findings = sorted(
        result.get("findings", []),
        key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )
    styles = getSampleStyleSheet()
    cell_style = ParagraphStyle("cell", parent=styles["BodyText"], fontSize=8, leading=10)

    doc = SimpleDocTemplate(path, pagesize=A4, topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    story = [
        Paragraph("ThreatLens — Relatório de Scan", styles["Title"]),
        Paragraph(f"Alvo: {url}", styles["Normal"]),
        Paragraph(f"Risk score: {result.get('risk_score')} | Duração: {result.get('duration_ms')} ms | "
                  f"Achados: {len(findings)}", styles["Normal"]),
        Spacer(1, 0.5 * cm),
    ]

    table_data = [["Severidade", "CVE", "Título", "Descrição", "Recomendação"]]
    for finding in findings:
        table_data.append([
            finding.get("severity", "").upper(),
            finding.get("cve", "") or "—",
            Paragraph(finding.get("title", ""), cell_style),
            Paragraph(finding.get("description", ""), cell_style),
            Paragraph(finding.get("recommendation", "") or "—", cell_style),
        ])

    table = Table(table_data, colWidths=[2 * cm, 2.2 * cm, 3.8 * cm, 5.7 * cm, 5 * cm], repeatRows=1)
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
    ]
    for row, finding in enumerate(findings, start=1):
        color = colors.HexColor(SEVERITY_COLORS.get(finding.get("severity", "informational"), "#9ca3af"))
        style_commands.append(("TEXTCOLOR", (0, row), (0, row), color))
    table.setStyle(TableStyle(style_commands))

    story.append(table)
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(f"ThreatLens v{APP_VERSION} — desenvolvido por {APP_AUTHOR}", styles["Normal"]))
    doc.build(story)
