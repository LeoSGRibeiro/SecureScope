import csv
from datetime import datetime, timedelta
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, HRFlowable

from security_utils import SEVERITY_COLORS, SEVERITY_ORDER
from version import APP_VERSION, APP_AUTHOR


def _esc(text: str) -> str:
    """Escape HTML special chars so ReportLab's paraparser doesn't choke on & < > in raw text."""
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

CSV_FIELDS = [
    "num_ameaca", "scan_datetime", "severity", "cve", "title", "description", "recommendation",
    "category", "module", "affected_url", "cvss_score", "owasp_category",
    "data_conclusao", "status", "observacao",
]

_CSV_DEADLINE_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}


def export_csv(result: dict, path: str, scan_time: datetime | None = None) -> None:
    scan_time_ref = scan_time or datetime.now()
    scan_time_str = scan_time_ref.strftime("%d/%m/%Y %H:%M:%S")
    findings = sorted(
        result.get("findings", []),
        key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for idx, finding in enumerate(findings, 1):
            sev = finding.get("severity", "")
            days = _CSV_DEADLINE_DAYS.get(sev)
            deadline = (scan_time_ref + timedelta(days=days)).strftime("%d/%m/%Y") if days else ""
            writer.writerow({
                **finding,
                "num_ameaca": idx,
                "scan_datetime": scan_time_str,
                "data_conclusao": deadline,
                "status": "",
                "observacao": "",
            })


INFRA_PROFILE_TITLE = "Infrastructure & Technology Profile"


def export_pdf(result: dict, url: str, path: str, scan_time: datetime | None = None) -> None:
    scan_time_str = (scan_time or datetime.now()).strftime("%d/%m/%Y %H:%M:%S")
    all_findings = result.get("findings", [])
    infra_profile = next((f for f in all_findings if f.get("title") == INFRA_PROFILE_TITLE), None)
    findings = sorted(
        [f for f in all_findings if f.get("title") != INFRA_PROFILE_TITLE],
        key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )
    styles = getSampleStyleSheet()
    cell_style = ParagraphStyle("cell", parent=styles["BodyText"], fontSize=8, leading=10)

    doc = SimpleDocTemplate(path, pagesize=A4, topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    story = [
        Paragraph("ThreatLens — Relatório de Scan", styles["Title"]),
        Paragraph(f"Alvo: {url}", styles["Normal"]),
        Paragraph(f"Data/Hora do Scan: {scan_time_str}", styles["Normal"]),
        Paragraph(f"Risk score: {result.get('risk_score')} | Duração: {result.get('duration_ms')} ms | "
                  f"Achados: {len(findings)}", styles["Normal"]),
    ]

    if infra_profile:
        profile_style = ParagraphStyle("profile", parent=styles["Normal"], spaceBefore=6)
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("<b>Perfil de Infraestrutura e Tecnologia</b>", styles["Heading3"]))
        story.append(Paragraph(_esc(infra_profile.get("description", "")), profile_style))

    story.append(Spacer(1, 0.5 * cm))

    table_data = [["#", "Severidade", "CVE", "Título", "Descrição", "Recomendação"]]
    for idx, finding in enumerate(findings, 1):
        severity = finding.get("severity", "informational")
        severity_style = ParagraphStyle(
            "severity_cell", parent=cell_style, fontSize=8, leading=10,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor(SEVERITY_COLORS.get(severity, "#9ca3af")),
        )
        table_data.append([
            Paragraph(str(idx), cell_style),
            Paragraph(severity.upper(), severity_style),
            Paragraph(_esc(finding.get("cve", "") or "—"), cell_style),
            Paragraph(_esc(finding.get("title", "")), cell_style),
            Paragraph(_esc(finding.get("description", "")), cell_style),
            Paragraph(_esc(finding.get("recommendation", "") or "—"), cell_style),
        ])

    table = Table(table_data, colWidths=[0.7 * cm, 2.2 * cm, 2.1 * cm, 3.4 * cm, 5.3 * cm, 4.6 * cm], repeatRows=1)
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
    ]
    table.setStyle(TableStyle(style_commands))

    story.append(table)
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(f"ThreatLens v{APP_VERSION} — desenvolvido por {APP_AUTHOR}", styles["Normal"]))
    doc.build(story)


# ---------------------------------------------------------------------------
# Relatório Gerencial
# ---------------------------------------------------------------------------

_SEVERITY_PT = {
    "critical": "Crítico",
    "high": "Alto",
    "medium": "Médio",
    "low": "Baixo",
    "informational": "Informativo",
}

_PRIORITY_PT = {
    "critical": "Imediata",
    "high": "Alta",
    "medium": "Média",
    "low": "Baixa",
}

_DEADLINE_DAYS = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
}


def _g_severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "informational")
        if sev in counts:
            counts[sev] += 1
    return counts


def _g_action_priority(severity: str) -> str:
    return _PRIORITY_PT.get(severity, "—")


def _g_action_deadline(severity: str, scan_time: datetime) -> str:
    days = _DEADLINE_DAYS.get(severity)
    if days is None:
        return "—"
    return (scan_time + timedelta(days=days)).strftime("%d/%m/%Y")


def _g_risk_label(score: float) -> str:
    if score >= 80:
        return "Baixo risco"
    if score >= 60:
        return "Risco moderado"
    if score >= 40:
        return "Risco elevado"
    return "Risco crítico"


def _g_executive_paragraph(findings: list[dict], url: str) -> str:
    counts = _g_severity_counts(findings)
    total = len(findings)
    critical_high = counts.get("critical", 0) + counts.get("high", 0)
    from urllib.parse import urlparse
    domain = urlparse(url).netloc or url
    if total == 0:
        return (
            f"A análise de segurança do domínio <b>{domain}</b> não identificou achados registráveis. "
            "O ambiente apresenta postura de segurança satisfatória com base nos módulos executados."
        )
    urgency = ""
    if critical_high > 0:
        urgency = (
            f" Destes, <b>{critical_high}</b> são de severidade crítica ou alta e requerem atenção imediata."
        )
    return (
        f"A análise de segurança do domínio <b>{domain}</b> identificou <b>{total}</b> achado(s).{urgency} "
        "Recomenda-se seguir o plano de ação detalhado neste relatório, priorizando os itens de maior severidade."
    )


def _gerencial_footer(canvas, doc):
    canvas.saveState()
    styles = getSampleStyleSheet()
    footer_style = ParagraphStyle("footer", parent=styles["Normal"], fontSize=7, textColor=colors.grey)
    page_width, _ = A4
    text = (
        f"ThreatLens v{APP_VERSION} — Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M')} — "
        f"Desenvolvido por {APP_AUTHOR} — CONFIDENCIAL"
    )
    p = Paragraph(text, footer_style)
    w, h = p.wrap(page_width - 4 * cm, 1 * cm)
    p.drawOn(canvas, 2 * cm, 1.2 * cm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.grey)
    canvas.drawRightString(page_width - 2 * cm, 1.2 * cm, f"Página {doc.page}")
    canvas.restoreState()


def export_pdf_gerencial(result: dict, url: str, path: str, scan_time: datetime | None = None) -> None:
    scan_time = scan_time or datetime.now()
    scan_time_str = scan_time.strftime("%d/%m/%Y %H:%M:%S")
    all_findings = result.get("findings", [])
    infra_profile = next((f for f in all_findings if f.get("title") == INFRA_PROFILE_TITLE), None)
    findings_no_infra = [f for f in all_findings if f.get("title") != INFRA_PROFILE_TITLE]
    actionable = sorted(
        [f for f in findings_no_infra if f.get("severity") != "informational"],
        key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )
    informational = [f for f in findings_no_infra if f.get("severity") == "informational"]
    risk_score = result.get("risk_score", 0)
    modules_run = result.get("modules_run", [])

    styles = getSampleStyleSheet()
    page_width, _ = A4
    usable_width = page_width - 4 * cm

    heading1 = ParagraphStyle("h1g", parent=styles["Heading1"], fontSize=18, textColor=colors.HexColor("#2DD4BF"), spaceAfter=4)
    heading2 = ParagraphStyle("h2g", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#1f2937"), spaceBefore=14, spaceAfter=6)
    body = ParagraphStyle("bodyg", parent=styles["BodyText"], fontSize=9, leading=13)
    cell_style = ParagraphStyle("cellg", parent=styles["BodyText"], fontSize=8, leading=10)
    small = ParagraphStyle("smallg", parent=styles["Normal"], fontSize=7, textColor=colors.grey)

    doc = SimpleDocTemplate(
        path, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm,
        leftMargin=2 * cm, rightMargin=2 * cm,
    )

    story = []

    # --- Capa ---
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph("ThreatLens", heading1))
    story.append(Paragraph("Relatório Gerencial de Segurança", ParagraphStyle(
        "subtitle", parent=styles["Normal"], fontSize=14, textColor=colors.HexColor("#374151"), spaceAfter=8,
    )))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#2DD4BF"), spaceAfter=10))
    story.append(Paragraph(f"<b>Alvo:</b> {_esc(url)}", body))
    story.append(Paragraph(f"<b>Data/Hora do Scan:</b> {scan_time_str}", body))
    risk_label = _g_risk_label(risk_score)
    risk_color = (
        "#22C55E" if risk_score >= 80
        else "#FACC15" if risk_score >= 60
        else "#F97316" if risk_score >= 40
        else "#F43F5E"
    )
    story.append(Paragraph(
        f"<b>Risk Score:</b> <font color='{risk_color}'><b>{risk_score} — {risk_label}</b></font>",
        body,
    ))
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey, spaceAfter=6))

    # --- 1. Sumário Executivo ---
    story.append(Paragraph("1. Sumário Executivo", heading2))
    story.append(Paragraph(_g_executive_paragraph(findings_no_infra, url), body))
    story.append(Spacer(1, 0.4 * cm))

    counts = _g_severity_counts(findings_no_infra)
    total_findings = len(findings_no_infra)
    sev_table_data = [
        [
            Paragraph("<b>Severidade</b>", cell_style),
            Paragraph("<b>Quantidade</b>", cell_style),
            Paragraph("<b>% do total</b>", cell_style),
        ]
    ]
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        pct = f"{count / total_findings * 100:.0f}%" if total_findings else "0%"
        sev_color = colors.HexColor(SEVERITY_COLORS.get(sev, "#9ca3af"))
        sev_table_data.append([
            Paragraph(f"<font color='{SEVERITY_COLORS.get(sev, '#9ca3af')}'><b>{_SEVERITY_PT.get(sev, sev)}</b></font>", cell_style),
            Paragraph(str(count), cell_style),
            Paragraph(pct, cell_style),
        ])
    sev_table = Table(sev_table_data, colWidths=[5 * cm, 4 * cm, 4 * cm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(sev_table)

    if modules_run:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            f"<b>Escopo da análise:</b> {', '.join(modules_run)}",
            ParagraphStyle("scope", parent=small, fontSize=8, textColor=colors.HexColor("#6b7280")),
        ))

    # --- 2. Perfil de Infraestrutura ---
    story.append(Paragraph("2. Perfil de Infraestrutura e Tecnologia", heading2))
    if infra_profile:
        story.append(Paragraph(_esc(infra_profile.get("description", "")), body))
        rec = infra_profile.get("recommendation", "")
        if rec:
            story.append(Spacer(1, 0.2 * cm))
            story.append(Paragraph(f"<b>Versões e recomendações:</b> {_esc(rec)}", body))
    else:
        story.append(Paragraph("Nenhuma informação de infraestrutura disponível para este alvo.", body))

    # --- 3. Distribuição de Riscos ---
    story.append(Paragraph("3. Distribuição de Riscos", heading2))
    risk_table_data = [
        [
            Paragraph("<b>Severidade</b>", cell_style),
            Paragraph("<b>Qtd</b>", cell_style),
            Paragraph("<b>Proporção</b>", cell_style),
        ]
    ]
    bar_max_width = usable_width * 0.55
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        bar_pct = count / total_findings if total_findings else 0
        bar_width = max(bar_pct * bar_max_width, 0)
        bar_color = SEVERITY_COLORS.get(sev, "#9ca3af")
        bar_html = (
            f"<font color='{bar_color}'>{'█' * max(int(bar_pct * 40), 1 if count else 0)}</font> "
            f"<font color='#6b7280'>{bar_pct:.0%}</font>"
            if count else "<font color='#9ca3af'>—</font>"
        )
        risk_table_data.append([
            Paragraph(f"<font color='{bar_color}'><b>{_SEVERITY_PT.get(sev, sev)}</b></font>", cell_style),
            Paragraph(str(count), cell_style),
            Paragraph(bar_html, cell_style),
        ])
    risk_table = Table(risk_table_data, colWidths=[4 * cm, 2 * cm, 9 * cm])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(risk_table)

    # --- 4. Plano de Ação ---
    story.append(Paragraph("4. Plano de Ação Detalhado", heading2))
    if actionable:
        action_data = [[
            Paragraph("<b>#</b>", cell_style),
            Paragraph("<b>Severidade</b>", cell_style),
            Paragraph("<b>Achado</b>", cell_style),
            Paragraph("<b>O que fazer</b>", cell_style),
            Paragraph("<b>Prioridade</b>", cell_style),
            Paragraph("<b>Prazo sugerido</b>", cell_style),
        ]]
        for idx, f in enumerate(actionable, 1):
            sev = f.get("severity", "low")
            sev_color = SEVERITY_COLORS.get(sev, "#9ca3af")
            action_data.append([
                Paragraph(str(idx), cell_style),
                Paragraph(f"<font color='{sev_color}'><b>{_SEVERITY_PT.get(sev, sev)}</b></font>", cell_style),
                Paragraph(_esc(f.get("title", "")), cell_style),
                Paragraph(_esc(f.get("recommendation", "—") or "—"), cell_style),
                Paragraph(_g_action_priority(sev), cell_style),
                Paragraph(_g_action_deadline(sev, scan_time), cell_style),
            ])
        action_table = Table(
            action_data,
            colWidths=[0.7 * cm, 2.2 * cm, 3.8 * cm, 5.5 * cm, 2 * cm, 2.3 * cm],
            repeatRows=1,
        )
        action_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(action_table)
    else:
        story.append(Paragraph("Nenhum achado de risco identificado que exija ação corretiva.", body))

    if informational:
        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph(
            "<b>Observações / Pontos de Atenção</b>",
            ParagraphStyle("obs_title", parent=body, fontSize=9, textColor=colors.HexColor("#6b7280")),
        ))
        for f in informational:
            story.append(Paragraph(
                f"• <b>{_esc(f.get('title', ''))}</b>: {_esc(f.get('description', ''))}",
                ParagraphStyle("obs", parent=small, fontSize=7.5, leading=11),
            ))

    # --- 5. Apêndice Técnico ---
    story.append(PageBreak())
    story.append(Paragraph("5. Apêndice Técnico", heading2))
    story.append(Paragraph(
        "Referência técnica completa para equipes de TI e segurança.",
        ParagraphStyle("apx_intro", parent=small, fontSize=8, spaceAfter=6),
    ))
    if actionable:
        apx_data = [[
            Paragraph("<b>Achado</b>", cell_style),
            Paragraph("<b>CVE</b>", cell_style),
            Paragraph("<b>OWASP</b>", cell_style),
            Paragraph("<b>Módulo</b>", cell_style),
            Paragraph("<b>CVSS</b>", cell_style),
        ]]
        for f in actionable:
            apx_data.append([
                Paragraph(_esc(f.get("title", "")), cell_style),
                Paragraph(_esc(f.get("cve", "") or "—"), cell_style),
                Paragraph(_esc(f.get("owasp_category", "") or "—"), cell_style),
                Paragraph(_esc(f.get("module", "") or "—"), cell_style),
                Paragraph(str(f.get("cvss_score", "—")), cell_style),
            ])
        apx_table = Table(apx_data, colWidths=[5.5 * cm, 2.4 * cm, 4 * cm, 2.2 * cm, 1.9 * cm], repeatRows=1)
        apx_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(apx_table)
    else:
        story.append(Paragraph("Nenhum achado técnico registrado.", body))

    doc.build(story, onFirstPage=_gerencial_footer, onLaterPages=_gerencial_footer)
