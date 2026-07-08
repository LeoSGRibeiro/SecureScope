import smtplib
import logging
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import settings

logger = logging.getLogger(__name__)

_SEVERITY_COLOR = {
    "critical": "#F43F5E",
    "high": "#F97316",
    "medium": "#FACC15",
    "low": "#22C55E",
    "informational": "#9ca3af",
}

_SEVERITY_PT = {
    "critical": "Crítico",
    "high": "Alto",
    "medium": "Médio",
    "low": "Baixo",
    "informational": "Informativo",
}


def _finding_rows(findings: list[dict], row_bg: str = "#1f2937") -> str:
    if not findings:
        return '<tr><td colspan="3" style="padding:8px;color:#9ca3af;">Nenhum achado.</td></tr>'
    rows = []
    for f in findings:
        sev = f.get("severity", "informational")
        color = _SEVERITY_COLOR.get(sev, "#9ca3af")
        sev_pt = _SEVERITY_PT.get(sev, sev)
        title = f.get("title", "")
        rec = f.get("recommendation", "") or "—"
        rows.append(
            f'<tr style="background:{row_bg}">'
            f'<td style="padding:6px 10px;font-weight:bold;color:{color}">{sev_pt}</td>'
            f'<td style="padding:6px 10px">{title}</td>'
            f'<td style="padding:6px 10px;color:#9ca3af">{rec}</td>'
            f"</tr>"
        )
    return "\n".join(rows)


def _build_html(url: str, diff: dict, scan_time: datetime, risk_score: float) -> str:
    scan_time_str = scan_time.strftime("%d/%m/%Y %H:%M:%S")
    new_findings = diff.get("new", [])
    resolved_findings = diff.get("resolved", [])
    new_count = len(new_findings)
    resolved_count = len(resolved_findings)

    if new_count == 0 and resolved_count == 0:
        summary = "Nenhuma alteração no perfil de segurança em relação ao scan anterior."
    else:
        parts = []
        if new_count:
            parts.append(f"<b>{new_count}</b> nova(s) vulnerabilidade(s) encontrada(s)")
        if resolved_count:
            parts.append(f"<b>{resolved_count}</b> vulnerabilidade(s) resolvida(s)")
        summary = " e ".join(parts) + "."

    risk_color = (
        "#22C55E" if risk_score >= 80
        else "#FACC15" if risk_score >= 60
        else "#F97316" if risk_score >= 40
        else "#F43F5E"
    )

    new_table = _finding_rows(new_findings)
    resolved_table = _finding_rows(resolved_findings, row_bg="#162032")

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"><title>ThreatLens — Relatório de Scan Agendado</title></head>
<body style="margin:0;padding:0;background:#0f172a;font-family:Arial,sans-serif;color:#e2e8f0">
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:700px;margin:32px auto">
  <tr>
    <td style="background:#151A23;padding:24px 32px;border-radius:8px 8px 0 0">
      <h1 style="margin:0;color:#2DD4BF;font-size:22px">ThreatLens</h1>
      <p style="margin:4px 0 0;color:#9ca3af;font-size:13px">Relatório de Scan Agendado</p>
    </td>
  </tr>
  <tr>
    <td style="background:#202735;padding:20px 32px">
      <p style="margin:0 0 4px"><b>Alvo:</b> {url}</p>
      <p style="margin:0 0 4px"><b>Data/Hora:</b> {scan_time_str}</p>
      <p style="margin:0"><b>Risk Score:</b> <span style="color:{risk_color};font-weight:bold">{risk_score}</span></p>
    </td>
  </tr>
  <tr>
    <td style="background:#1a2232;padding:16px 32px">
      <p style="margin:0;font-size:14px">{summary}</p>
    </td>
  </tr>

  <tr><td style="background:#151A23;padding:20px 32px">
    <h2 style="color:#F43F5E;font-size:15px;margin:0 0 10px">🔴 Novas Vulnerabilidades ({new_count})</h2>
    <table width="100%" cellpadding="0" cellspacing="2" style="font-size:12px">
      <tr style="background:#1f2937">
        <th style="padding:6px 10px;text-align:left;color:#9ca3af">Severidade</th>
        <th style="padding:6px 10px;text-align:left;color:#9ca3af">Vulnerabilidade</th>
        <th style="padding:6px 10px;text-align:left;color:#9ca3af">Recomendação</th>
      </tr>
      {new_table}
    </table>
  </td></tr>

  <tr><td style="background:#151A23;padding:4px 32px 20px">
    <h2 style="color:#22C55E;font-size:15px;margin:0 0 10px">✅ Vulnerabilidades Resolvidas ({resolved_count})</h2>
    <table width="100%" cellpadding="0" cellspacing="2" style="font-size:12px">
      <tr style="background:#1f2937">
        <th style="padding:6px 10px;text-align:left;color:#9ca3af">Severidade</th>
        <th style="padding:6px 10px;text-align:left;color:#9ca3af">Vulnerabilidade</th>
        <th style="padding:6px 10px;text-align:left;color:#9ca3af">Recomendação</th>
      </tr>
      {resolved_table}
    </table>
  </td></tr>

  <tr>
    <td style="background:#0f172a;padding:14px 32px;border-radius:0 0 8px 8px;text-align:center">
      <p style="margin:0;font-size:11px;color:#4b5563">
        ThreatLens — Desenvolvido por Leonardo Ribeiro — Este e-mail é gerado automaticamente.
      </p>
    </td>
  </tr>
</table>
</body>
</html>"""


def send_scan_diff_email(
    to: str,
    url: str,
    diff: dict,
    scan_time: datetime,
    risk_score: float,
) -> None:
    if not settings.SMTP_HOST or not settings.SMTP_USER or not settings.SMTP_PASS:
        logger.warning("SMTP not configured — skipping email notification")
        return

    html = _build_html(url, diff, scan_time, risk_score)
    new_count = len(diff.get("new", []))
    resolved_count = len(diff.get("resolved", []))

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[ThreatLens] Scan {url} — {new_count} nova(s), {resolved_count} resolvida(s)"
    msg["From"] = settings.EMAILS_FROM or settings.SMTP_USER
    msg["To"] = to
    msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASS)
            server.sendmail(msg["From"], [to], msg.as_string())
        logger.info("Scan diff email sent to %s for %s", to, url)
    except Exception:
        logger.exception("Failed to send scan diff email to %s", to)
