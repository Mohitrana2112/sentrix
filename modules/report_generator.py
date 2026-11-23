"""
SENTRIX Report Generation Module v2.5
Creates executive cybersecurity intelligence reports in PDF (via ReportLab), CSV, and TXT formats.
Includes SENTRIX branding, confidence ratings, IP intelligence, threat indicators, and remediation steps.
"""

import io
import csv
import datetime
from typing import Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable


def generate_pdf_report(investigation_data: Dict[str, Any]) -> bytes:
    """
    Generates a professional, print-ready cybersecurity audit PDF using ReportLab.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    brand_blue = colors.HexColor("#080E1C")
    brand_cyan = colors.HexColor("#00D5FF")
    brand_surface = colors.HexColor("#142238")
    accent_gray = colors.HexColor("#64748B")
    card_bg = colors.HexColor("#F8FAFC")
    border_color = colors.HexColor("#CBD5E1")

    # Risk Colors
    risk_score = investigation_data.get("risk_score", 0)
    risk_level = str(investigation_data.get("risk_level", "LOW")).upper()
    confidence = str(investigation_data.get("confidence", "HIGH")).upper()

    if risk_level == "CRITICAL":
        risk_color = colors.HexColor("#FF5263")
    elif risk_level == "HIGH":
        risk_color = colors.HexColor("#FF7A00")
    elif risk_level == "MEDIUM":
        risk_color = colors.HexColor("#FFB547")
    else:
        risk_color = colors.HexColor("#21D4A5")

    title_style = ParagraphStyle(
        "DocTitle",
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=brand_blue
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=accent_gray
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=brand_surface,
        spaceBefore=12,
        spaceAfter=5
    )
    body_style = ParagraphStyle(
        "BodyDark",
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#1E293B")
    )
    code_style = ParagraphStyle(
        "CodeText",
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0F172A")
    )

    elements = []

    # 1. Header Banner
    header_data = [
        [
            Paragraph("<b>SENTRIX</b> | Security Intelligence Platform", title_style),
            Paragraph(f"<b>CASE ID:</b> {investigation_data.get('uuid', 'STX-2026-001')}<br/>"
                      f"<b>Date:</b> {investigation_data.get('timestamp', datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'))}", subtitle_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[350, 180])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=2, color=brand_cyan, spaceBefore=0, spaceAfter=12))

    # 2. Target & Executive Summary Box
    summary_text = investigation_data.get("summary", "Automated threat intelligence and URL structure analysis.")
    target_str = str(investigation_data.get("target", "N/A"))

    exec_data = [
        [
            Paragraph(f"<b>Target Subject:</b> {target_str}<br/><b>Target Type:</b> {investigation_data.get('target_type', 'URL').upper()}<br/><b>Confidence:</b> {confidence}", body_style),
            Paragraph(f"<font size=18><b>{risk_score}/100</b></font><br/><b>VERDICT: {risk_level} RISK</b>", ParagraphStyle("RiskBadge", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=risk_color, alignment=1))
        ]
    ]
    exec_table = Table(exec_data, colWidths=[380, 150])
    exec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), card_bg),
        ('BOX', (0, 0), (-1, -1), 1, border_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 7),
    ]))
    elements.append(exec_table)
    elements.append(Spacer(1, 8))

    elements.append(Paragraph(f"<b>Executive Summary:</b> {summary_text}", body_style))
    elements.append(Spacer(1, 10))

    # 3. IP Intelligence Section
    ip_intel = investigation_data.get("ip_intelligence", {})
    if ip_intel and ip_intel.get("details"):
        elements.append(Paragraph("1. IP Intelligence &amp; Dual-Stack Resolution", section_heading))
        ip_rows = [
            [Paragraph("<b>IP Address</b>", body_style), Paragraph("<b>Version</b>", body_style), Paragraph("<b>Classification</b>", body_style), Paragraph("<b>Reverse PTR</b>", body_style)]
        ]
        for item in ip_intel.get("details", [])[:4]:
            ip_rows.append([
                Paragraph(f"<code>{item.get('ip')}</code>", code_style),
                Paragraph(str(item.get("version")), body_style),
                Paragraph(str(item.get("classification")), body_style),
                Paragraph(str(item.get("ptr")), code_style)
            ])
        ip_table = Table(ip_rows, colWidths=[120, 50, 180, 180])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ('GRID', (0, 0), (-1, -1), 0.5, border_color),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(ip_table)
        elements.append(Spacer(1, 10))

    # 4. URL Anatomy Structure
    anatomy = investigation_data.get("anatomy", {})
    if anatomy:
        elements.append(Paragraph("2. Technical URL Anatomy Breakdown", section_heading))
        anatomy_rows = [
            [Paragraph("<b>Component</b>", body_style), Paragraph("<b>Identified Value</b>", body_style), Paragraph("<b>Security Notes</b>", body_style)],
            [Paragraph("Protocol", body_style), Paragraph(f"<code>{anatomy.get('protocol', 'N/A')}</code>", code_style), Paragraph("TLS Encrypted" if anatomy.get('protocol') == 'https' else "Insecure Cleartext", body_style)],
            [Paragraph("Hostname", body_style), Paragraph(f"<code>{anatomy.get('hostname', 'N/A')}</code>", code_style), Paragraph(f"Shannon Entropy: {anatomy.get('host_entropy', 'N/A')} bits/char", body_style)],
            [Paragraph("Registered Domain", body_style), Paragraph(f"<code>{anatomy.get('domain', 'N/A')}</code>", code_style), Paragraph(f"TLD: {anatomy.get('tld', 'N/A')}", body_style)],
            [Paragraph("Port", body_style), Paragraph(f"<code>{anatomy.get('port', 'N/A')}</code>", code_style), Paragraph("Standard web port" if anatomy.get('port') in ('80', '443', 80, 443) else "Non-standard port", body_style)],
            [Paragraph("Path", body_style), Paragraph(f"<code>{str(anatomy.get('path', 'N/A'))[:45]}</code>", code_style), Paragraph("Endpoint routing target", body_style)],
        ]
        anat_table = Table(anatomy_rows, colWidths=[120, 240, 170])
        anat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ('GRID', (0, 0), (-1, -1), 0.5, border_color),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(anat_table)
        elements.append(Spacer(1, 10))

    # 5. Security Indicators & Findings
    indicators = investigation_data.get("indicators", [])
    elements.append(Paragraph(f"3. Security Indicators &amp; Threat Evidence ({len(indicators)} detected)", section_heading))
    if indicators:
        ind_rows = [
            [Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Finding Name</b>", body_style), Paragraph("<b>Evidence &amp; Technical Impact</b>", body_style)]
        ]
        for ind in indicators[:6]:
            sev = ind.get("severity", "LOW")
            sev_col = "#FF5263" if sev == "CRITICAL" else ("#FF7A00" if sev == "HIGH" else ("#FFB547" if sev == "MEDIUM" else "#21D4A5"))
            ind_rows.append([
                Paragraph(f"<font color='{sev_col}'><b>{sev}</b></font>", body_style),
                Paragraph(f"<b>{ind.get('name', 'N/A')}</b> (+{ind.get('score_impact', 0)} pts)", body_style),
                Paragraph(f"<b>Evidence:</b> {ind.get('evidence', 'N/A')}<br/><b>Impact:</b> {ind.get('technical_explanation', 'N/A')}", body_style)
            ])
        ind_table = Table(ind_rows, colWidths=[65, 165, 300])
        ind_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ('GRID', (0, 0), (-1, -1), 0.5, border_color),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(ind_table)
    else:
        elements.append(Paragraph("Clean baseline verified: Zero suspicious structural indicators or brand anomalies detected.", body_style))
    elements.append(Spacer(1, 10))

    # 6. Recommendations
    recs = investigation_data.get("recommendations", [])
    if recs:
        elements.append(Paragraph("4. Recommended Defensive Precautions", section_heading))
        rec_items = "".join([f"&bull; {r}<br/>" for r in recs])
        elements.append(Paragraph(rec_items, body_style))
        elements.append(Spacer(1, 10))

    # 7. Disclaimer Footer
    elements.append(HRFlowable(width="100%", thickness=1, color=border_color, spaceBefore=6, spaceAfter=6))
    elements.append(Paragraph(
        "<b>SENTRIX Intelligence Notice:</b> This audit report is generated automatically by the SENTRIX cybersecurity engine. "
        "It provides structural heuristic analysis and OSINT telemetry. Absence of detected anomalies does not guarantee complete security. "
        "Intended strictly for authorized defensive security assessments.",
        subtitle_style
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()


def generate_txt_report(investigation_data: Dict[str, Any]) -> str:
    """
    Generates structured plain-text investigation report.
    """
    lines = []
    lines.append("=" * 80)
    lines.append("SENTRIX SECURITY ANALYSIS & URL INTELLIGENCE AUDIT REPORT")
    lines.append(f"Case ID:        {investigation_data.get('uuid', 'STX-2026-001')}")
    lines.append(f"Target:         {investigation_data.get('target', 'N/A')}")
    lines.append(f"Target Type:    {str(investigation_data.get('target_type', 'URL')).upper()}")
    lines.append(f"Timestamp:      {investigation_data.get('timestamp', datetime.datetime.utcnow().isoformat())}")
    lines.append(f"Risk Score:     {investigation_data.get('risk_score', 0)} / 100 ({investigation_data.get('risk_level', 'LOW')})")
    lines.append(f"Confidence:     {investigation_data.get('confidence', 'HIGH')}")
    lines.append("=" * 80)
    lines.append("\n[EXECUTIVE SUMMARY]")
    lines.append(investigation_data.get("summary", "Preliminary static risk inspection."))
    lines.append("\n" + "-" * 80)

    ip_intel = investigation_data.get("ip_intelligence", {})
    if ip_intel and ip_intel.get("details"):
        lines.append("[IP INTELLIGENCE]")
        for item in ip_intel.get("details", []):
            lines.append(f" * {item.get('ip')} ({item.get('version')}) - {item.get('classification')} | PTR: {item.get('ptr')}")
        lines.append("-" * 80)

    anatomy = investigation_data.get("anatomy", {})
    if anatomy:
        lines.append("[URL ANATOMY]")
        lines.append(f"Protocol:       {anatomy.get('protocol')}")
        lines.append(f"Hostname:       {anatomy.get('hostname')}")
        lines.append(f"Domain:         {anatomy.get('domain')}")
        lines.append(f"TLD:            {anatomy.get('tld')}")
        lines.append(f"Port:           {anatomy.get('port')}")
        lines.append(f"Path:           {anatomy.get('path')}")
        lines.append(f"Entropy:        {anatomy.get('host_entropy')} bits/char")
        lines.append("-" * 80)

    indicators = investigation_data.get("indicators", [])
    lines.append(f"[SECURITY FINDINGS] ({len(indicators)} indicators detected)")
    if indicators:
        for idx, ind in enumerate(indicators, 1):
            lines.append(f"\n{idx}. [{ind.get('severity', 'LOW')}] {ind.get('name')} (+{ind.get('score_impact', 0)} pts)")
            lines.append(f"   Evidence:    {ind.get('evidence')}")
            lines.append(f"   Explanation: {ind.get('technical_explanation')}")
            lines.append(f"   Precaution:  {ind.get('precaution')}")
    else:
        lines.append("Clean baseline: Zero suspicious structural indicators detected.")
    lines.append("\n" + "-" * 80)

    recs = investigation_data.get("recommendations", [])
    if recs:
        lines.append("[ACTIONABLE PRECAUTIONS]")
        for r in recs:
            lines.append(f" * {r}")
        lines.append("-" * 80)

    lines.append("\nDISCLAIMER: This automated preliminary audit is for defensive research purposes only.")
    lines.append("=" * 80)
    return "\n".join(lines)


def generate_csv_report(investigation_data: Dict[str, Any]) -> str:
    """
    Generates CSV format for investigation findings.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Case ID", "Target", "Risk Score", "Risk Level", "Confidence",
        "Indicator Name", "Severity", "Impact", "Evidence", "Technical Explanation", "Precaution"
    ])

    case_id = investigation_data.get("uuid", "STX-2026-001")
    target = investigation_data.get("target", "")
    score = investigation_data.get("risk_score", 0)
    level = investigation_data.get("risk_level", "LOW")
    conf = investigation_data.get("confidence", "HIGH")

    indicators = investigation_data.get("indicators", [])
    if indicators:
        for ind in indicators:
            writer.writerow([
                case_id,
                target,
                score,
                level,
                conf,
                ind.get("name", ""),
                ind.get("severity", ""),
                ind.get("score_impact", 0),
                ind.get("evidence", ""),
                ind.get("technical_explanation", ""),
                ind.get("precaution", "")
            ])
    else:
        writer.writerow([case_id, target, score, level, conf, "Clean Baseline", "LOW", 0, "No anomalies detected", "Clean structural baseline", "Standard telemetry logging"])

    return buf.getvalue()
