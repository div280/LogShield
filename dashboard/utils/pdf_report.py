"""
pdf_report.py
Generates professional forensic PDF reports
for LogShield using ReportLab.
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet, ParagraphStyle)
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable, PageBreak)
from reportlab.lib.enums import TA_LEFT, TA_CENTER
import pandas as pd
from datetime import datetime
from typing import Optional
import io


DARK_RED = colors.HexColor('#CC1F24')
DARK_BG = colors.HexColor('#0A0C10')
MID_GREY = colors.HexColor('#374151')
LIGHT_GREY = colors.HexColor('#6B7280')
OFF_WHITE = colors.HexColor('#F0F2F5')
SUCCESS = colors.HexColor('#059669')
WARNING = colors.HexColor('#D97706')


def generate_pdf_report(
        df: pd.DataFrame,
        verdict: str,
        deleted_count: int,
        injected_count: int,
        anomaly_count: int,
        critical_count: int,
        findings: list,
        analysis_timestamp: str) -> bytes:
    """
    Generate a professional forensic PDF report.

    Args:
        df: analyzed DataFrame
        verdict: COMPROMISED, SUSPICIOUS, or CLEAN
        deleted_count: number of deleted records
        injected_count: number of injected records
        anomaly_count: number of AI anomalies
        critical_count: number of critical events
        findings: list of finding dicts
        analysis_timestamp: when analysis was run

    Returns:
        PDF as bytes
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()
    story = []

    # Cover page
    story.append(Spacer(1, 3*cm))
    story.append(Paragraph(
        "LOGSHIELD",
        ParagraphStyle(
            'brand',
            fontSize=32,
            fontName='Helvetica-Bold',
            textColor=DARK_RED,
            letterSpacing=8,
            alignment=TA_CENTER
        )
    ))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "Forensic Integrity Platform",
        ParagraphStyle(
            'tagline',
            fontSize=11,
            fontName='Helvetica',
            textColor=LIGHT_GREY,
            letterSpacing=3,
            alignment=TA_CENTER
        )
    ))
    story.append(Spacer(1, 1.5*cm))
    story.append(HRFlowable(
        width="100%",
        thickness=1,
        color=DARK_RED,
        spaceAfter=1.5*cm
    ))

    # Verdict block
    verdict_color = (
        DARK_RED if verdict == "COMPROMISED"
        else WARNING if verdict == "SUSPICIOUS"
        else SUCCESS
    )
    story.append(Paragraph(
        f"FORENSIC ANALYSIS REPORT",
        ParagraphStyle(
            'report_title',
            fontSize=18,
            fontName='Helvetica-Bold',
            textColor=colors.black,
            alignment=TA_CENTER
        )
    ))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(
        f"Verdict: {verdict}",
        ParagraphStyle(
            'verdict_text',
            fontSize=24,
            fontName='Helvetica-Bold',
            textColor=verdict_color,
            alignment=TA_CENTER
        )
    ))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(
        f"Analysis performed: {analysis_timestamp}",
        ParagraphStyle(
            'timestamp',
            fontSize=10,
            fontName='Helvetica',
            textColor=LIGHT_GREY,
            alignment=TA_CENTER
        )
    ))
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(
        "CONFIDENTIAL FORENSIC DOCUMENT",
        ParagraphStyle(
            'confidential',
            fontSize=9,
            fontName='Helvetica-Bold',
            textColor=LIGHT_GREY,
            letterSpacing=2,
            alignment=TA_CENTER
        )
    ))
    story.append(PageBreak())

    # Executive Summary
    def section(title):
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph(
            title,
            ParagraphStyle(
                'section',
                fontSize=14,
                fontName='Helvetica-Bold',
                textColor=DARK_RED,
                spaceBefore=12,
                spaceAfter=6
            )
        ))
        story.append(HRFlowable(
            width="100%",
            thickness=0.5,
            color=DARK_RED,
            spaceAfter=8
        ))

    body = ParagraphStyle(
        'body',
        fontSize=10,
        fontName='Helvetica',
        textColor=colors.black,
        leading=16,
        spaceAfter=8
    )

    section("1. EXECUTIVE SUMMARY")

    summary_map = {
        "COMPROMISED": (
            "LogShield has identified confirmed evidence "
            "of deliberate log manipulation in the "
            "analyzed file. Cryptographic chain "
            "verification and AI behavioral analysis "
            "both indicate that this log file has been "
            "tampered with. The integrity of this file "
            "as forensic evidence is compromised."
        ),
        "SUSPICIOUS": (
            "LogShield has identified anomalous patterns "
            "in the analyzed log file that are "
            "inconsistent with normal system behavior. "
            "While cryptographic chain integrity is "
            "intact, AI behavioral analysis has flagged "
            "statistical outliers requiring investigation."
        ),
        "CLEAN": (
            "LogShield analysis indicates that the "
            "submitted log file appears authentic. "
            "Cryptographic chain verification passed "
            "and AI behavioral analysis found no "
            "significant anomalies. The log file "
            "appears to be an accurate record of "
            "system activity."
        )
    }
    story.append(Paragraph(
        summary_map.get(verdict, ""),
        body))

    section("2. QUANTITATIVE FINDINGS")

    metrics_data = [
        ["Metric", "Value", "Status"],
        ["Total Events Analyzed",
         f"{len(df):,}", "INFO"],
        ["Deleted Records (HMAC)",
         f"{deleted_count:,}",
         "CRITICAL" if deleted_count > 0 else "PASS"],
        ["Injected Records (HMAC)",
         f"{injected_count:,}",
         "CRITICAL" if injected_count > 0 else "PASS"],
        ["AI Anomalies Detected",
         f"{anomaly_count:,}",
         "HIGH" if anomaly_count > 0 else "PASS"],
        ["Critical Events (1102/4719)",
         f"{critical_count:,}",
         "HIGH" if critical_count > 0 else "PASS"],
        ["Overall Verdict", verdict,
         "SEE ABOVE"]
    ]

    t = Table(
        metrics_data,
        colWidths=[7*cm, 4*cm, 4*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), DARK_RED),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),
        ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,1), (-1,-1), 10),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.white, colors.HexColor('#F8FAFC')]),
        ('GRID', (0,0), (-1,-1), 0.5,
         colors.HexColor('#E2E8F0')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(t)

    section("3. FORENSIC FINDINGS")

    if not findings:
        story.append(Paragraph(
            "No significant forensic findings "
            "identified.", body))
    else:
        for i, f in enumerate(findings, 1):
            sev = f.get('sev', 'medium').upper()
            sev_color = (
                DARK_RED if sev == 'CRITICAL'
                else WARNING if sev == 'HIGH'
                else colors.black
            )
            story.append(Paragraph(
                f"{i}. [{sev}] {f['title']}",
                ParagraphStyle(
                    f'finding_{i}',
                    fontSize=11,
                    fontName='Helvetica-Bold',
                    textColor=sev_color,
                    spaceBefore=8,
                    spaceAfter=4
                )
            ))
            story.append(Paragraph(
                f['detail'], body))

    section("4. RECOMMENDED ACTIONS")

    actions = [
        ("Preserve log file",
         "Create a write-protected forensic copy "
         "immediately. Do not allow any process to "
         "modify or overwrite the original."),
        ("Isolate affected system",
         "Disconnect the machine from the network "
         "to prevent further evidence destruction."),
        ("Engage incident response",
         "Escalate with this LogShield report. "
         "Record the exact timestamp of analysis."),
        ("Correlate with external sources",
         "Check network, firewall, and DNS logs "
         "for the same time period."),
        ("Preserve chain of custody",
         "Document every action taken, by whom, "
         "and at what time.")
    ]

    if verdict == "CLEAN":
        story.append(Paragraph(
            "No immediate action required. "
            "Continue routine monitoring.", body))
    else:
        for i, (title, detail) in enumerate(
                actions, 1):
            story.append(Paragraph(
                f"{i}. {title}",
                ParagraphStyle(
                    f'action_{i}',
                    fontSize=11,
                    fontName='Helvetica-Bold',
                    textColor=colors.black,
                    spaceBefore=6,
                    spaceAfter=2
                )
            ))
            story.append(Paragraph(
                detail, body))

    section("5. METHODOLOGY")

    methodology = (
        "LogShield employs a dual-layer detection "
        "framework. Layer 1 uses HMAC-SHA256 "
        "cryptographic chaining where each log "
        "record HMAC is computed as a function of "
        "the record content, the previous record "
        "HMAC, and a secret key. This provides "
        "mathematical proof of any deletion, "
        "modification, or injection. Layer 2 "
        "applies unsupervised machine learning "
        "using Isolation Forest trained on normal "
        "log baselines to detect behavioral "
        "anomalies including temporal gaps, "
        "frequency outliers, and critical event "
        "patterns. Results from both layers are "
        "fused with cryptographic results taking "
        "precedence over statistical findings."
    )
    story.append(Paragraph(methodology, body))

    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(
        width="100%",
        thickness=0.5,
        color=LIGHT_GREY,
        spaceAfter=8
    ))
    story.append(Paragraph(
        "This report was generated by LogShield. "
        "For investigative reference only. "
        "Findings should be verified by a "
        "qualified forensic professional before "
        "use in legal proceedings.",
        ParagraphStyle(
            'disclaimer',
            fontSize=8,
            fontName='Helvetica',
            textColor=LIGHT_GREY,
            alignment=TA_CENTER
        )
    ))

    doc.build(story)
    return buffer.getvalue()
