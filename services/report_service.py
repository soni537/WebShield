"""
services/report_service.py — Generate CSV, JSON, and PDF reports.
"""

from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from models import Scan, Finding


_OUTPUT_DIR = Path(tempfile.gettempdir()) / "webshield_reports"


def _ensure_output_dir(directory: Path) -> Path:
    """Create the output directory if it doesn't exist, then return it."""
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _scan_meta(scan: Scan) -> dict:
    return {
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "hostname": scan.normalized_hostname,
        "scanned_at": scan.scan_started_at.isoformat() if scan.scan_started_at else None,
        "completed_at": scan.scan_completed_at.isoformat() if scan.scan_completed_at else None,
        "security_score": scan.security_score,
        "total_findings": scan.total_findings,
        "critical": scan.critical_count,
        "high": scan.high_count,
        "medium": scan.medium_count,
        "low": scan.low_count,
        "informational": scan.informational_count,
    }


def _finding_row(f: Finding) -> dict:
    return {
        "finding_id": f.finding_id,
        "check_name": f.check_name,
        "category": f.category,
        "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
        "status": f.status.value if hasattr(f.status, "value") else f.status,
        "description": f.description,
        "evidence": f.evidence or "",
        "impact": f.impact or "",
        "recommendation": f.recommendation or "",
        "reference_url": f.reference_url or "",
    }


def generate_csv(scan: Scan, findings: list[Finding]) -> tuple[str, str, str]:
    out_dir = _ensure_output_dir(_OUTPUT_DIR)
    path = out_dir / f"webshield_scan_{scan.id}.csv"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        meta = _scan_meta(scan)
        # Write scan metadata as comment rows
        fh.write(f"# WebShield Security Report\n")
        fh.write(f"# Target: {meta['target_url']}\n")
        fh.write(f"# Score: {meta['security_score']}/100\n")
        fh.write(f"# Scanned: {meta['scanned_at']}\n")
        fh.write("#\n")

        fieldnames = [
            "finding_id", "check_name", "category", "severity",
            "status", "description", "evidence", "impact",
            "recommendation", "reference_url",
        ]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            writer.writerow(_finding_row(f))

    return str(path), "text/csv", f"webshield_scan_{scan.id}.csv"


def generate_json(scan: Scan, findings: list[Finding]) -> tuple[str, str, str]:
    out_dir = _ensure_output_dir(_OUTPUT_DIR)
    path = out_dir / f"webshield_scan_{scan.id}.json"
    report = {
        "report_generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": _scan_meta(scan),
        "findings": [_finding_row(f) for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    return str(path), "application/json", f"webshield_scan_{scan.id}.json"


def generate_pdf(scan: Scan, findings: list[Finding]) -> tuple[str, str, str]:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    )

    out_dir = _ensure_output_dir(_OUTPUT_DIR)
    path = out_dir / f"webshield_scan_{scan.id}.pdf"

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title", parent=styles["Title"], fontSize=20, textColor=colors.HexColor("#1a2a4a")
    )
    h2_style = ParagraphStyle(
        "H2", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#1e3a5f")
    )
    body_style = styles["BodyText"]

    SEVERITY_COLOURS = {
        "critical": colors.HexColor("#dc3545"),
        "high": colors.HexColor("#fd7e14"),
        "medium": colors.HexColor("#ffc107"),
        "low": colors.HexColor("#0dcaf0"),
        "informational": colors.HexColor("#6c757d"),
    }

    story = []

    # Title
    story.append(Paragraph("WebShield Security Scan Report", title_style))
    story.append(Spacer(1, 0.3 * cm))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1e3a5f")))
    story.append(Spacer(1, 0.4 * cm))

    # Metadata table
    meta = _scan_meta(scan)
    meta_data = [
        ["Target URL", meta["target_url"]],
        ["Scan Started", meta["scanned_at"] or "—"],
        ["Scan Completed", meta["completed_at"] or "—"],
        ["Security Score", f"{meta['security_score']}/100"],
        ["Total Findings", str(meta["total_findings"])],
        ["Critical / High / Medium / Low", f"{meta['critical']} / {meta['high']} / {meta['medium']} / {meta['low']}"],
    ]
    meta_table = Table(meta_data, colWidths=[5 * cm, 12 * cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eef5")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (1, 0), (1, -1), True),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.6 * cm))

    # Findings
    story.append(Paragraph("Findings", h2_style))
    story.append(Spacer(1, 0.2 * cm))

    if findings:
        headers_row = ["ID", "Check", "Category", "Severity", "Status", "Description"]
        table_data = [headers_row]
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else f.severity
            stat = f.status.value if hasattr(f.status, "value") else f.status
            table_data.append([
                f.finding_id,
                Paragraph(f.check_name, body_style),
                f.category,
                sev.upper(),
                stat.upper(),
                Paragraph(f.description[:200], body_style),
            ])

        col_widths = [1.5 * cm, 4 * cm, 3 * cm, 2 * cm, 1.8 * cm, 5 * cm]
        tbl = Table(table_data, colWidths=col_widths, repeatRows=1)
        tbl_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ]
        # Colour severity cells
        for row_idx, f in enumerate(findings, start=1):
            sev = f.severity.value if hasattr(f.severity, "value") else f.severity
            c = SEVERITY_COLOURS.get(sev, colors.grey)
            tbl_style.append(("TEXTCOLOR", (3, row_idx), (3, row_idx), c))
            tbl_style.append(("FONTNAME", (3, row_idx), (3, row_idx), "Helvetica-Bold"))

        tbl.setStyle(TableStyle(tbl_style))
        story.append(tbl)
    else:
        story.append(Paragraph("No findings recorded.", body_style))

    story.append(Spacer(1, 0.6 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Spacer(1, 0.2 * cm))
    story.append(
        Paragraph(
            "Disclaimer: This report is generated for educational and authorised security assessment purposes only. "
            "Findings are observations and may require manual verification to confirm exploitability.",
            ParagraphStyle("Disclaimer", parent=body_style, fontSize=8, textColor=colors.grey),
        )
    )

    doc.build(story)
    return str(path), "application/pdf", f"webshield_scan_{scan.id}.pdf"


def generate_report(scan: Scan, findings: list[Finding], fmt: str) -> tuple[str, str, str]:
    """Dispatch to the correct generator. Returns (file_path, mime_type, filename)."""
    if fmt == "csv":
        return generate_csv(scan, findings)
    elif fmt == "json":
        return generate_json(scan, findings)
    elif fmt == "pdf":
        return generate_pdf(scan, findings)
    else:
        raise ValueError(f"Unsupported format: {fmt}")
