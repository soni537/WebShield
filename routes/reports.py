"""
routes/reports.py — Report generation and export.
"""

from __future__ import annotations

from flask import Blueprint, abort, jsonify, render_template, request, send_file, current_app

from extensions import db
from models import Scan, Finding, ScanStatus

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/<int:scan_id>")
def report_page(scan_id: int):
    """HTML report page for a completed scan."""
    scan = db.session.get(Scan, scan_id) or abort(404)
    if scan.status != ScanStatus.COMPLETED:
        abort(404)
    findings = Finding.query.filter_by(scan_id=scan_id).order_by(Finding.severity).all()
    from scanner.scoring import score_label, score_colour
    return render_template(
        "reports.html",
        scan=scan,
        findings=findings,
        score_label=score_label(scan.security_score or 0),
        score_colour=score_colour(scan.security_score or 0),
    )


@reports_bp.route("/<int:scan_id>/export/<fmt>")
def export_report(scan_id: int, fmt: str):
    """Export a report in CSV, JSON, or PDF format."""
    from services.report_service import generate_report
    scan = db.session.get(Scan, scan_id) or abort(404)
    if scan.status != ScanStatus.COMPLETED:
        abort(404)

    findings = Finding.query.filter_by(scan_id=scan_id).all()

    fmt = fmt.lower()
    if fmt not in ("csv", "json", "pdf"):
        abort(400)

    file_path, mime_type, filename = generate_report(scan, findings, fmt)
    return send_file(file_path, mimetype=mime_type, as_attachment=True, download_name=filename)
