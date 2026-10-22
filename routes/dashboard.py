"""
routes/dashboard.py — Landing page, dashboard, and scan history views.
"""

from __future__ import annotations

import urllib.parse
from datetime import datetime, timedelta

from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import current_user

from extensions import db
from models import Scan, ScanStatus

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    """Landing page with scan initiation form."""
    return render_template("index.html")


@dashboard_bp.route("/dashboard")
def dashboard():
    """Main dashboard with statistics and recent scans."""
    # Statistics
    total_scans = Scan.query.count()
    completed_scans = Scan.query.filter_by(status=ScanStatus.COMPLETED).count()

    # Aggregate finding counts from completed scans
    from sqlalchemy import func
    agg = db.session.query(
        func.sum(Scan.total_findings).label("total"),
        func.sum(Scan.critical_count).label("critical"),
        func.sum(Scan.high_count).label("high"),
        func.sum(Scan.medium_count).label("medium"),
        func.sum(Scan.low_count).label("low"),
    ).filter(Scan.status == ScanStatus.COMPLETED).first()

    total_findings = agg.total or 0
    critical_count = agg.critical or 0
    high_count = agg.high or 0
    medium_count = agg.medium or 0
    low_count = agg.low or 0

    # Recent scans (last 10)
    recent_scans = (
        Scan.query.order_by(Scan.scan_started_at.desc()).limit(10).all()
    )

    # Score distribution for chart (last 30 completed scans)
    chart_scans = (
        Scan.query.filter_by(status=ScanStatus.COMPLETED)
        .order_by(Scan.scan_started_at.desc())
        .limit(30)
        .all()
    )
    chart_labels = [s.scan_started_at.strftime("%b %d") for s in reversed(chart_scans)]
    chart_scores = [s.security_score or 0 for s in reversed(chart_scans)]

    # Severity distribution
    sev_labels = ["Critical", "High", "Medium", "Low"]
    sev_data = [critical_count, high_count, medium_count, low_count]

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        completed_scans=completed_scans,
        total_findings=total_findings,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        recent_scans=recent_scans,
        chart_labels=chart_labels,
        chart_scores=chart_scores,
        sev_labels=sev_labels,
        sev_data=sev_data,
    )


@dashboard_bp.route("/history")
def scan_history():
    """Scan history page with search/filter."""
    page = request.args.get("page", 1, type=int)
    query_str = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()

    q = Scan.query

    if query_str:
        q = q.filter(Scan.target_url.ilike(f"%{query_str}%"))
    if status_filter:
        try:
            q = q.filter(Scan.status == ScanStatus(status_filter))
        except ValueError:
            pass

    scans = q.order_by(Scan.scan_started_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template(
        "scan_history.html",
        scans=scans,
        query_str=query_str,
        status_filter=status_filter,
    )


@dashboard_bp.route("/health")
def health():
    """Health check endpoint."""
    try:
        db.session.execute(db.text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    from flask import jsonify
    return jsonify({"status": "ok" if db_ok else "degraded", "db": db_ok})
