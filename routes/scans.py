"""
routes/scans.py — Scan initiation, status, results, and API endpoints.
"""

from __future__ import annotations

import threading
import urllib.parse
from datetime import datetime, timezone

from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
    flash,
)

from extensions import db
from models import Scan, Finding, ScanStatus
from scanner import run_scan, dispatch_scan
from scanner.safety import validate_url
from scanner.scoring import score_label, score_colour

scans_bp = Blueprint("scans", __name__, url_prefix="/scans")

# Simple in-memory per-IP rate limiter (for demo use; production needs Redis)
_rate_cache: dict[str, list[datetime]] = {}


def _check_rate_limit(ip: str, limit: int) -> bool:
    """Return True if request is within rate limit, False if exceeded."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)  # naive UTC for comparison
    window = [t for t in _rate_cache.get(ip, []) if (now - t).seconds < 60]
    _rate_cache[ip] = window
    if len(window) >= limit:
        return False
    _rate_cache[ip].append(now)
    return True


# ---------------------------------------------------------------------------
# Web routes
# ---------------------------------------------------------------------------

@scans_bp.route("/new", methods=["POST"])
def new_scan():
    """Initiate a new scan (form POST from landing page)."""
    target_url = request.form.get("url", "").strip()
    client_ip = request.remote_addr or "unknown"
    rate_limit = current_app.config.get("RATE_LIMIT_PER_MINUTE", 10)

    if not target_url:
        flash("Please enter a URL to scan.", "warning")
        return redirect(url_for("dashboard.index"))

    # Normalise scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    # Rate limit check
    if not _check_rate_limit(client_ip, rate_limit):
        flash("Rate limit exceeded. Please wait before initiating another scan.", "danger")
        return redirect(url_for("dashboard.index"))

    # SSRF validation
    allowlist = current_app.config.get("SCAN_ALLOWLIST", [])
    allow_private = current_app.config.get("SCANNER_ALLOW_PRIVATE_IPS", False)
    validation = validate_url(target_url, allowlist=allowlist, allow_private_ips=allow_private)
    if not validation.valid:
        flash(f"Scan blocked: {validation.error}", "danger")
        return redirect(url_for("dashboard.index"))

    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname or ""

    scan = Scan(
        target_url=target_url,
        normalized_hostname=hostname,
        status=ScanStatus.PENDING,
        scan_started_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.session.add(scan)
    db.session.commit()

    # Launch scan task (managed thread / sync in tests)
    app = current_app._get_current_object()
    dispatch_scan(scan.id, target_url, app)

    return redirect(url_for("scans.scan_status_page", scan_id=scan.id))


@scans_bp.route("/<int:scan_id>")
def scan_status_page(scan_id: int):
    """Scan results / status page."""
    scan = db.session.get(Scan, scan_id) or abort(404)
    findings = []
    if scan.status == ScanStatus.COMPLETED:
        findings = Finding.query.filter_by(scan_id=scan_id).all()

    # Group findings by severity for display
    sev_order = ["critical", "high", "medium", "low", "informational"]
    grouped: dict[str, list[Finding]] = {s: [] for s in sev_order}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        grouped.setdefault(sev, []).append(f)

    score = scan.security_score or 0
    label = score_label(score)
    colour = score_colour(score)

    return render_template(
        "scan_results.html",
        scan=scan,
        findings=findings,
        grouped=grouped,
        sev_order=sev_order,
        score=score,
        score_label=label,
        score_colour=colour,
    )


@scans_bp.route("/<int:scan_id>/compare")
def compare_scans(scan_id: int):
    """Compare two scans of the same host."""
    other_id = request.args.get("other", type=int)
    scan_a = db.session.get(Scan, scan_id) or abort(404)
    scan_b = db.session.get(Scan, other_id) if other_id else None

    # Fetch all previous scans for the same hostname (for the dropdown)
    same_host_scans = (
        Scan.query.filter(
            Scan.normalized_hostname == scan_a.normalized_hostname,
            Scan.id != scan_id,
            Scan.status == ScanStatus.COMPLETED,
        )
        .order_by(Scan.scan_started_at.desc())
        .all()
    )

    findings_a = (
        {f.finding_id: f for f in Finding.query.filter_by(scan_id=scan_id).all()}
        if scan_a.status == ScanStatus.COMPLETED else {}
    )
    findings_b = (
        {f.finding_id: f for f in Finding.query.filter_by(scan_id=other_id).all()}
        if scan_b and scan_b.status == ScanStatus.COMPLETED else {}
    )

    all_fids = sorted(set(findings_a) | set(findings_b))

    return render_template(
        "compare.html",
        scan_a=scan_a,
        scan_b=scan_b,
        same_host_scans=same_host_scans,
        findings_a=findings_a,
        findings_b=findings_b,
        all_fids=all_fids,
    )


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

@scans_bp.route("/api/scan", methods=["POST"])
def api_new_scan():
    """API endpoint to start a scan. Expects JSON: {"url": "..."}"""
    data = request.get_json(silent=True) or {}
    target_url = str(data.get("url", "")).strip()
    client_ip = request.remote_addr or "unknown"
    rate_limit = current_app.config.get("RATE_LIMIT_PER_MINUTE", 10)

    if not target_url:
        return jsonify({"error": "url field is required"}), 400

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    if not _check_rate_limit(client_ip, rate_limit):
        return jsonify({"error": "Rate limit exceeded"}), 429

    allowlist = current_app.config.get("SCAN_ALLOWLIST", [])
    allow_private = current_app.config.get("SCANNER_ALLOW_PRIVATE_IPS", False)
    validation = validate_url(target_url, allowlist=allowlist, allow_private_ips=allow_private)
    if not validation.valid:
        return jsonify({"error": validation.error}), 422

    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname or ""

    scan = Scan(
        target_url=target_url,
        normalized_hostname=hostname,
        status=ScanStatus.PENDING,
        scan_started_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.session.add(scan)
    db.session.commit()

    app = current_app._get_current_object()
    dispatch_scan(scan.id, target_url, app)

    return jsonify({"scan_id": scan.id, "status": "pending"}), 202


@scans_bp.route("/api/scan/<int:scan_id>", methods=["GET"])
def api_scan_status(scan_id: int):
    """Return scan status and summary."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan.to_dict())


@scans_bp.route("/api/scan/<int:scan_id>/findings", methods=["GET"])
def api_scan_findings(scan_id: int):
    """Return all findings for a completed scan."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404
    if scan.status != ScanStatus.COMPLETED:
        return jsonify({"error": "Scan not yet completed", "status": scan.status.value}), 409
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    return jsonify({"scan_id": scan_id, "findings": [f.to_dict() for f in findings]})


@scans_bp.route("/api/history", methods=["GET"])
def api_history():
    """Return paginated scan history."""
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), 100)
    scans = Scan.query.order_by(Scan.scan_started_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return jsonify({
        "page": scans.page,
        "total": scans.total,
        "pages": scans.pages,
        "scans": [s.to_dict() for s in scans.items],
    })
