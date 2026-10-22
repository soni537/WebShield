"""
scanner/orchestrator.py — Coordinates all scanning modules and persists results.

run_scan(scan_id, target_url, app) is called from a background thread.
It updates the Scan record directly in the database.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Optional

import requests
import requests.exceptions

logger = logging.getLogger(__name__)

# Sentinel origin used to test CORS reflection
_CORS_TEST_ORIGIN = "https://webshield-test.example.invalid"


def _normalise_finding(f, scan_id: int) -> dict:
    """Convert a FindingData dataclass (from any module) into a dict for the DB."""
    if isinstance(f, dict):
        d = f.copy()
    else:
        d = f.__dict__.copy()
    d["scan_id"] = scan_id
    return d


def run_scan(scan_id: int, target_url: str, app) -> None:
    """
    Entry point called from a background thread.

    Performs all security checks, computes a score, and persists results.
    """
    with app.app_context():
        from extensions import db
        from models import Scan, Finding, ScanStatus, Severity, FindingStatus
        from scanner.safety import validate_url
        from scanner.headers import run_header_checks
        from scanner.cookies import run_cookie_checks
        from scanner.cors import run_cors_checks
        from scanner.transport import run_transport_checks
        from scanner.html_checks import run_html_checks
        from scanner.scoring import calculate_score

        scan: Optional[Scan] = db.session.get(Scan, scan_id)
        if scan is None:
            logger.error("run_scan called with unknown scan_id=%s", scan_id)
            return

        scan.status = ScanStatus.RUNNING
        scan.scan_started_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.commit()

        timeout = app.config.get("SCANNER_TIMEOUT", 15)
        allowlist = app.config.get("SCAN_ALLOWLIST", [])
        demo_mode = app.config.get("DEMO_MODE", False)

        all_raw_findings: list[dict] = []

        try:
            # ----------------------------------------------------------
            # 1. Validate URL (SSRF prevention)
            # ----------------------------------------------------------
            allow_private_ips = app.config.get("SCANNER_ALLOW_PRIVATE_IPS", False)
            validation = validate_url(target_url, allowlist=allowlist, allow_private_ips=allow_private_ips)
            if not validation.valid:
                scan.status = ScanStatus.FAILED
                scan.error_message = f"URL validation failed: {validation.error}"
                scan.scan_completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                db.session.commit()
                return

            scheme = validation.scheme

            # ----------------------------------------------------------
            # 2. Transport checks (HTTPS / TLS)
            # ----------------------------------------------------------
            transport_findings, primary_response = run_transport_checks(
                target_url, timeout=timeout
            )
            for f in transport_findings:
                all_raw_findings.append(_normalise_finding(f, scan_id))

            # ----------------------------------------------------------
            # 3. Header checks
            # ----------------------------------------------------------
            headers: dict[str, str] = {}
            raw_cookies: list[str] = []
            html_content: str = ""
            actual_scheme: str = scheme

            if primary_response is not None:
                headers = dict(primary_response.headers)
                raw_cookies = primary_response.raw.headers.getlist("Set-Cookie") if hasattr(primary_response.raw, "headers") else []
                if not raw_cookies:
                    raw_cookies = [v for k, v in primary_response.headers.items() if k.lower() == "set-cookie"]
                actual_scheme = primary_response.url.split("://")[0] if primary_response.url else scheme
                try:
                    html_content = primary_response.text[:app.config.get("SCANNER_MAX_RESPONSE_SIZE", 5_000_000)]
                except Exception:
                    html_content = ""

            header_findings = run_header_checks(headers, actual_scheme)
            for f in header_findings:
                all_raw_findings.append(_normalise_finding(f, scan_id))

            # ----------------------------------------------------------
            # 4. Cookie checks
            # ----------------------------------------------------------
            cookie_findings = run_cookie_checks(raw_cookies, actual_scheme)
            for f in cookie_findings:
                all_raw_findings.append(_normalise_finding(f, scan_id))

            # ----------------------------------------------------------
            # 5. CORS checks
            # ----------------------------------------------------------
            cors_headers: dict[str, str] = {}
            try:
                cors_response = requests.options(
                    target_url,
                    headers={
                        "Origin": _CORS_TEST_ORIGIN,
                        "Access-Control-Request-Method": "GET",
                        "User-Agent": "WebShield-SecurityScanner/1.0 (educational)",
                    },
                    timeout=timeout,
                    verify=True,
                    allow_redirects=False,
                )
                cors_headers = dict(cors_response.headers)
            except Exception as exc:
                logger.debug("CORS OPTIONS request failed: %s", exc)
                cors_headers = headers  # Fall back to main response headers

            cors_findings = run_cors_checks(cors_headers, _CORS_TEST_ORIGIN)
            for f in cors_findings:
                all_raw_findings.append(_normalise_finding(f, scan_id))

            # ----------------------------------------------------------
            # 6. HTML checks
            # ----------------------------------------------------------
            html_findings = run_html_checks(html_content, target_url)
            for f in html_findings:
                all_raw_findings.append(_normalise_finding(f, scan_id))

            # ----------------------------------------------------------
            # 7. Persist findings
            # ----------------------------------------------------------
            sev_order = {
                "critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4
            }
            counts = {s: 0 for s in sev_order}

            for raw in all_raw_findings:
                sev_str = str(raw.get("severity", "informational")).lower()
                stat_str = str(raw.get("status", "pass")).lower()

                try:
                    sev_enum = Severity(sev_str)
                except ValueError:
                    sev_enum = Severity.INFORMATIONAL
                try:
                    stat_enum = FindingStatus(stat_str)
                except ValueError:
                    stat_enum = FindingStatus.WARNING

                finding = Finding(
                    scan_id=scan_id,
                    finding_id=raw.get("finding_id", "UNK-000"),
                    check_name=raw.get("check_name", "Unknown Check"),
                    category=raw.get("category", "General"),
                    severity=sev_enum,
                    status=stat_enum,
                    description=raw.get("description", ""),
                    evidence=raw.get("evidence", ""),
                    impact=raw.get("impact", ""),
                    recommendation=raw.get("recommendation", ""),
                    reference_url=raw.get("reference_url", ""),
                )
                db.session.add(finding)
                counts[sev_str] = counts.get(sev_str, 0) + 1

            # ----------------------------------------------------------
            # 8. Compute score and update scan record
            # ----------------------------------------------------------
            score = calculate_score(all_raw_findings)

            scan.security_score = score
            scan.total_findings = len(all_raw_findings)
            scan.critical_count = counts.get("critical", 0)
            scan.high_count = counts.get("high", 0)
            scan.medium_count = counts.get("medium", 0)
            scan.low_count = counts.get("low", 0)
            scan.informational_count = counts.get("informational", 0)
            scan.status = ScanStatus.COMPLETED
            scan.scan_completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            db.session.commit()

            logger.info(
                "Scan %s completed. Score=%s Findings=%s",
                scan_id, score, len(all_raw_findings)
            )

        except Exception as exc:
            logger.exception("Scan %s failed with unexpected error: %s", scan_id, exc)
            try:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(exc)[:500]
                scan.scan_completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                db.session.commit()
            except Exception:
                db.session.rollback()
        finally:
            try:
                db.session.remove()
            except Exception:
                pass
