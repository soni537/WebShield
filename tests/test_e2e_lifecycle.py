"""
tests/test_e2e_lifecycle.py — End-to-end scan lifecycle validation.

Spawns an isolated local test HTTP server that emits controlled security headers,
cookies, and CORS responses. Executes a full scan, verifies database persistence of
real findings, and validates dashboard, scan results, scan status, history, and report exports.
"""

import http.server
import json
import socket
import threading
from typing import Generator
import pytest

from models import Scan, Finding, ScanStatus
from scanner.task_runner import wait_for_all_scans


class ControlledSecurityHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP server emitting controlled headers, cookies, and CORS configurations
    for deterministic scanner validation.
    """

    def do_HEAD(self):
        self.send_response(200)
        self._send_security_headers()
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self._send_security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        html = (
            b"<!DOCTYPE html><html><head><title>WebShield Mock Target</title></head>"
            b"<body><h1>Mock Vulnerable App</h1>"
            b"<form action='/login' method='POST'>"
            b"<input type='text' name='username'><input type='password' name='password'>"
            b"<button type='submit'>Login</button></form></body></html>"
        )
        self.wfile.write(html)

    def do_OPTIONS(self):
        self.send_response(204)
        origin = self.headers.get("Origin", "")
        if origin:
            # Emulate misconfigured CORS reflecting origin
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        self.end_headers()

    def _send_security_headers(self):
        # Controlled headers:
        # - Missing Strict-Transport-Security
        # - Weak CSP with unsafe-inline
        # - Missing X-Frame-Options
        # - Insecure Cookie (missing Secure and HttpOnly)
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Server", "Apache/2.4.52 (Ubuntu)")
        self.send_header("Set-Cookie", "session_id=insecure_token_123; Path=/")

    def log_message(self, format, *args):
        # Silence HTTP server logs during test run
        pass


@pytest.fixture(scope="module")
def mock_target_server() -> Generator[str, None, None]:
    """Starts a local HTTP server on an ephemeral port and returns its base URL."""
    # Find a free port
    with socket.socket(socket.AF_SOCKET if hasattr(socket, "AF_SOCKET") else socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = http.server.HTTPServer(("127.0.0.1", port), ControlledSecurityHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    yield base_url

    server.shutdown()
    server.server_close()


def test_complete_scan_lifecycle(app, client, mock_target_server):
    """
    Test the complete end-to-end scan lifecycle:
    1. Scan initiation via API
    2. Synchronous/managed task execution
    3. Findings persisted in database
    4. Scan status and findings API
    5. Web UI views (dashboard, results, history, compare)
    6. Report generation (JSON, CSV, PDF)
    """
    app.config["SCANNER_ALLOW_PRIVATE_IPS"] = True
    app.config["SYNC_SCANS"] = True

    with app.app_context():
        from extensions import db

        # 1. Initiate scan via API
        resp = client.post("/scans/api/scan", json={"url": mock_target_server})
        assert resp.status_code == 202
        data = json.loads(resp.data)
        assert "scan_id" in data
        scan_id = data["scan_id"]

        # 2. Verify scan completed in database
        scan = db.session.get(Scan, scan_id)
        assert scan is not None
        assert scan.status == ScanStatus.COMPLETED
        assert scan.security_score is not None
        assert 0 <= scan.security_score <= 100
        assert scan.total_findings > 0

        # 3. Verify real findings are recorded in database
        findings = Finding.query.filter_by(scan_id=scan_id).all()
        assert len(findings) == scan.total_findings
        finding_ids = [f.finding_id for f in findings]

        # Check expected findings triggered by ControlledSecurityHandler
        # E.g., CKY-002 (missing HttpOnly), CKY-001 (missing Secure on HTTP or observed),
        # HDR-001 (unsafe-inline CSP), HDR-004 (missing X-Frame-Options), HDR-008 (server banner)
        assert any("CKY" in fid for fid in finding_ids)
        assert any("HDR" in fid for fid in finding_ids)

        # 4. Check API scan status endpoint
        status_resp = client.get(f"/scans/api/scan/{scan_id}")
        assert status_resp.status_code == 200
        status_data = json.loads(status_resp.data)
        assert status_data["status"] == "completed"
        assert status_data["security_score"] == scan.security_score

        # 5. Check API scan findings endpoint
        findings_resp = client.get(f"/scans/api/scan/{scan_id}/findings")
        assert findings_resp.status_code == 200
        findings_data = json.loads(findings_resp.data)
        assert len(findings_data["findings"]) == len(findings)

        # 6. Check Dashboard UI
        dash_resp = client.get("/dashboard")
        assert dash_resp.status_code == 200
        assert b"WebShield" in dash_resp.data
        assert str(scan.security_score).encode() in dash_resp.data

        # 7. Check Scan Results UI Page
        results_resp = client.get(f"/scans/{scan_id}")
        assert results_resp.status_code == 200
        assert b"Score" in results_resp.data
        assert b"Findings" in results_resp.data

        # 8. Check Scan History UI and API
        history_resp = client.get("/history")
        assert history_resp.status_code == 200
        assert b"127.0.0.1" in history_resp.data or b"localhost" in history_resp.data or b"Mock" in history_resp.data

        api_hist_resp = client.get("/scans/api/history")
        assert api_hist_resp.status_code == 200
        hist_data = json.loads(api_hist_resp.data)
        assert hist_data["total"] >= 1

        # 9. Check Report HTML View
        report_resp = client.get(f"/reports/{scan_id}")
        assert report_resp.status_code == 200
        assert b"Executive Summary" in report_resp.data or b"Report" in report_resp.data

        # 10. Check Report Exports
        # JSON export
        json_export = client.get(f"/reports/{scan_id}/export/json")
        assert json_export.status_code == 200
        assert json_export.content_type == "application/json"
        json_body = json.loads(json_export.data)
        assert "scan" in json_body
        assert "findings" in json_body

        # CSV export
        csv_export = client.get(f"/reports/{scan_id}/export/csv")
        assert csv_export.status_code == 200
        assert "text/csv" in csv_export.content_type
        assert b"finding_id" in csv_export.data

        # PDF export
        pdf_export = client.get(f"/reports/{scan_id}/export/pdf")
        assert pdf_export.status_code == 200
        assert pdf_export.content_type == "application/pdf"
        assert pdf_export.data.startswith(b"%PDF")


def test_web_form_scan_and_comparison(app, client, mock_target_server):
    """
    Test initiating scan from the web form POST, and comparing multiple scans.
    """
    app.config["SCANNER_ALLOW_PRIVATE_IPS"] = True
    app.config["SYNC_SCANS"] = True

    # 1. Post form to /scans/new
    resp = client.post("/scans/new", data={"url": mock_target_server}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Scan Results" in resp.data or b"Score" in resp.data

    # 2. Run a second scan so we have 2 scans of the same host to compare
    resp2 = client.post("/scans/new", data={"url": mock_target_server}, follow_redirects=True)
    assert resp2.status_code == 200

    with app.app_context():
        from models import Scan
        scans = Scan.query.order_by(Scan.id.desc()).limit(2).all()
        assert len(scans) == 2
        scan_newer, scan_older = scans[0], scans[1]

        # 3. Test compare page
        compare_resp = client.get(f"/scans/{scan_newer.id}/compare?other={scan_older.id}")
        assert compare_resp.status_code == 200
        assert b"Comparison" in compare_resp.data or b"Compare" in compare_resp.data


def test_async_background_thread_lifecycle(app, client, mock_target_server):
    """
    Test that background thread execution finishes cleanly and wait_for_all_scans
    ensures no database teardown exceptions occur.
    """
    app.config["SCANNER_ALLOW_PRIVATE_IPS"] = True
    app.config["SYNC_SCANS"] = False  # Asynchronous thread mode

    resp = client.post("/scans/api/scan", json={"url": mock_target_server})
    assert resp.status_code == 202
    data = json.loads(resp.data)
    scan_id = data["scan_id"]

    # Wait for the background thread to finish cleanly
    wait_for_all_scans(timeout=10.0)

    with app.app_context():
        from extensions import db
        scan = db.session.get(Scan, scan_id)
        assert scan is not None
        assert scan.status == ScanStatus.COMPLETED
        assert scan.total_findings > 0

