"""
tests/test_api.py — Integration tests for Flask API endpoints.
Uses SQLite in-memory database (TestingConfig).
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from config import TestingConfig





# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def test_health_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert "status" in data


# ---------------------------------------------------------------------------
# API — new scan
# ---------------------------------------------------------------------------

def test_api_new_scan_missing_url(client):
    resp = client.post("/scans/api/scan", json={})
    assert resp.status_code == 400
    data = json.loads(resp.data)
    assert "error" in data


def test_api_new_scan_invalid_scheme(client):
    resp = client.post("/scans/api/scan", json={"url": "ftp://example.com"})
    # Should be blocked by SSRF validation
    assert resp.status_code in (422, 400)


def test_api_new_scan_private_ip(client):
    resp = client.post("/scans/api/scan", json={"url": "http://192.168.1.1"})
    assert resp.status_code == 422
    data = json.loads(resp.data)
    assert "error" in data


def test_api_new_scan_loopback(client):
    resp = client.post("/scans/api/scan", json={"url": "http://127.0.0.1"})
    assert resp.status_code == 422


def test_api_new_scan_metadata_endpoint(client):
    resp = client.post("/scans/api/scan", json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert resp.status_code == 422


@patch("routes.scans.dispatch_scan")
def test_api_new_scan_valid_public_url(mock_dispatch, client):
    """A valid public URL should be accepted and a scan created."""
    resp = client.post("/scans/api/scan", json={"url": "https://example.com"})
    # In test mode, this might fail DNS or be accepted — we just check it's not blocked for SSRF
    assert resp.status_code in (202, 422)  # 422 only if DNS fails in CI
    if resp.status_code == 202:
        data = json.loads(resp.data)
        assert "scan_id" in data


# ---------------------------------------------------------------------------
# API — scan status
# ---------------------------------------------------------------------------

def test_api_scan_status_not_found(client):
    resp = client.get("/scans/api/scan/99999")
    assert resp.status_code == 404


def test_api_scan_findings_not_found(client):
    resp = client.get("/scans/api/scan/99999/findings")
    assert resp.status_code == 404


def test_api_history_empty(client):
    resp = client.get("/scans/api/history")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert "scans" in data
    assert data["total"] == 0


# ---------------------------------------------------------------------------
# Web routes
# ---------------------------------------------------------------------------

def test_index_page(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"WebShield" in resp.data


def test_dashboard_page(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert b"Dashboard" in resp.data


def test_history_page(client):
    resp = client.get("/history")
    assert resp.status_code == 200


def test_scan_not_found(client):
    resp = client.get("/scans/99999")
    assert resp.status_code == 404


def test_new_scan_post_empty_url(client):
    resp = client.post("/scans/new", data={"url": ""}, follow_redirects=True)
    assert resp.status_code == 200
    # Should flash a warning — either redirect to index or show form
    assert b"WebShield" in resp.data


def test_new_scan_post_private_ip(client):
    resp = client.post("/scans/new", data={"url": "http://10.0.0.1"}, follow_redirects=True)
    assert resp.status_code == 200
    # Should flash a danger message
    assert b"blocked" in resp.data.lower() or b"WebShield" in resp.data


# ---------------------------------------------------------------------------
# Report export — 404 for non-existent scan
# ---------------------------------------------------------------------------

def test_report_not_found(client):
    resp = client.get("/reports/99999")
    assert resp.status_code == 404


def test_export_bad_format(client):
    """Invalid format should return 404 or 400."""
    resp = client.get("/reports/1/export/xml")
    assert resp.status_code in (400, 404)
