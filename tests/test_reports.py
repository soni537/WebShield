"""
tests/test_reports.py — Unit tests for report generation (CSV, JSON, PDF).
"""

import json
import os
import pytest
from unittest.mock import MagicMock


def _make_mock_scan():
    import datetime
    scan = MagicMock()
    scan.id = 1
    scan.target_url = "https://example.com"
    scan.normalized_hostname = "example.com"
    scan.scan_started_at = datetime.datetime(2024, 1, 15, 10, 30, 0)
    scan.scan_completed_at = datetime.datetime(2024, 1, 15, 10, 30, 45)
    scan.security_score = 72
    scan.total_findings = 3
    scan.critical_count = 0
    scan.high_count = 1
    scan.medium_count = 1
    scan.low_count = 1
    scan.informational_count = 0
    scan.duration_seconds = 45.0
    return scan


def _make_mock_finding(finding_id, severity, status, check_name):
    f = MagicMock()
    f.finding_id = finding_id
    f.check_name = check_name
    f.category = "HTTP Security Headers"
    f.severity = MagicMock()
    f.severity.value = severity
    f.status = MagicMock()
    f.status.value = status
    f.description = f"Test description for {check_name}"
    f.evidence = "Header not present"
    f.impact = "Test impact"
    f.recommendation = "Add the header"
    f.reference_url = "https://developer.mozilla.org"
    return f


@pytest.fixture
def mock_scan():
    return _make_mock_scan()


@pytest.fixture
def mock_findings():
    return [
        _make_mock_finding("HDR-001", "high", "fail", "Content-Security-Policy"),
        _make_mock_finding("HDR-003", "medium", "fail", "X-Content-Type-Options"),
        _make_mock_finding("HDR-005", "low", "warning", "Referrer-Policy"),
    ]


def test_generate_json(mock_scan, mock_findings, tmp_path, monkeypatch):
    """JSON report should be valid JSON with correct structure."""
    import services.report_service as svc
    monkeypatch.setattr(svc, "_OUTPUT_DIR", tmp_path)

    path, mime, filename = svc.generate_json(mock_scan, mock_findings)

    assert os.path.exists(path)
    assert mime == "application/json"
    assert filename.endswith(".json")

    with open(path) as f:
        data = json.load(f)

    assert "scan" in data
    assert "findings" in data
    assert len(data["findings"]) == 3
    assert data["scan"]["target_url"] == "https://example.com"
    assert data["scan"]["security_score"] == 72


def test_generate_csv(mock_scan, mock_findings, tmp_path, monkeypatch):
    """CSV report should have a header row and 3 data rows."""
    import services.report_service as svc
    monkeypatch.setattr(svc, "_OUTPUT_DIR", tmp_path)

    path, mime, filename = svc.generate_csv(mock_scan, mock_findings)

    assert os.path.exists(path)
    assert mime == "text/csv"
    assert filename.endswith(".csv")

    with open(path, encoding="utf-8") as f:
        lines = [l for l in f.readlines() if not l.startswith("#")]

    # Header + 3 data rows
    assert len(lines) >= 4  # 1 header + 3 findings


def test_generate_pdf(mock_scan, mock_findings, tmp_path, monkeypatch):
    """PDF report should be a non-empty binary file."""
    import services.report_service as svc
    monkeypatch.setattr(svc, "_OUTPUT_DIR", tmp_path)

    path, mime, filename = svc.generate_pdf(mock_scan, mock_findings)

    assert os.path.exists(path)
    assert mime == "application/pdf"
    assert filename.endswith(".pdf")

    size = os.path.getsize(path)
    assert size > 1024  # At least 1KB — real PDF content


def test_generate_report_dispatch(mock_scan, mock_findings, tmp_path, monkeypatch):
    """generate_report() should dispatch to the correct generator."""
    import services.report_service as svc
    monkeypatch.setattr(svc, "_OUTPUT_DIR", tmp_path)

    for fmt in ("json", "csv", "pdf"):
        path, mime, filename = svc.generate_report(mock_scan, mock_findings, fmt)
        assert os.path.exists(path)


def test_generate_report_invalid_format(mock_scan, mock_findings):
    from services.report_service import generate_report
    with pytest.raises(ValueError):
        generate_report(mock_scan, mock_findings, "xml")


def test_json_report_empty_findings(mock_scan, tmp_path, monkeypatch):
    import services.report_service as svc
    monkeypatch.setattr(svc, "_OUTPUT_DIR", tmp_path)

    path, _, _ = svc.generate_json(mock_scan, [])
    with open(path) as f:
        data = json.load(f)
    assert data["findings"] == []
