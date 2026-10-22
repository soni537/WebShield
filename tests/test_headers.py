"""
tests/test_headers.py — Unit tests for HTTP security header checks.
"""

import pytest
from scanner.headers import (
    run_header_checks,
    check_csp,
    check_hsts,
    check_x_content_type,
    check_x_frame_options,
    check_referrer_policy,
    check_permissions_policy,
    check_server_disclosure,
)


# ---------------------------------------------------------------------------
# Content-Security-Policy
# ---------------------------------------------------------------------------

def test_csp_missing():
    f = check_csp({}, "https")
    assert f.status == "fail"
    assert f.severity == "high"
    assert "absent" in f.description.lower()


def test_csp_present_clean():
    f = check_csp({"Content-Security-Policy": "default-src 'self'"}, "https")
    assert f.status == "pass"
    assert f.severity == "informational"


def test_csp_unsafe_inline():
    f = check_csp({"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"}, "https")
    assert f.status == "warning"
    assert f.severity == "medium"
    assert "unsafe-inline" in f.impact


def test_csp_unsafe_eval():
    f = check_csp({"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-eval'"}, "https")
    assert f.status == "warning"
    assert "unsafe-eval" in f.impact


# ---------------------------------------------------------------------------
# HSTS
# ---------------------------------------------------------------------------

def test_hsts_missing_on_https():
    f = check_hsts({}, "https")
    assert f.status == "fail"
    assert f.severity == "high"


def test_hsts_present_valid():
    f = check_hsts({"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}, "https")
    assert f.status == "pass"


def test_hsts_low_max_age():
    f = check_hsts({"Strict-Transport-Security": "max-age=86400"}, "https")
    assert f.status == "warning"
    assert f.severity == "low"


def test_hsts_skipped_on_http():
    f = check_hsts({}, "http")
    assert f.status == "warning"
    assert "http" in f.description.lower()


def test_hsts_missing_max_age():
    f = check_hsts({"Strict-Transport-Security": "includeSubDomains"}, "https")
    assert f.status == "warning"
    assert f.severity == "medium"


# ---------------------------------------------------------------------------
# X-Content-Type-Options
# ---------------------------------------------------------------------------

def test_xcto_missing():
    f = check_x_content_type({}, "https")
    assert f.status == "fail"
    assert f.severity == "medium"


def test_xcto_nosniff():
    f = check_x_content_type({"X-Content-Type-Options": "nosniff"}, "https")
    assert f.status == "pass"


def test_xcto_wrong_value():
    f = check_x_content_type({"X-Content-Type-Options": "sniff"}, "https")
    assert f.status == "warning"


# ---------------------------------------------------------------------------
# X-Frame-Options
# ---------------------------------------------------------------------------

def test_xframe_missing():
    f = check_x_frame_options({}, "https")
    assert f.status == "fail"
    assert f.severity == "medium"


def test_xframe_deny():
    f = check_x_frame_options({"X-Frame-Options": "DENY"}, "https")
    assert f.status == "pass"


def test_xframe_sameorigin():
    f = check_x_frame_options({"X-Frame-Options": "SAMEORIGIN"}, "https")
    assert f.status == "pass"


def test_xframe_csp_supersedes():
    headers = {
        "Content-Security-Policy": "frame-ancestors 'self'",
    }
    f = check_x_frame_options(headers, "https")
    assert f.status == "pass"
    assert "frame-ancestors" in f.evidence.lower()


# ---------------------------------------------------------------------------
# Referrer-Policy
# ---------------------------------------------------------------------------

def test_referrer_missing():
    f = check_referrer_policy({}, "https")
    assert f.status == "fail"
    assert f.severity == "low"


def test_referrer_safe_value():
    f = check_referrer_policy({"Referrer-Policy": "strict-origin-when-cross-origin"}, "https")
    assert f.status == "pass"


def test_referrer_weak_value():
    f = check_referrer_policy({"Referrer-Policy": "unsafe-url"}, "https")
    assert f.status == "warning"


# ---------------------------------------------------------------------------
# Permissions-Policy
# ---------------------------------------------------------------------------

def test_permissions_missing():
    f = check_permissions_policy({}, "https")
    assert f.status == "warning"
    assert f.severity == "informational"


def test_permissions_present():
    f = check_permissions_policy({"Permissions-Policy": "camera=(), microphone=()"}, "https")
    assert f.status == "pass"


# ---------------------------------------------------------------------------
# Server Disclosure
# ---------------------------------------------------------------------------

def test_server_disclosure_present():
    f = check_server_disclosure({"Server": "Apache/2.4.51"}, "https")
    assert f.status == "warning"
    assert "Apache/2.4.51" in f.evidence


def test_server_no_disclosure():
    f = check_server_disclosure({}, "https")
    assert f.status == "pass"


# ---------------------------------------------------------------------------
# run_header_checks integration
# ---------------------------------------------------------------------------

def test_run_header_checks_returns_all():
    results = run_header_checks({}, "https")
    # Should have one finding per check function (7)
    assert len(results) == 7


def test_run_header_checks_all_present():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
    }
    results = run_header_checks(headers, "https")
    passes = [r for r in results if r.status == "pass"]
    # At least 5 should pass
    assert len(passes) >= 5
