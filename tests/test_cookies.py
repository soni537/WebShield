"""
tests/test_cookies.py — Unit tests for cookie security checks.
"""

import pytest
from scanner.cookies import run_cookie_checks


def test_no_cookies():
    results = run_cookie_checks([], "https")
    assert len(results) == 1
    assert results[0].status == "pass"
    assert "No Set-Cookie" in results[0].description


def test_cookie_missing_all_flags():
    cookies = ["sessionid=abc123; Path=/"]
    results = run_cookie_checks(cookies, "https")
    # Should have findings for Secure, HttpOnly, SameSite
    fids = {r.finding_id for r in results}
    assert "CKY-001" in fids
    assert "CKY-002" in fids
    assert "CKY-003" in fids


def test_cookie_secure_flag_on_https():
    cookies = ["session=xyz; Secure; HttpOnly; SameSite=Lax; Path=/"]
    results = run_cookie_checks(cookies, "https")
    # No findings about those attributes (should not contain CKY-001 fail)
    fail_findings = [r for r in results if r.status == "fail"]
    assert not fail_findings


def test_cookie_missing_secure_on_https():
    cookies = ["session=xyz; HttpOnly; SameSite=Strict; Path=/"]
    results = run_cookie_checks(cookies, "https")
    secure_findings = [r for r in results if r.finding_id == "CKY-001"]
    assert len(secure_findings) >= 1
    assert secure_findings[0].severity == "medium"


def test_cookie_no_httponly_session():
    cookies = ["sessiontoken=abc; Secure; SameSite=Lax; Path=/"]
    results = run_cookie_checks(cookies, "https")
    httponly_findings = [r for r in results if r.finding_id == "CKY-002"]
    assert len(httponly_findings) >= 1
    # Session-like cookie → medium severity
    assert httponly_findings[0].severity == "medium"


def test_cookie_samesite_none_without_secure():
    cookies = ["tracker=xyz; SameSite=None; Path=/"]
    results = run_cookie_checks(cookies, "https")
    samesite_findings = [r for r in results if r.finding_id == "CKY-003" and "None" in r.check_name]
    assert len(samesite_findings) >= 1
    assert samesite_findings[0].status == "fail"


def test_cookie_http_no_secure_flag_expected():
    """On HTTP, missing Secure flag should not trigger CKY-001 (Secure only meaningful over HTTPS)."""
    cookies = ["session=abc; HttpOnly; SameSite=Lax"]
    results = run_cookie_checks(cookies, "http")
    cky001 = [r for r in results if r.finding_id == "CKY-001"]
    # Should NOT find CKY-001 on http
    assert len(cky001) == 0


def test_multiple_cookies():
    cookies = [
        "session=abc; Secure; HttpOnly; SameSite=Strict",
        "analytics=xyz; Path=/",
    ]
    results = run_cookie_checks(cookies, "https")
    # analytics cookie has no flags — should report issues
    finding_ids = [r.finding_id for r in results]
    assert "CKY-002" in finding_ids or "CKY-003" in finding_ids
