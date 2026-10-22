"""
tests/test_cors.py — Unit tests for CORS configuration checks.
"""

import pytest
from scanner.cors import run_cors_checks


TEST_ORIGIN = "https://attacker.example.invalid"


def test_no_cors_headers():
    results = run_cors_checks({}, TEST_ORIGIN)
    assert len(results) == 1
    assert results[0].status == "pass"
    assert "absent" in results[0].evidence.lower()


def test_wildcard_with_credentials():
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    results = run_cors_checks(headers, TEST_ORIGIN)
    crs001 = [r for r in results if r.finding_id == "CRS-001"]
    assert len(crs001) >= 1
    assert crs001[0].severity == "high"
    assert crs001[0].status == "fail"


def test_wildcard_without_credentials():
    headers = {"Access-Control-Allow-Origin": "*"}
    results = run_cors_checks(headers, TEST_ORIGIN)
    # Should warn but not be high-severity fail
    sev_vals = {r.severity for r in results}
    assert "high" not in sev_vals or all(
        r.severity != "high" for r in results if r.finding_id == "CRS-001"
    )


def test_reflected_origin_with_credentials():
    headers = {
        "Access-Control-Allow-Origin": TEST_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
    }
    results = run_cors_checks(headers, TEST_ORIGIN)
    crs002 = [r for r in results if r.finding_id == "CRS-002"]
    assert len(crs002) >= 1
    assert crs002[0].severity == "high"


def test_reflected_origin_without_credentials():
    headers = {
        "Access-Control-Allow-Origin": TEST_ORIGIN,
        "Access-Control-Allow-Credentials": "false",
    }
    results = run_cors_checks(headers, TEST_ORIGIN)
    crs002 = [r for r in results if r.finding_id == "CRS-002"]
    assert len(crs002) >= 1
    assert crs002[0].severity == "medium"  # Lower risk without credentials


def test_broad_method_allowance():
    headers = {
        "Access-Control-Allow-Origin": "https://trusted.example.com",
        "Access-Control-Allow-Methods": "GET, POST, DELETE, PUT",
    }
    results = run_cors_checks(headers, TEST_ORIGIN)
    crs003 = [r for r in results if r.finding_id == "CRS-003"]
    assert len(crs003) >= 1
    assert "DELETE" in crs003[0].evidence or "PUT" in crs003[0].evidence


def test_missing_vary_origin():
    headers = {
        "Access-Control-Allow-Origin": "https://trusted.example.com",
    }
    results = run_cors_checks(headers, TEST_ORIGIN)
    crs004 = [r for r in results if r.finding_id == "CRS-004"]
    assert len(crs004) >= 1


def test_vary_origin_present():
    headers = {
        "Access-Control-Allow-Origin": "https://trusted.example.com",
        "Vary": "Origin, Accept-Encoding",
    }
    results = run_cors_checks(headers, TEST_ORIGIN)
    crs004 = [r for r in results if r.finding_id == "CRS-004"]
    assert len(crs004) == 0


def test_safe_cors_configuration():
    headers = {
        "Access-Control-Allow-Origin": "https://trusted.example.com",
        "Vary": "Origin",
        "Access-Control-Allow-Methods": "GET, POST",
    }
    results = run_cors_checks(headers, TEST_ORIGIN)
    failures = [r for r in results if r.status == "fail"]
    assert len(failures) == 0
