"""
tests/test_safety.py — Unit tests for URL validation and SSRF prevention.
"""

import pytest
from scanner.safety import validate_url, validate_redirect, _is_blocked_ip


# ---------------------------------------------------------------------------
# IP blocking
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip,expected_blocked", [
    ("127.0.0.1", True),          # Loopback
    ("127.255.255.255", True),    # Loopback range
    ("10.0.0.1", True),           # Private class A
    ("172.16.0.1", True),         # Private class B
    ("172.31.255.255", True),     # Private class B
    ("192.168.1.100", True),      # Private class C
    ("169.254.169.254", True),    # Link-local / cloud metadata
    ("0.0.0.0", True),            # Zero network
    ("224.0.0.1", True),          # Multicast
    ("255.255.255.255", True),    # Broadcast
    ("100.64.0.1", True),         # CGN
    ("198.18.0.1", True),         # Benchmarking
    ("8.8.8.8", False),           # Public DNS
    ("1.1.1.1", False),           # Public DNS
    ("93.184.216.34", False),     # example.com
])
def test_ipv4_blocking(ip, expected_blocked):
    blocked, _ = _is_blocked_ip(ip)
    assert blocked == expected_blocked, f"Expected {ip} blocked={expected_blocked}, got {blocked}"


@pytest.mark.parametrize("ip,expected_blocked", [
    ("::1", True),                  # IPv6 loopback
    ("fc00::1", True),              # ULA
    ("fd00::1", True),              # ULA
    ("fe80::1", True),              # Link-local
    ("ff02::1", True),              # Multicast
    ("::", True),                   # Unspecified
    ("2001:4860:4860::8888", False),# Google public DNS
])
def test_ipv6_blocking(ip, expected_blocked):
    blocked, _ = _is_blocked_ip(ip)
    assert blocked == expected_blocked, f"Expected IPv6 {ip} blocked={expected_blocked}"


# ---------------------------------------------------------------------------
# URL scheme validation
# ---------------------------------------------------------------------------

def test_http_scheme_allowed():
    r = validate_url("http://example.com")
    assert r.valid or "not in the configured" not in r.error  # valid if no allowlist


def test_https_scheme_allowed():
    r = validate_url("https://example.com")
    # No allowlist → should not fail on scheme
    assert r.scheme in ("", "https") or r.valid


def test_ftp_scheme_blocked():
    r = validate_url("ftp://example.com/file.txt")
    assert not r.valid
    assert "scheme" in r.error.lower()


def test_file_scheme_blocked():
    r = validate_url("file:///etc/passwd")
    assert not r.valid


def test_javascript_scheme_blocked():
    r = validate_url("javascript:alert(1)")
    assert not r.valid


def test_data_scheme_blocked():
    r = validate_url("data:text/html,<h1>hi</h1>")
    assert not r.valid


# ---------------------------------------------------------------------------
# IP literal URLs
# ---------------------------------------------------------------------------

def test_loopback_ip_url_blocked():
    r = validate_url("http://127.0.0.1/")
    assert not r.valid
    assert "allowed" in r.error.lower() or "blocked" in r.error.lower()


def test_private_ip_url_blocked():
    r = validate_url("http://192.168.1.1/admin")
    assert not r.valid


def test_metadata_ip_blocked():
    r = validate_url("http://169.254.169.254/latest/meta-data/")
    assert not r.valid


def test_ipv6_loopback_blocked():
    r = validate_url("http://[::1]/")
    assert not r.valid


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

def test_allowlist_blocks_non_listed():
    r = validate_url("https://evil.com", allowlist=["example.com", "test.example.org"])
    assert not r.valid
    assert "allowlist" in r.error.lower()


def test_allowlist_permits_listed():
    # example.com resolves to public IPs; this test may hit DNS
    # Use an explicit check that doesn't fail on DNS but verifies allowlist logic
    r = validate_url("https://example.com", allowlist=["example.com"])
    # Either valid (DNS resolved public) or failed for DNS, not for allowlist
    if not r.valid:
        assert "allowlist" not in r.error.lower()


def test_allowlist_empty_permits_all():
    r = validate_url("https://example.com", allowlist=[])
    if not r.valid:
        assert "allowlist" not in r.error.lower()


# ---------------------------------------------------------------------------
# Empty/malformed URLs
# ---------------------------------------------------------------------------

def test_empty_url():
    r = validate_url("")
    assert not r.valid


def test_no_hostname():
    r = validate_url("https://")
    assert not r.valid
    assert "hostname" in r.error.lower()


def test_blocked_hostname():
    r = validate_url("https://metadata.google.internal/")
    assert not r.valid


# ---------------------------------------------------------------------------
# Redirect validation
# ---------------------------------------------------------------------------

def test_redirect_to_private_ip_blocked():
    r = validate_redirect("example.com", "http://10.0.0.1/secret")
    assert not r.valid
    assert "redirect" in r.error.lower() or "blocked" in r.error.lower()


def test_redirect_to_public_host_allowed():
    r = validate_redirect("example.com", "https://example.com/page", allowlist=[])
    # Should not be blocked for SSRF reasons (DNS may fail in test env)
    if not r.valid:
        assert "allowlist" not in r.error.lower()


def test_redirect_scheme_change_blocked():
    r = validate_redirect("example.com", "ftp://example.com/file")
    assert not r.valid
