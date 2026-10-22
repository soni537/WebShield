"""
scanner/headers.py — HTTP Security Header checks.

Checks:
  HDR-001  Content-Security-Policy       (High if missing)
  HDR-002  Strict-Transport-Security     (High if missing on HTTPS)
  HDR-003  X-Content-Type-Options        (Medium if missing)
  HDR-004  X-Frame-Options               (Medium if missing)
  HDR-005  Referrer-Policy               (Low if missing)
  HDR-006  Permissions-Policy            (Informational if missing)
  HDR-007  X-Powered-By / Server leak    (Informational)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FindingData:
    finding_id: str
    check_name: str
    category: str = "HTTP Security Headers"
    severity: str = "informational"
    status: str = "pass"
    description: str = ""
    evidence: str = ""
    impact: str = ""
    recommendation: str = ""
    reference_url: str = ""


def _present(headers: dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def check_csp(headers: dict[str, str], scheme: str) -> FindingData:
    val = _present(headers, "Content-Security-Policy")
    f = FindingData(
        finding_id="HDR-001",
        check_name="Content-Security-Policy",
        reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    )
    if val is None:
        f.severity = "high"
        f.status = "fail"
        f.description = "The Content-Security-Policy header is absent."
        f.evidence = "Header not present in HTTP response."
        f.impact = (
            "Without CSP, the browser has no policy-level protection against "
            "cross-site scripting (XSS) or content-injection attacks."
        )
        f.recommendation = (
            "Add a Content-Security-Policy header. Start with "
            "\"Content-Security-Policy: default-src 'self'\" and refine "
            "directives to match your application's resource requirements."
        )
    else:
        f.status = "pass"
        f.description = "Content-Security-Policy header is present."
        f.evidence = f"Content-Security-Policy: {val[:300]}"
        # Check for unsafe directives
        warnings = []
        if "unsafe-inline" in val:
            warnings.append("'unsafe-inline' weakens XSS protection")
        if "unsafe-eval" in val:
            warnings.append("'unsafe-eval' allows arbitrary JS execution")
        if "default-src *" in val or "script-src *" in val:
            warnings.append("wildcard source allows any origin")
        if warnings:
            f.severity = "medium"
            f.status = "warning"
            f.description = "Content-Security-Policy header is present but contains potentially weak directives."
            f.impact = "; ".join(warnings)
            f.recommendation = (
                "Review and tighten your CSP directives. Remove 'unsafe-inline', "
                "'unsafe-eval', and wildcard sources where possible."
            )
        else:
            f.severity = "informational"
    return f


def check_hsts(headers: dict[str, str], scheme: str) -> FindingData:
    val = _present(headers, "Strict-Transport-Security")
    f = FindingData(
        finding_id="HDR-002",
        check_name="Strict-Transport-Security (HSTS)",
        reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    )
    if scheme != "https":
        f.severity = "informational"
        f.status = "warning"
        f.description = "HSTS check skipped: target was scanned over HTTP."
        f.evidence = f"Request scheme: {scheme}"
        f.recommendation = "Enable HTTPS and then add an HSTS header."
        return f

    if val is None:
        f.severity = "high"
        f.status = "fail"
        f.description = "Strict-Transport-Security (HSTS) header is absent on an HTTPS response."
        f.evidence = "Header not present in HTTPS response."
        f.impact = (
            "Without HSTS, browsers may connect over insecure HTTP if tricked. "
            "This exposes users to SSL-stripping attacks."
        )
        f.recommendation = (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        )
    else:
        f.status = "pass"
        f.severity = "informational"
        f.description = "HSTS header is present on the HTTPS response."
        f.evidence = f"Strict-Transport-Security: {val}"
        # Validate max-age
        import re
        match = re.search(r"max-age\s*=\s*(\d+)", val, re.IGNORECASE)
        if match:
            max_age = int(match.group(1))
            if max_age < 31536000:
                f.severity = "low"
                f.status = "warning"
                f.description = "HSTS max-age is set but is below the recommended minimum of 31536000 (1 year)."
                f.recommendation = "Increase max-age to at least 31536000."
        else:
            f.severity = "medium"
            f.status = "warning"
            f.description = "HSTS header is present but max-age directive is missing or malformed."
            f.recommendation = "Ensure the HSTS header includes a valid max-age directive."
    return f


def check_x_content_type(headers: dict[str, str], scheme: str) -> FindingData:
    val = _present(headers, "X-Content-Type-Options")
    f = FindingData(
        finding_id="HDR-003",
        check_name="X-Content-Type-Options",
        reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    )
    if val is None:
        f.severity = "medium"
        f.status = "fail"
        f.description = "X-Content-Type-Options header is absent."
        f.evidence = "Header not present in HTTP response."
        f.impact = (
            "Without this header, browsers may MIME-sniff responses and execute "
            "content as a different type than declared, potentially enabling XSS."
        )
        f.recommendation = 'Add: X-Content-Type-Options: nosniff'
    elif val.strip().lower() != "nosniff":
        f.severity = "low"
        f.status = "warning"
        f.description = "X-Content-Type-Options is present but the value is not 'nosniff'."
        f.evidence = f"X-Content-Type-Options: {val}"
        f.recommendation = "Set the value to exactly 'nosniff'."
    else:
        f.severity = "informational"
        f.status = "pass"
        f.description = "X-Content-Type-Options: nosniff is correctly set."
        f.evidence = f"X-Content-Type-Options: {val}"
    return f


def check_x_frame_options(headers: dict[str, str], scheme: str) -> FindingData:
    val = _present(headers, "X-Frame-Options")
    csp = _present(headers, "Content-Security-Policy") or ""
    f = FindingData(
        finding_id="HDR-004",
        check_name="X-Frame-Options",
        reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    )

    # CSP frame-ancestors supersedes X-Frame-Options in modern browsers
    if "frame-ancestors" in csp.lower():
        f.severity = "informational"
        f.status = "pass"
        f.description = "Clickjacking protection is provided via CSP frame-ancestors directive."
        f.evidence = f"Content-Security-Policy contains frame-ancestors. X-Frame-Options: {val or 'absent'}"
        return f

    if val is None:
        f.severity = "medium"
        f.status = "fail"
        f.description = "X-Frame-Options header is absent and CSP frame-ancestors is not configured."
        f.evidence = "Neither X-Frame-Options nor CSP frame-ancestors found."
        f.impact = "The page may be embedded in iframes on attacker-controlled sites (clickjacking)."
        f.recommendation = (
            "Add X-Frame-Options: DENY or SAMEORIGIN. "
            "Alternatively, use CSP frame-ancestors 'self'."
        )
    elif val.upper() not in ("DENY", "SAMEORIGIN"):
        f.severity = "low"
        f.status = "warning"
        f.description = "X-Frame-Options is present but uses a non-standard or permissive value."
        f.evidence = f"X-Frame-Options: {val}"
        f.recommendation = "Use DENY or SAMEORIGIN."
    else:
        f.severity = "informational"
        f.status = "pass"
        f.description = "X-Frame-Options is correctly set."
        f.evidence = f"X-Frame-Options: {val}"
    return f


def check_referrer_policy(headers: dict[str, str], scheme: str) -> FindingData:
    val = _present(headers, "Referrer-Policy")
    SAFE_VALUES = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "same-origin",
    }
    f = FindingData(
        finding_id="HDR-005",
        check_name="Referrer-Policy",
        reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    )
    if val is None:
        f.severity = "low"
        f.status = "fail"
        f.description = "Referrer-Policy header is absent."
        f.evidence = "Header not present."
        f.impact = "The browser's default referrer policy may leak URL paths to third-party sites."
        f.recommendation = "Add: Referrer-Policy: strict-origin-when-cross-origin"
    elif val.lower().strip() in SAFE_VALUES:
        f.severity = "informational"
        f.status = "pass"
        f.description = "Referrer-Policy is configured with a safe value."
        f.evidence = f"Referrer-Policy: {val}"
    else:
        f.severity = "low"
        f.status = "warning"
        f.description = "Referrer-Policy is set but may allow referrer leakage."
        f.evidence = f"Referrer-Policy: {val}"
        f.recommendation = "Prefer strict-origin-when-cross-origin or no-referrer."
    return f


def check_permissions_policy(headers: dict[str, str], scheme: str) -> FindingData:
    val = _present(headers, "Permissions-Policy")
    f = FindingData(
        finding_id="HDR-006",
        check_name="Permissions-Policy",
        reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    )
    if val is None:
        f.severity = "informational"
        f.status = "warning"
        f.description = "Permissions-Policy header is absent."
        f.evidence = "Header not present."
        f.impact = "Without a Permissions-Policy, the browser may grant embedded content access to sensitive APIs."
        f.recommendation = (
            "Consider adding a Permissions-Policy header to restrict browser features "
            "such as camera, microphone, and geolocation."
        )
    else:
        f.severity = "informational"
        f.status = "pass"
        f.description = "Permissions-Policy header is present."
        f.evidence = f"Permissions-Policy: {val[:300]}"
    return f


def check_server_disclosure(headers: dict[str, str], scheme: str) -> FindingData:
    server = _present(headers, "Server")
    powered = _present(headers, "X-Powered-By")
    f = FindingData(
        finding_id="HDR-007",
        check_name="Server/Technology Disclosure",
        reference_url="https://owasp.org/www-project-web-security-testing-guide/",
    )
    disclosures = []
    if server:
        disclosures.append(f"Server: {server}")
    if powered:
        disclosures.append(f"X-Powered-By: {powered}")

    if disclosures:
        f.severity = "informational"
        f.status = "warning"
        f.description = "Server version or technology information is disclosed in response headers."
        f.evidence = "; ".join(disclosures)
        f.impact = "Version disclosure may assist attackers in targeting known CVEs for the specific version."
        f.recommendation = (
            "Configure your web server to suppress or minimise version disclosure. "
            "For Apache: ServerTokens Prod; For Nginx: server_tokens off."
        )
    else:
        f.severity = "informational"
        f.status = "pass"
        f.description = "No obvious server version or technology disclosure in headers."
        f.evidence = "Server and X-Powered-By headers are absent or generic."
    return f


def run_header_checks(headers: dict[str, str], scheme: str) -> list[FindingData]:
    """Run all header checks and return a list of FindingData objects."""
    checks = [
        check_csp,
        check_hsts,
        check_x_content_type,
        check_x_frame_options,
        check_referrer_policy,
        check_permissions_policy,
        check_server_disclosure,
    ]
    return [c(headers, scheme) for c in checks]
