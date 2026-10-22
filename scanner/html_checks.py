"""
scanner/html_checks.py — HTML-level security observations.

Uses BeautifulSoup4 to inspect the retrieved HTML document.

Checks:
  HTML-001  Forms submitted over HTTP
  HTML-002  Password input form actions
  HTML-003  External script / resource references
  HTML-004  Meta security tags (CSP meta, referrer meta)
  HTML-005  Mixed content indicators

These are contextual observations, not confirmed vulnerabilities.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

from bs4 import BeautifulSoup


@dataclass
class FindingData:
    finding_id: str
    check_name: str
    category: str = "HTML Security"
    severity: str = "informational"
    status: str = "pass"
    description: str = ""
    evidence: str = ""
    impact: str = ""
    recommendation: str = ""
    reference_url: str = "https://owasp.org/www-project-web-security-testing-guide/"


def _is_http_url(url: str) -> bool:
    return url.lower().startswith("http://")


def run_html_checks(html_content: str, base_url: str) -> list[FindingData]:
    """Parse HTML and return security observations."""
    findings: list[FindingData] = []

    if not html_content:
        f = FindingData(finding_id="HTML-000", check_name="HTML Content")
        f.status = "warning"
        f.severity = "informational"
        f.description = "No HTML content was available for analysis."
        return [f]

    try:
        soup = BeautifulSoup(html_content, "lxml")
    except Exception:
        soup = BeautifulSoup(html_content, "html.parser")

    base_parsed = urllib.parse.urlparse(base_url)

    # ------------------------------------------------------------------
    # HTML-001  Forms submitted over HTTP
    # ------------------------------------------------------------------
    http_forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        if action:
            absolute = urllib.parse.urljoin(base_url, action)
            if _is_http_url(absolute):
                http_forms.append(f'<form action="{action}" method="{method}">')
        elif base_parsed.scheme == "http":
            http_forms.append(f'<form action="" method="{method}"> (inherited HTTP base)')

    if http_forms:
        f = FindingData(finding_id="HTML-001", check_name="Forms Submitted Over HTTP")
        f.severity = "medium"
        f.status = "warning"
        f.description = f"{len(http_forms)} form(s) appear to submit data over HTTP."
        f.evidence = "\n".join(http_forms[:5])
        f.impact = "Form data submitted over HTTP is transmitted in plaintext and may be intercepted."
        f.recommendation = "Ensure all forms submit to HTTPS endpoints."
        findings.append(f)

    # ------------------------------------------------------------------
    # HTML-002  Password inputs — check destination
    # ------------------------------------------------------------------
    pwd_issues = []
    for form in soup.find_all("form"):
        if form.find("input", {"type": "password"}):
            action = urllib.parse.urljoin(base_url, form.get("action", base_url))
            if _is_http_url(action):
                pwd_issues.append(action)

    if pwd_issues:
        f = FindingData(finding_id="HTML-002", check_name="Password Form Submits Over HTTP")
        f.severity = "high"
        f.status = "fail"
        f.description = "Password input form(s) appear to submit over HTTP."
        f.evidence = "Form actions: " + ", ".join(pwd_issues[:3])
        f.impact = "User credentials may be transmitted in plaintext and intercepted."
        f.recommendation = "Serve the login form and its action endpoint over HTTPS."
        f.reference_url = "https://owasp.org/www-community/attacks/Credential_stuffing"
        findings.append(f)

    # ------------------------------------------------------------------
    # HTML-003  External resources loaded over HTTP (mixed content risk)
    # ------------------------------------------------------------------
    if base_parsed.scheme == "https":
        mixed = []
        for tag, attr in [("script", "src"), ("link", "href"), ("img", "src"), ("iframe", "src")]:
            for el in soup.find_all(tag):
                src = el.get(attr, "")
                if _is_http_url(src):
                    mixed.append(f"<{tag} {attr}=\"{src[:100]}\">")

        if mixed:
            f = FindingData(finding_id="HTML-003", check_name="Mixed Content (External HTTP Resources)")
            f.severity = "medium"
            f.status = "warning"
            f.description = (
                f"{len(mixed)} external resource(s) are referenced over HTTP on an HTTPS page."
            )
            f.evidence = "\n".join(mixed[:5])
            f.impact = "Mixed content degrades HTTPS security and is blocked by modern browsers."
            f.recommendation = "Update all resource URLs to use HTTPS."
            f.reference_url = "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"
            findings.append(f)

    # ------------------------------------------------------------------
    # HTML-004  Security-related meta tags
    # ------------------------------------------------------------------
    meta_csp = soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "content-security-policy"})
    meta_ref = soup.find("meta", attrs={"name": lambda v: v and v.lower() == "referrer"})

    observations = []
    if meta_csp:
        observations.append("CSP delivered via <meta> tag (less effective than HTTP header)")
    if meta_ref:
        observations.append("Referrer policy delivered via <meta name=referrer> tag")

    if observations:
        f = FindingData(finding_id="HTML-004", check_name="Security Policies Delivered via Meta Tags")
        f.severity = "informational"
        f.status = "warning"
        f.description = "Security policies are configured using HTML meta tags rather than HTTP headers."
        f.evidence = "; ".join(observations)
        f.impact = (
            "HTTP header-based policies are more reliably enforced. "
            "Meta-tag-based CSP, for instance, cannot block resources loaded before the meta tag is parsed."
        )
        f.recommendation = "Prefer HTTP response headers for CSP and Referrer-Policy."
        findings.append(f)

    # ------------------------------------------------------------------
    # HTML-005  Autocomplete on sensitive forms
    # ------------------------------------------------------------------
    auto_issues = []
    for form in soup.find_all("form"):
        pwd_input = form.find("input", {"type": "password"})
        if pwd_input:
            form_auto = form.get("autocomplete", "").lower()
            input_auto = pwd_input.get("autocomplete", "").lower()
            if form_auto != "off" and input_auto != "off" and input_auto != "new-password":
                auto_issues.append(str(form)[:100])

    if auto_issues:
        f = FindingData(finding_id="HTML-005", check_name="Autocomplete on Password Fields")
        f.severity = "informational"
        f.status = "warning"
        f.description = "Password field(s) do not explicitly disable browser autocomplete."
        f.evidence = f"{len(auto_issues)} password form(s) without autocomplete=off/new-password"
        f.impact = (
            "On shared devices, autocomplete may store sensitive credentials in the browser. "
            "Note: modern password managers may override autocomplete=off."
        )
        f.recommendation = "Consider adding autocomplete='new-password' on registration forms."
        findings.append(f)

    if not findings:
        f = FindingData(finding_id="HTML-000", check_name="HTML Security Observations")
        f.status = "pass"
        f.severity = "informational"
        f.description = "No notable HTML-level security concerns were observed."
        findings.append(f)

    return findings
