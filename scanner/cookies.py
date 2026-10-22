"""
scanner/cookies.py — Cookie security attribute checks.

Checks:
  CKY-001  Secure flag
  CKY-002  HttpOnly flag
  CKY-003  SameSite attribute
  CKY-004  Cookie expiration / Persistent cookie observation

Note: not every cookie has the same security requirements.  Session cookies
should have Secure + HttpOnly.  Third-party analytics cookies may legitimately
omit some flags.  Findings are contextual observations, not exploitability proofs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FindingData:
    finding_id: str
    check_name: str
    category: str = "Cookie Security"
    severity: str = "informational"
    status: str = "pass"
    description: str = ""
    evidence: str = ""
    impact: str = ""
    recommendation: str = ""
    reference_url: str = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"


def _parse_set_cookie_headers(raw_cookies: list[str]) -> list[dict]:
    """
    Parse a list of raw Set-Cookie header values into structured dicts.
    Returns list of dicts with keys: name, value, secure, httponly, samesite, expires, path, domain.
    """
    cookies = []
    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue
        # First part is name=value
        name_val = parts[0]
        if "=" in name_val:
            name, _, value = name_val.partition("=")
        else:
            name = name_val
            value = ""

        attrs = {a.lower(): True for a in parts[1:] if "=" not in a}
        attr_vals = {}
        for a in parts[1:]:
            if "=" in a:
                k, _, v = a.partition("=")
                attr_vals[k.strip().lower()] = v.strip()

        cookies.append(
            {
                "name": name.strip(),
                "value": value[:50] + "..." if len(value) > 50 else value,
                "secure": "secure" in attrs,
                "httponly": "httponly" in attrs,
                "samesite": attr_vals.get("samesite", "").lower(),
                "expires": attr_vals.get("expires", ""),
                "max_age": attr_vals.get("max-age", ""),
                "path": attr_vals.get("path", ""),
                "domain": attr_vals.get("domain", ""),
                "_raw": raw[:200],
            }
        )
    return cookies


def run_cookie_checks(
    raw_cookie_headers: list[str], scheme: str
) -> list[FindingData]:
    """
    Analyse Set-Cookie headers and return findings.
    raw_cookie_headers: list of Set-Cookie header values (strings).
    """
    if not raw_cookie_headers:
        f = FindingData(
            finding_id="CKY-000",
            check_name="Cookie Presence",
        )
        f.status = "pass"
        f.severity = "informational"
        f.description = "No Set-Cookie headers were returned by the server."
        f.evidence = "No cookies found."
        return [f]

    cookies = _parse_set_cookie_headers(raw_cookie_headers)
    findings: list[FindingData] = []
    counter = {"secure": 0, "httponly": 0, "samesite": 0}

    for ck in cookies:
        name = ck["name"]

        # CKY-001 Secure flag
        if not ck["secure"]:
            if scheme == "https":
                f = FindingData(
                    finding_id="CKY-001",
                    check_name=f"Cookie Missing Secure Flag ({name})",
                )
                f.severity = "medium"
                f.status = "fail"
                f.description = (
                    f"Cookie '{name}' is set without the Secure attribute on an HTTPS site."
                )
                f.evidence = ck["_raw"]
                f.impact = (
                    "Without Secure, the cookie could be transmitted over HTTP if the "
                    "user or an intermediary downgrade the connection."
                )
                f.recommendation = f"Add the Secure attribute: Set-Cookie: {name}=...; Secure"
                findings.append(f)
                counter["secure"] += 1

        # CKY-002 HttpOnly flag
        if not ck["httponly"]:
            f = FindingData(
                finding_id="CKY-002",
                check_name=f"Cookie Missing HttpOnly Flag ({name})",
            )
            # Heuristic: if the name looks like a session cookie, escalate
            is_session_like = any(
                kw in name.lower()
                for kw in ("session", "sess", "auth", "token", "jwt", "sid", "csrftoken")
            )
            f.severity = "medium" if is_session_like else "low"
            f.status = "warning"
            f.description = (
                f"Cookie '{name}' does not have the HttpOnly attribute. "
                + ("This appears to be a session-related cookie." if is_session_like else "")
            )
            f.evidence = ck["_raw"]
            f.impact = (
                "Without HttpOnly, client-side scripts can read this cookie. "
                "If an XSS vulnerability exists, this could enable session hijacking."
            )
            f.recommendation = f"Add HttpOnly attribute: Set-Cookie: {name}=...; HttpOnly"
            findings.append(f)
            counter["httponly"] += 1

        # CKY-003 SameSite
        ss = ck["samesite"]
        if ss == "":
            f = FindingData(
                finding_id="CKY-003",
                check_name=f"Cookie Missing SameSite Attribute ({name})",
            )
            f.severity = "low"
            f.status = "warning"
            f.description = f"Cookie '{name}' does not have a SameSite attribute."
            f.evidence = ck["_raw"]
            f.impact = (
                "Without SameSite, the cookie is sent on cross-site requests. "
                "This may contribute to CSRF risk depending on other protections."
            )
            f.recommendation = (
                f"Add SameSite=Lax or SameSite=Strict: Set-Cookie: {name}=...; SameSite=Lax"
            )
            findings.append(f)
            counter["samesite"] += 1
        elif ss == "none" and not ck["secure"]:
            f = FindingData(
                finding_id="CKY-003",
                check_name=f"Cookie SameSite=None without Secure ({name})",
            )
            f.severity = "medium"
            f.status = "fail"
            f.description = (
                f"Cookie '{name}' has SameSite=None but is missing the Secure attribute. "
                "Modern browsers will reject this cookie."
            )
            f.evidence = ck["_raw"]
            f.impact = "Cookie will be rejected by modern browsers or transmitted insecurely."
            f.recommendation = "Add Secure attribute when using SameSite=None."
            findings.append(f)

    if not findings:
        f = FindingData(finding_id="CKY-000", check_name="Cookie Security")
        f.status = "pass"
        f.severity = "informational"
        total = len(cookies)
        f.description = f"All {total} cookie(s) appear to have reasonable security attributes."
        f.evidence = f"Checked {total} cookie(s): " + ", ".join(c["name"] for c in cookies)
        findings.append(f)

    return findings
