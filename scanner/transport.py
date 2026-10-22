"""
scanner/transport.py — HTTPS / TLS transport security checks.

Checks:
  TLS-001  HTTPS support
  TLS-002  HTTP-to-HTTPS redirect
  TLS-003  Certificate verification (using requests default CA bundle)
  TLS-004  HSTS on HTTPS response (delegated to headers.py but summarised here)
"""

from __future__ import annotations

import logging
import urllib.parse
from dataclasses import dataclass
from typing import Optional

import requests
import requests.exceptions

from scanner.safety import validate_redirect

logger = logging.getLogger(__name__)


@dataclass
class FindingData:
    finding_id: str
    check_name: str
    category: str = "Transport Security"
    severity: str = "informational"
    status: str = "pass"
    description: str = ""
    evidence: str = ""
    impact: str = ""
    recommendation: str = ""
    reference_url: str = "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"


def run_transport_checks(
    target_url: str,
    timeout: int = 15,
    max_response_bytes: int = 5 * 1024 * 1024,
    validated_ips: Optional[list[str]] = None,
) -> tuple[list[FindingData], Optional[requests.Response]]:
    """
    Perform transport-security checks and return (findings, final_response).

    The *final_response* is the response that should be used for subsequent
    header / cookie / HTML checks.  It may be None if the target is unreachable.

    NOTE: TLS certificate verification is NEVER disabled.  If verification
    fails, that fact is reported as a finding rather than silently bypassed.
    """
    findings: list[FindingData] = []
    final_response: Optional[requests.Response] = None

    parsed_scheme = target_url.split("://")[0].lower() if "://" in target_url else "http"

    # ------------------------------------------------------------------
    # TLS-001 HTTPS Support
    # ------------------------------------------------------------------
    https_url = target_url if parsed_scheme == "https" else target_url.replace("http://", "https://", 1)
    http_url = target_url if parsed_scheme == "http" else target_url.replace("https://", "http://", 1)

    f_https = FindingData(
        finding_id="TLS-001",
        check_name="HTTPS Support",
        reference_url="https://developer.mozilla.org/en-US/docs/Glossary/HTTPS",
    )
    https_ok = False
    https_response: Optional[requests.Response] = None

    try:
        https_response = requests.get(
            https_url,
            timeout=timeout,
            verify=True,
            allow_redirects=False,
            headers={"User-Agent": "WebShield-SecurityScanner/1.0 (educational)"},
            stream=True,
        )
        # Read at most max_response_bytes to prevent memory exhaustion
        content_bytes = b""
        for chunk in https_response.iter_content(chunk_size=65536):
            content_bytes += chunk
            if len(content_bytes) >= max_response_bytes:
                break
        https_response._content = content_bytes  # cache for .text access later
        https_response.close()
        https_ok = True
        f_https.status = "pass"
        f_https.severity = "informational"
        f_https.description = "HTTPS is supported and the server responded successfully."
        f_https.evidence = f"HTTP {https_response.status_code} from {https_url}"
        final_response = https_response
    except requests.exceptions.SSLError as exc:
        f_https.status = "fail"
        f_https.severity = "high"
        f_https.description = "HTTPS connection failed due to an SSL/TLS certificate error."
        f_https.evidence = str(exc)[:400]
        f_https.impact = (
            "An invalid or untrusted TLS certificate prevents secure communication and "
            "may expose users to man-in-the-middle attacks."
        )
        f_https.recommendation = (
            "Obtain a valid certificate from a trusted CA (e.g., Let's Encrypt). "
            "Ensure the certificate matches the domain and has not expired."
        )
    except requests.exceptions.ConnectionError as exc:
        f_https.status = "fail"
        f_https.severity = "medium"
        f_https.description = "Could not establish an HTTPS connection to the target."
        f_https.evidence = str(exc)[:400]
        f_https.impact = "HTTPS may not be supported or is misconfigured."
        f_https.recommendation = "Enable HTTPS on the web server with a valid certificate."
    except requests.exceptions.Timeout:
        f_https.status = "error"
        f_https.severity = "low"
        f_https.description = "HTTPS connection timed out."
        f_https.evidence = f"Request to {https_url} exceeded {timeout}s timeout."
    except Exception as exc:
        f_https.status = "error"
        f_https.severity = "low"
        f_https.description = "An unexpected error occurred during the HTTPS check."
        f_https.evidence = str(exc)[:400]

    findings.append(f_https)

    # ------------------------------------------------------------------
    # TLS-002 HTTP → HTTPS redirect
    # ------------------------------------------------------------------
    f_redirect = FindingData(
        finding_id="TLS-002",
        check_name="HTTP to HTTPS Redirect",
    )
    try:
        http_response = requests.get(
            http_url,
            timeout=timeout,
            verify=True,
            allow_redirects=False,
            headers={"User-Agent": "WebShield-SecurityScanner/1.0 (educational)"},
        )
        location = http_response.headers.get("Location", "")
        if http_response.is_redirect and location.lower().startswith("https://"):
            f_redirect.status = "pass"
            f_redirect.severity = "informational"
            f_redirect.description = "HTTP requests are correctly redirected to HTTPS."
            f_redirect.evidence = (
                f"HTTP {http_response.status_code} → Location: {location}"
            )
        elif http_response.is_redirect:
            f_redirect.status = "warning"
            f_redirect.severity = "medium"
            f_redirect.description = "HTTP redirects, but the destination is not HTTPS."
            f_redirect.evidence = f"HTTP {http_response.status_code} → Location: {location}"
            f_redirect.recommendation = "Ensure HTTP always redirects to the HTTPS version."
        else:
            f_redirect.status = "fail"
            f_redirect.severity = "medium"
            f_redirect.description = (
                "HTTP endpoint does not redirect to HTTPS. "
                "Content may be served over an unencrypted connection."
            )
            f_redirect.evidence = f"HTTP {http_response.status_code} with no redirect."
            f_redirect.recommendation = (
                "Configure a permanent (301) redirect from HTTP to HTTPS."
            )
    except Exception as exc:
        f_redirect.status = "error"
        f_redirect.severity = "informational"
        f_redirect.description = "Could not complete HTTP redirect check."
        f_redirect.evidence = str(exc)[:300]

    findings.append(f_redirect)

    # ------------------------------------------------------------------
    # TLS-003 Certificate Validity (summarised from TLS-001 result)
    # ------------------------------------------------------------------
    f_cert = FindingData(
        finding_id="TLS-003",
        check_name="TLS Certificate Validity",
        reference_url="https://letsencrypt.org/",
    )
    if https_ok:
        f_cert.status = "pass"
        f_cert.severity = "informational"
        f_cert.description = "TLS certificate was accepted by the default system CA bundle."
        f_cert.evidence = f"Successful verified HTTPS connection to {https_url}"
    elif f_https.status == "fail" and "ssl" in f_https.description.lower():
        f_cert.status = "fail"
        f_cert.severity = "high"
        f_cert.description = "TLS certificate validation failed."
        f_cert.evidence = f_https.evidence
        f_cert.recommendation = f_https.recommendation
    else:
        f_cert.status = "warning"
        f_cert.severity = "informational"
        f_cert.description = "Certificate validity could not be verified (connection error)."
        f_cert.evidence = "HTTPS connection was not successful."

    findings.append(f_cert)

    # If no HTTPS response, fall back to plain HTTP for subsequent checks
    if final_response is None:
        try:
            http_r = requests.get(
                http_url,
                timeout=timeout,
                verify=True,
                allow_redirects=False,
                headers={"User-Agent": "WebShield-SecurityScanner/1.0 (educational)"},
                stream=True,
            )
            # Follow redirects safely with SSRF re-validation at each hop
            redirect_hops = 0
            while http_r.is_redirect and "Location" in http_r.headers and redirect_hops < 5:
                next_url = urllib.parse.urljoin(http_r.url, http_r.headers["Location"])
                val = validate_redirect(http_url, next_url)
                if not val.valid:
                    logger.warning("SSRF redirect blocked in transport fallback: %s -> %s", http_url, next_url)
                    break
                redirect_hops += 1
                http_r.close()
                http_r = requests.get(
                    next_url,
                    timeout=timeout,
                    verify=True,
                    allow_redirects=False,
                    headers={"User-Agent": "WebShield-SecurityScanner/1.0 (educational)"},
                    stream=True,
                )

            # Cap content read to max_response_bytes to prevent memory exhaustion
            content_bytes = b""
            for chunk in http_r.iter_content(chunk_size=65536):
                content_bytes += chunk
                if len(content_bytes) >= max_response_bytes:
                    break
            http_r._content = content_bytes
            http_r.close()
            final_response = http_r
        except Exception as exc:
            logger.debug("Fallback HTTP probe failed: %s", exc)

    return findings, final_response
