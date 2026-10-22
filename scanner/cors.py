"""
scanner/cors.py — CORS configuration analysis.

Checks:
  CRS-001  Wildcard origin with credentials
  CRS-002  Reflected origin
  CRS-003  Broad method allowance
  CRS-004  Missing Vary: Origin

Important: response headers alone do not prove exploitability of CORS issues.
Findings are observations that warrant manual verification.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FindingData:
    finding_id: str
    check_name: str
    category: str = "CORS Configuration"
    severity: str = "informational"
    status: str = "pass"
    description: str = ""
    evidence: str = ""
    impact: str = ""
    recommendation: str = ""
    reference_url: str = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"


def _header(headers: dict[str, str], name: str) -> str:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return ""


def run_cors_checks(
    response_headers: dict[str, str],
    request_origin_sent: str,
) -> list[FindingData]:
    """
    Analyse CORS response headers.

    Args:
        response_headers: Headers from the server response.
        request_origin_sent: The Origin header value sent in the request
                             (used to detect reflected-origin behaviour).
    """
    findings: list[FindingData] = []

    acao = _header(response_headers, "Access-Control-Allow-Origin")
    acac = _header(response_headers, "Access-Control-Allow-Credentials")
    acam = _header(response_headers, "Access-Control-Allow-Methods")
    acah = _header(response_headers, "Access-Control-Allow-Headers")
    vary = _header(response_headers, "Vary")

    if not acao:
        f = FindingData(
            finding_id="CRS-000",
            check_name="CORS Policy Presence",
        )
        f.status = "pass"
        f.severity = "informational"
        f.description = "No Access-Control-Allow-Origin header is present."
        f.evidence = "ACAO header absent — this endpoint does not appear to have a CORS policy."
        findings.append(f)
        return findings

    # CRS-001  Wildcard origin + credentials
    if acao.strip() == "*" and acac.strip().lower() == "true":
        f = FindingData(
            finding_id="CRS-001",
            check_name="CORS: Wildcard Origin with Allow-Credentials",
        )
        f.severity = "high"
        f.status = "fail"
        f.description = (
            "The server returns Access-Control-Allow-Origin: * combined with "
            "Access-Control-Allow-Credentials: true."
        )
        f.evidence = (
            f"Access-Control-Allow-Origin: {acao}\n"
            f"Access-Control-Allow-Credentials: {acac}"
        )
        f.impact = (
            "Although browsers block this combination per the CORS specification, "
            "some non-browser clients and misconfigured libraries do not enforce this. "
            "This configuration suggests a misconfiguration that may weaken CORS intent."
        )
        f.recommendation = (
            "Do not combine wildcard origins with Allow-Credentials. "
            "Specify the exact trusted origin instead of *."
        )
        findings.append(f)

    # CRS-002  Reflected origin
    elif request_origin_sent and acao.strip() == request_origin_sent.strip():
        f = FindingData(
            finding_id="CRS-002",
            check_name="CORS: Origin Reflection",
        )
        # Only escalate if credentials are also allowed
        if acac.strip().lower() == "true":
            f.severity = "high"
            f.status = "warning"
            f.description = (
                "The server reflects the requesting Origin header back in "
                "Access-Control-Allow-Origin and also allows credentials."
            )
            f.impact = (
                "If the origin whitelist is not properly validated server-side, "
                "an attacker may be able to perform cross-origin requests with user credentials. "
                "Requires manual verification to confirm exploitability."
            )
            f.recommendation = (
                "Maintain an explicit server-side whitelist of trusted origins. "
                "Do not reflect arbitrary origin values."
            )
        else:
            f.severity = "medium"
            f.status = "warning"
            f.description = (
                "The server reflects the requesting Origin in ACAO but does not allow credentials. "
                "Without credentials, exploitability is limited."
            )
            f.impact = "Cross-origin read of non-credentialed responses may be possible."
            f.recommendation = "Validate the origin against an explicit allowlist rather than reflecting it."
        f.evidence = (
            f"Sent Origin: {request_origin_sent}\n"
            f"Access-Control-Allow-Origin: {acao}\n"
            f"Access-Control-Allow-Credentials: {acac or 'absent'}"
        )
        findings.append(f)

    elif acao.strip() == "*":
        f = FindingData(
            finding_id="CRS-002",
            check_name="CORS: Wildcard Origin (No Credentials)",
        )
        f.severity = "informational"
        f.status = "warning"
        f.description = "Access-Control-Allow-Origin: * is set without credentials."
        f.evidence = f"Access-Control-Allow-Origin: {acao}"
        f.impact = (
            "A wildcard origin allows any site to read non-credentialed responses. "
            "For public APIs this is often intentional; for sensitive endpoints it may not be."
        )
        f.recommendation = (
            "Verify that this endpoint intentionally allows any origin. "
            "If not, restrict to specific trusted origins."
        )
        findings.append(f)

    # CRS-003  Broad method allowance
    dangerous_methods = {"DELETE", "PUT", "PATCH", "TRACE", "CONNECT"}
    allowed_methods = {m.strip().upper() for m in acam.split(",")} if acam else set()
    overlap = dangerous_methods & allowed_methods
    if overlap:
        f = FindingData(
            finding_id="CRS-003",
            check_name="CORS: Potentially Broad Method Allowance",
        )
        f.severity = "low"
        f.status = "warning"
        f.description = (
            "The CORS policy allows potentially sensitive HTTP methods cross-origin."
        )
        f.evidence = f"Access-Control-Allow-Methods: {acam}"
        f.impact = (
            f"Methods {', '.join(sorted(overlap))} are allowed cross-origin. "
            "Depending on server-side authorisation, this could enable unintended cross-origin state changes."
        )
        f.recommendation = "Allow only the HTTP methods that cross-origin clients genuinely need."
        findings.append(f)

    # CRS-004  Missing Vary: Origin
    if acao and "*" not in acao:
        if "origin" not in vary.lower():
            f = FindingData(
                finding_id="CRS-004",
                check_name="CORS: Missing Vary: Origin",
            )
            f.severity = "informational"
            f.status = "warning"
            f.description = (
                "A dynamic CORS origin is returned but Vary: Origin is absent from the response."
            )
            f.evidence = f"Access-Control-Allow-Origin: {acao}\nVary: {vary or 'absent'}"
            f.impact = "Shared caches may serve incorrect CORS headers to different origins."
            f.recommendation = "Add Vary: Origin to responses that set a dynamic ACAO header."
            findings.append(f)

    if not findings:
        f = FindingData(
            finding_id="CRS-000",
            check_name="CORS Policy",
        )
        f.status = "pass"
        f.severity = "informational"
        f.description = "No significant CORS policy concerns were identified."
        f.evidence = f"Access-Control-Allow-Origin: {acao}"
        findings.append(f)

    return findings
