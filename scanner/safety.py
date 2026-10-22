"""
scanner/safety.py — SSRF-prevention, URL validation, and network-destination checks.

All network access performed by the scanner MUST pass through validate_url()
before a connection is established.  validate_redirect() must be called for
every redirect destination.

Defense-in-depth layers implemented here:
 1. Scheme whitelist (http / https only).
 2. Hostname validation and normalisation.
 3. Configurable allowlist (optional strict mode).
 4. DNS resolution with all returned addresses checked.
 5. Blocked IP ranges: loopback, private, link-local, multicast, reserved,
    cloud-metadata (169.254.169.254 and [fd00::]/8 alike).
 6. IPv6 restrictions matching IPv4 policy.
 7. Redirect-destination re-validation (time-of-use check).
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Blocked network ranges
# ---------------------------------------------------------------------------

_BLOCKED_IPV4 = [
    ipaddress.ip_network("0.0.0.0/8"),          # "This" network
    ipaddress.ip_network("10.0.0.0/8"),          # Private
    ipaddress.ip_network("100.64.0.0/10"),       # Shared address (CGN)
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local / cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),       # Private
    ipaddress.ip_network("192.0.0.0/24"),        # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),      # Private
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved / future
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
]

_BLOCKED_IPV6 = [
    ipaddress.ip_network("::1/128"),             # Loopback
    ipaddress.ip_network("::/128"),              # Unspecified
    ipaddress.ip_network("fc00::/7"),            # Unique local (ULA)
    ipaddress.ip_network("fe80::/10"),           # Link-local
    ipaddress.ip_network("ff00::/8"),            # Multicast
    ipaddress.ip_network("100::/64"),            # Discard
    ipaddress.ip_network("64:ff9b::/96"),        # NAT64
]

# Cloud metadata endpoints that must always be blocked
_BLOCKED_HOSTNAMES: set[str] = {
    "metadata.google.internal",
    "metadata.goog",
}

# Allowed schemes
_ALLOWED_SCHEMES: set[str] = {"http", "https"}

# Hostname must not look like a raw IP disguised with DNS tricks
_VALID_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    valid: bool
    url: str = ""
    scheme: str = ""
    hostname: str = ""
    port: Optional[int] = None
    resolved_ips: list[str] = field(default_factory=list)
    error: str = ""


# ---------------------------------------------------------------------------
# IP-address helpers
# ---------------------------------------------------------------------------

def _is_blocked_ip(addr_str: str) -> tuple[bool, str]:
    """Return (True, reason) if *addr_str* is in a blocked range."""
    try:
        addr = ipaddress.ip_address(addr_str)
    except ValueError:
        return True, f"Cannot parse IP address: {addr_str}"

    if isinstance(addr, ipaddress.IPv4Address):
        for net in _BLOCKED_IPV4:
            if addr in net:
                return True, f"{addr} is in blocked range {net}"
    else:
        for net in _BLOCKED_IPV6:
            if addr in net:
                return True, f"{addr} is in blocked IPv6 range {net}"

    return False, ""


def resolve_and_check(hostname: str) -> tuple[bool, list[str], str]:
    """
    Resolve *hostname* and validate every returned address.

    Returns:
        (all_ok, ip_list, error_message)
    """
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return False, [], f"DNS resolution failed: {exc}"

    ips: list[str] = []
    for info in infos:
        ip_str = info[4][0]
        if ip_str not in ips:
            ips.append(ip_str)

    for ip in ips:
        blocked, reason = _is_blocked_ip(ip)
        if blocked:
            return False, ips, f"Resolved address {ip} is not allowed: {reason}"

    if not ips:
        return False, [], "No IP addresses returned for hostname"

    return True, ips, ""


# ---------------------------------------------------------------------------
# Main validation entry-points
# ---------------------------------------------------------------------------

def validate_url(
    url: str,
    allowlist: Optional[list[str]] = None,
    allow_private_ips: bool = False,
) -> ValidationResult:
    """
    Full SSRF-prevention validation for a user-supplied URL.

    Steps:
     1. Parse URL and normalise.
     2. Check scheme.
     3. Check for blocked hostnames.
     4. Check allowlist (if configured).
     5. Block raw IP literals that are in blocked ranges.
     6. Resolve hostname and validate every address.
    """
    url = url.strip()

    # 1 — Parse
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:
        return ValidationResult(valid=False, url=url, error=f"URL parse error: {exc}")

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc or ""

    # Strip port from netloc to get raw host
    if "[" in netloc:
        # IPv6 literal: [::1]:8080 → ::1
        host_part = netloc.split("]")[0].lstrip("[")
        port_part = netloc.split("]:")[1] if "]:" in netloc else ""
    elif ":" in netloc:
        host_part, _, port_part = netloc.rpartition(":")
    else:
        host_part = netloc
        port_part = ""

    hostname = host_part.lower()

    try:
        port: Optional[int] = int(port_part) if port_part else None
    except ValueError:
        return ValidationResult(valid=False, url=url, error=f"Invalid port: {port_part}")

    # 2 — Scheme
    if scheme not in _ALLOWED_SCHEMES:
        return ValidationResult(
            valid=False, url=url, error=f"Scheme '{scheme}' is not allowed. Only http and https are accepted."
        )

    # 3 — Empty host
    if not hostname:
        return ValidationResult(valid=False, url=url, error="URL contains no hostname.")

    # 4 — Blocked hostnames
    if hostname in _BLOCKED_HOSTNAMES:
        return ValidationResult(
            valid=False, url=url, error=f"Hostname '{hostname}' is explicitly blocked."
        )

    # 5 — Allowlist
    if allowlist:
        normalised_allowlist = [h.lower().strip() for h in allowlist]
        if hostname not in normalised_allowlist and f"www.{hostname}" not in normalised_allowlist:
            # Check if hostname is a subdomain of an allowlisted entry
            allowed = any(hostname.endswith(f".{a}") or hostname == a for a in normalised_allowlist)
            if not allowed:
                return ValidationResult(
                    valid=False,
                    url=url,
                    error=(
                        f"'{hostname}' is not in the configured scan allowlist. "
                        "Only explicitly authorised targets may be scanned."
                    ),
                )

    # 6 — Raw IP literal check (before DNS)
    addr_obj = None
    try:
        addr_obj = ipaddress.ip_address(hostname)
    except ValueError:
        # Check numeric integer or hex IPv4 literal e.g. 2130706433 or 0x7f000001
        try:
            val = int(hostname, 0)
            if 0 <= val <= 0xFFFFFFFF:
                addr_obj = ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass

    if addr_obj is not None:
        if not allow_private_ips:
            blocked, reason = _is_blocked_ip(str(addr_obj))
            if blocked:
                return ValidationResult(
                    valid=False, url=url, error=f"IP address target is not allowed: {reason}"
                )
        return ValidationResult(
            valid=True,
            url=url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            resolved_ips=[str(addr_obj)],
        )

    # 7 — DNS + address validation
    ok, ips, err = resolve_and_check(hostname)
    if not ok:
        if not allow_private_ips:
            return ValidationResult(valid=False, url=url, error=err)
        # If in isolated test mode and DNS failed on loopback/test hostname, check if it's test hostname
        if not ips:
            return ValidationResult(valid=False, url=url, error=err)

    if not allow_private_ips:
        for ip in ips:
            blocked, reason = _is_blocked_ip(ip)
            if blocked:
                return ValidationResult(
                    valid=False, url=url, error=f"Resolved address {ip} is not allowed: {reason}"
                )

    return ValidationResult(
        valid=True,
        url=url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        resolved_ips=ips,
    )


def validate_redirect(
    original_hostname: str,
    redirect_url: str,
    allowlist: Optional[list[str]] = None,
    allow_private_ips: bool = False,
) -> ValidationResult:
    """
    Validate a redirect destination with the same strictness as the original
    URL.  This addresses time-of-check/time-of-use (TOCTOU) issues where a
    server might initially respond cleanly and then redirect to an internal
    address.
    """
    result = validate_url(redirect_url, allowlist=allowlist, allow_private_ips=allow_private_ips)
    if not result.valid:
        result.error = f"Redirect to '{redirect_url}' blocked: {result.error}"
    return result
