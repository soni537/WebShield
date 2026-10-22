"""
scanner/scoring.py — Security score calculation.

Scoring methodology
-------------------
The score starts at 100 and deductions are applied based on finding severity
and status.  The same underlying issue is only counted once.

Deductions:
  Critical finding (fail)     : -25
  High finding (fail)         : -15
  High finding (warning)      : -10
  Medium finding (fail)       : -10
  Medium finding (warning)    :  -5
  Low finding (fail/warning)  :  -3
  Informational findings      :  -0  (no deduction)

The score is capped at 0 (minimum) and 100 (maximum).

This scoring is for educational demonstration purposes only and should not be
interpreted as a formal security rating.
"""

from __future__ import annotations

from typing import Any

DEDUCTIONS: dict[tuple[str, str], int] = {
    ("critical", "fail"):    25,
    ("critical", "warning"): 20,
    ("high", "fail"):        15,
    ("high", "warning"):     10,
    ("medium", "fail"):      10,
    ("medium", "warning"):    5,
    ("low", "fail"):          3,
    ("low", "warning"):       2,
}


def calculate_score(findings: list[Any]) -> int:
    """
    Calculate a security score from 0 to 100.

    findings: list of objects with .severity and .status attributes,
              OR dicts with 'severity' and 'status' keys.
    """
    score = 100
    seen_ids: set[str] = set()

    for f in findings:
        if isinstance(f, dict):
            sev = f.get("severity", "informational").lower()
            stat = f.get("status", "pass").lower()
            fid = f.get("finding_id", "")
        else:
            sev = getattr(f, "severity", "informational").lower()
            stat = getattr(f, "status", "pass").lower()
            fid = getattr(f, "finding_id", "")

        # Don't double-count the same base finding ID across retries
        if fid and fid in seen_ids:
            continue
        if fid:
            seen_ids.add(fid)

        deduction = DEDUCTIONS.get((sev, stat), 0)
        score -= deduction

    return max(0, min(100, score))


def score_label(score: int) -> str:
    """Return a human-readable label for a score."""
    if score >= 90:
        return "Excellent"
    elif score >= 75:
        return "Good"
    elif score >= 50:
        return "Fair"
    elif score >= 25:
        return "Poor"
    else:
        return "Critical"


def score_colour(score: int) -> str:
    """Return a Bootstrap-compatible colour class for a score."""
    if score >= 75:
        return "success"
    elif score >= 50:
        return "warning"
    else:
        return "danger"
