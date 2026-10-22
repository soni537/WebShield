"""
SQLAlchemy models for WebShield.
"""
from __future__ import annotations

import datetime
import enum
from typing import Optional

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    ERROR = "error"


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id: int = db.Column(db.Integer, primary_key=True)
    username: str = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email: str = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash: str = db.Column(db.String(256), nullable=False)
    is_active: bool = db.Column(db.Boolean, default=True, nullable=False)
    created_at: datetime.datetime = db.Column(
        db.DateTime, default=_utc_now, nullable=False
    )
    last_login_at: Optional[datetime.datetime] = db.Column(db.DateTime, nullable=True)

    scans = db.relationship("Scan", back_populates="user", lazy="dynamic")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f"<User {self.username}>"


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class Scan(db.Model):
    __tablename__ = "scans"

    id: int = db.Column(db.Integer, primary_key=True)
    user_id: Optional[int] = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True, index=True
    )
    target_url: str = db.Column(db.String(2048), nullable=False)
    normalized_hostname: str = db.Column(db.String(253), nullable=False, index=True)
    scan_started_at: datetime.datetime = db.Column(
        db.DateTime, default=_utc_now, nullable=False
    )
    scan_completed_at: Optional[datetime.datetime] = db.Column(
        db.DateTime, nullable=True
    )
    status: str = db.Column(
        db.Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True
    )
    security_score: Optional[int] = db.Column(db.SmallInteger, nullable=True)
    total_findings: int = db.Column(db.Integer, default=0)
    critical_count: int = db.Column(db.Integer, default=0)
    high_count: int = db.Column(db.Integer, default=0)
    medium_count: int = db.Column(db.Integer, default=0)
    low_count: int = db.Column(db.Integer, default=0)
    informational_count: int = db.Column(db.Integer, default=0)
    error_message: Optional[str] = db.Column(db.Text, nullable=True)

    user = db.relationship("User", back_populates="scans")
    findings = db.relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan", lazy="dynamic"
    )

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.scan_started_at and self.scan_completed_at:
            return (self.scan_completed_at - self.scan_started_at).total_seconds()
        return None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target_url": self.target_url,
            "normalized_hostname": self.normalized_hostname,
            "scan_started_at": self.scan_started_at.isoformat() if self.scan_started_at else None,
            "scan_completed_at": self.scan_completed_at.isoformat() if self.scan_completed_at else None,
            "status": self.status.value if hasattr(self.status, "value") else self.status,
            "security_score": self.security_score,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "informational_count": self.informational_count,
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message,
        }

    def __repr__(self) -> str:
        return f"<Scan {self.id} {self.target_url}>"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class Finding(db.Model):
    __tablename__ = "findings"

    id: int = db.Column(db.Integer, primary_key=True)
    scan_id: int = db.Column(
        db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True
    )
    finding_id: str = db.Column(db.String(64), nullable=False)  # e.g. "HDR-001"
    check_name: str = db.Column(db.String(128), nullable=False)
    category: str = db.Column(db.String(64), nullable=False, index=True)
    severity: str = db.Column(db.Enum(Severity), nullable=False, index=True)
    status: str = db.Column(db.Enum(FindingStatus), nullable=False)
    description: str = db.Column(db.Text, nullable=False)
    evidence: Optional[str] = db.Column(db.Text, nullable=True)
    impact: Optional[str] = db.Column(db.Text, nullable=True)
    recommendation: Optional[str] = db.Column(db.Text, nullable=True)
    reference_url: Optional[str] = db.Column(db.String(512), nullable=True)

    scan = db.relationship("Scan", back_populates="findings")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "finding_id": self.finding_id,
            "check_name": self.check_name,
            "category": self.category,
            "severity": self.severity.value if hasattr(self.severity, "value") else self.severity,
            "status": self.status.value if hasattr(self.status, "value") else self.status,
            "description": self.description,
            "evidence": self.evidence,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "reference_url": self.reference_url,
        }

    def __repr__(self) -> str:
        return f"<Finding {self.finding_id} scan={self.scan_id}>"
