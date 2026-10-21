"""SQLAlchemy models for the PKI registry, the feedback queue and operational logs."""
from __future__ import annotations

import time
from typing import Optional

from sqlalchemy import Boolean, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _now() -> int:
    return int(time.time())


class Base(DeclarativeBase):
    pass


class IssuerRecord(Base):
    """A registered business authorised to issue signed QR codes (F26)."""
    __tablename__ = "issuers"

    issuer_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    domain: Mapped[str] = mapped_column(String(253))
    key_id: Mapped[str] = mapped_column(String(32), default="key-1")
    public_key_b64: Mapped[str] = mapped_column(String(64))
    certificate_json: Mapped[str] = mapped_column(Text)
    managed_key: Mapped[bool] = mapped_column(Boolean, default=False)   # demo custody of the private key
    created_at: Mapped[int] = mapped_column(Integer, default=_now)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    revocation_reason: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    revoked_at: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)


class KeyRevocation(Base):
    """A single signing key revoked without revoking the whole issuer (rotation / theft)."""
    __tablename__ = "key_revocations"

    revocation_id: Mapped[str] = mapped_column(String(128), primary_key=True)   # "<issuer>:<kid>"
    revoked_at: Mapped[int] = mapped_column(Integer, default=_now)
    reason: Mapped[str] = mapped_column(String(256), default="revoked")


class CRLRecord(Base):
    """History of published, root-signed revocation lists."""
    __tablename__ = "crl_records"

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    issued_at: Mapped[int] = mapped_column(Integer)
    crl_json: Mapped[str] = mapped_column(Text)


class ScanReport(Base):
    """User feedback awaiting human review (F34). Holds no personal identifiers."""
    __tablename__ = "scan_reports"

    report_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload_hash: Mapped[str] = mapped_column(String(64), index=True)   # SHA-256 of the payload
    url: Mapped[str] = mapped_column(Text)
    user_label: Mapped[str] = mapped_column(String(32))                 # phishing | benign | tampered
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verdict_at_report: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    created_at: Mapped[int] = mapped_column(Integer, default=_now)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | approved | rejected
    reviewed_at: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    used_in_model: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)


class ScanLog(Base):
    """Anonymised scan telemetry used for the stats page (no payload, no image)."""
    __tablename__ = "scan_log"

    scan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[int] = mapped_column(Integer, default=_now)
    payload_hash: Mapped[str] = mapped_column(String(64))
    payload_type: Mapped[str] = mapped_column(String(16))
    verdict: Mapped[str] = mapped_column(String(16))
    risk: Mapped[float] = mapped_column(Float)
    url_risk: Mapped[float] = mapped_column(Float)
    tamper_risk: Mapped[float] = mapped_column(Float)
    sig_status: Mapped[str] = mapped_column(String(24))
    elapsed_ms: Mapped[float] = mapped_column(Float)


class AuditLog(Base):
    """Append-only trail of privileged actions."""
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[int] = mapped_column(Integer, default=_now)
    action: Mapped[str] = mapped_column(String(48))
    subject: Mapped[str] = mapped_column(String(128))
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class ModelVersion(Base):
    """Versioned ML models and the outcome of the benchmark gate (F35)."""
    __tablename__ = "model_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(16))          # url | cv
    version: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[int] = mapped_column(Integer, default=_now)
    status: Mapped[str] = mapped_column(String(16))        # active | rejected | archived
    metrics_json: Mapped[str] = mapped_column(Text)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
