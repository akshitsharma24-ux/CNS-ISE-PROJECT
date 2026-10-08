"""
SQLAlchemy database models for PKI Registry and User Feedback Reports (F26, F34).
"""
import time
from sqlalchemy import Column, String, Integer, Text, Boolean, Float
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class IssuerRecord(Base):
    """Registered businesses authorized to issue signed QR codes."""
    __tablename__ = "issuers"

    issuer_id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    domain = Column(String(256), nullable=False)
    public_key_b64 = Column(String(128), nullable=False)
    certificate_json = Column(Text, nullable=False)
    created_at = Column(Integer, default=lambda: int(time.time()))
    is_revoked = Column(Boolean, default=False)
    revocation_reason = Column(String(256), nullable=True)
    revoked_at = Column(Integer, nullable=True)

class CRLRecord(Base):
    """Certificate Revocation List metadata and signatures."""
    __tablename__ = "crl_records"

    version = Column(Integer, primary_key=True)
    issued_at = Column(Integer, nullable=False)
    crl_json = Column(Text, nullable=False)

class ScanReport(Base):
    """User submitted quishing / false-positive feedback reports (F34)."""
    __tablename__ = "scan_reports"

    report_id = Column(String(64), primary_key=True)
    payload_hash = Column(String(64), nullable=False)  # SHA-256 (privacy-preserving)
    url = Column(Text, nullable=False)
    user_label = Column(String(32), nullable=False)    # 'phishing' | 'benign' | 'tampered'
    note = Column(Text, nullable=True)
    created_at = Column(Integer, default=lambda: int(time.time()))
    status = Column(String(32), default="pending")     # 'pending' | 'approved' | 'rejected'
