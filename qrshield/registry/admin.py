"""
Registry administration and cryptographic lifecycle management (F26).
Maintains root authority keypair, issues signed X.509-style JSON certs,
maintains revocation ledger, and syncs local verifier caches.
"""
import os
import json
import time
import hashlib
from typing import Dict, Any, List, Optional
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from qrshield.registry.models import Base, IssuerRecord, CRLRecord, ScanReport
from qrshield.crypto_layer.keys import (
    generate_keypair,
    export_public_key_b64,
    load_public_key_b64,
    export_private_key_b64,
    load_private_key_b64
)
from qrshield.crypto_layer.pki import (
    create_issuer_certificate
)
from qrshield.crypto_layer.revocation import (
    create_signed_crl
)
from qrshield.crypto_layer.verify import (
    set_pinned_root_key,
    cache_certificate,
    set_cached_crl
)

DB_PATH = os.path.join(os.path.dirname(__file__), "qrshield_registry.db")
engine = create_engine(f"sqlite:///{DB_PATH}", echo=False, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# In-memory storage for root private key (offline authority model)
_ROOT_PRIVATE_KEY = None
_ROOT_PUBLIC_KEY = None

def init_db():
    """Initializes SQLite tables."""
    Base.metadata.create_all(bind=engine)

def get_or_create_root_key():
    """Retrieves or creates the Root Authority Ed25519 keypair."""
    global _ROOT_PRIVATE_KEY, _ROOT_PUBLIC_KEY
    if _ROOT_PRIVATE_KEY is not None:
        return _ROOT_PRIVATE_KEY, _ROOT_PUBLIC_KEY

    key_file = os.path.join(os.path.dirname(__file__), "root_key.json")
    if os.path.exists(key_file):
        try:
            with open(key_file, "r") as f:
                data = json.load(f)
            _ROOT_PRIVATE_KEY = load_private_key_b64(data["private_key"])
            _ROOT_PUBLIC_KEY = load_public_key_b64(data["public_key"])
            set_pinned_root_key(_ROOT_PUBLIC_KEY)
            return _ROOT_PRIVATE_KEY, _ROOT_PUBLIC_KEY
        except Exception:
            pass

    # Generate new authority key
    _ROOT_PRIVATE_KEY, _ROOT_PUBLIC_KEY = generate_keypair()
    priv_b64 = export_private_key_b64(_ROOT_PRIVATE_KEY)
    pub_b64 = export_public_key_b64(_ROOT_PUBLIC_KEY)
    with open(key_file, "w") as f:
        json.dump({"private_key": priv_b64, "public_key": pub_b64}, f, indent=2)

    set_pinned_root_key(_ROOT_PUBLIC_KEY)
    return _ROOT_PRIVATE_KEY, _ROOT_PUBLIC_KEY

def register_issuer(
    issuer_id: str,
    name: str,
    domain: str,
    issuer_pubkey_b64: str
) -> Dict[str, Any]:
    """
    Registers a business and issues a signed certificate.
    """
    init_db()
    root_priv, root_pub = get_or_create_root_key()
    issuer_pub = load_public_key_b64(issuer_pubkey_b64)

    cert = create_issuer_certificate(
        issuer_id=issuer_id,
        name=name,
        domain=domain,
        issuer_public_key=issuer_pub,
        root_private_key=root_priv
    )

    db = SessionLocal()
    try:
        existing = db.query(IssuerRecord).filter_by(issuer_id=issuer_id).first()
        if existing:
            existing.name = name
            existing.domain = domain
            existing.public_key_b64 = issuer_pubkey_b64
            existing.certificate_json = json.dumps(cert)
            existing.is_revoked = False
        else:
            rec = IssuerRecord(
                issuer_id=issuer_id,
                name=name,
                domain=domain,
                public_key_b64=issuer_pubkey_b64,
                certificate_json=json.dumps(cert),
                is_revoked=False
            )
            db.add(rec)
        db.commit()
    finally:
        db.close()

    # Sync to local verification engine
    cache_certificate(issuer_id, cert)
    return cert

def revoke_issuer(issuer_id: str, reason: str = "Key compromised") -> Dict[str, Any]:
    """
    Revokes an issuer certificate and regenerates the signed CRL.
    """
    init_db()
    root_priv, root_pub = get_or_create_root_key()
    now = int(time.time())

    db = SessionLocal()
    try:
        rec = db.query(IssuerRecord).filter_by(issuer_id=issuer_id).first()
        if rec:
            rec.is_revoked = True
            rec.revocation_reason = reason
            rec.revoked_at = now
            db.commit()

        # Query all currently revoked issuers
        revoked_rows = db.query(IssuerRecord).filter_by(is_revoked=True).all()
        revoked_entries = [
            {"id": r.issuer_id, "revoked_at": r.revoked_at or now, "reason": r.revocation_reason or reason}
            for r in revoked_rows
        ]

        # Get latest CRL version
        last_crl = db.query(CRLRecord).order_by(CRLRecord.version.desc()).first()
        new_version = (last_crl.version + 1) if last_crl else 1

        crl_data = create_signed_crl(revoked_entries, root_priv, version=new_version)
        crl_rec = CRLRecord(
            version=new_version,
            issued_at=crl_data["issued_at"],
            crl_json=json.dumps(crl_data)
        )
        db.add(crl_rec)
        db.commit()
    finally:
        db.close()

    # Sync CRL into local verifier cache
    set_cached_crl(crl_data)
    return crl_data

def get_current_crl() -> Dict[str, Any]:
    """Returns the latest signed CRL."""
    init_db()
    root_priv, root_pub = get_or_create_root_key()

    db = SessionLocal()
    try:
        rec = db.query(CRLRecord).order_by(CRLRecord.version.desc()).first()
        if rec:
            return json.loads(rec.crl_json)
    finally:
        db.close()

    # If no CRL yet, generate empty version 1
    crl_data = create_signed_crl([], root_priv, version=1)
    set_cached_crl(crl_data)
    return crl_data

def sync_all_certificates_to_verifier():
    """Pre-loads all registered certificates and CRL into verify engine on startup."""
    init_db()
    _, root_pub = get_or_create_root_key()
    set_pinned_root_key(root_pub)

    db = SessionLocal()
    try:
        records = db.query(IssuerRecord).all()
        if not records:
            from scripts.seed_registry import CITYPARK_PRIV_B64, SPIT_PRIV_B64
            citypark_priv = load_private_key_b64(CITYPARK_PRIV_B64)
            register_issuer(
                issuer_id="citypark-01",
                name="Mumbai Smart City Parking",
                domain="pay.citypark.example",
                issuer_pubkey_b64=export_public_key_b64(citypark_priv.public_key())
            )
            spit_priv = load_private_key_b64(SPIT_PRIV_B64)
            register_issuer(
                issuer_id="spit-admit",
                name="SPIT Admissions Authority",
                domain="spit.ac.in",
                issuer_pubkey_b64=export_public_key_b64(spit_priv.public_key())
            )
            records = db.query(IssuerRecord).all()

        for r in records:
            try:
                cert = json.loads(r.certificate_json)
                cache_certificate(r.issuer_id, cert)
            except Exception:
                pass
    finally:
        db.close()

    set_cached_crl(get_current_crl())
