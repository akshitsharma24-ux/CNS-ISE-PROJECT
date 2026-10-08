"""
FastAPI Registry Router (F26).
Public and Admin endpoints for issuer onboarding, certificate download,
revocation enforcement, and signed CRL distribution.
"""
import json
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional

from qrshield.registry.admin import (
    register_issuer,
    revoke_issuer,
    get_current_crl,
    SessionLocal,
    IssuerRecord
)
from qrshield.crypto_layer.verify import verify as crypto_verify

registry_router = APIRouter(prefix="/api/registry", tags=["Registry & PKI"])

class IssuerRegisterRequest(BaseModel):
    issuer_id: str = Field(..., example="citypark-01")
    name: str = Field(..., example="Mumbai Smart City Parking")
    domain: str = Field(..., example="pay.citypark.example")
    public_key_b64: str = Field(..., description="Ed25519 public key base64url")

class RevokeRequest(BaseModel):
    reason: Optional[str] = "Compromised key"

class VerifyRequest(BaseModel):
    payload: str = Field(..., example="https://pay.citypark.example/m/42?qrs=...")

@registry_router.post("/issuers")
def api_register_issuer(req: IssuerRegisterRequest):
    """Registers an organization and returns an Ed25519 root-signed certificate."""
    try:
        cert = register_issuer(
            issuer_id=req.issuer_id,
            name=req.name,
            domain=req.domain,
            issuer_pubkey_b64=req.public_key_b64
        )
        return {"success": True, "certificate": cert}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@registry_router.get("/issuers/{issuer_id}/cert")
def api_get_certificate(issuer_id: str):
    """Retrieves public certificate for an issuer for offline client caching."""
    db = SessionLocal()
    try:
        rec = db.query(IssuerRecord).filter_by(issuer_id=issuer_id).first()
        if not rec:
            raise HTTPException(status_code=404, detail="Issuer not found")
        return json.loads(rec.certificate_json)
    finally:
        db.close()

@registry_router.post("/issuers/{issuer_id}/revoke")
def api_revoke_issuer(issuer_id: str, req: RevokeRequest):
    """Revokes an issuer certificate and publishes a new signed CRL version."""
    try:
        crl = revoke_issuer(issuer_id, reason=req.reason)
        return {
            "success": True,
            "message": f"Issuer '{issuer_id}' revoked.",
            "crl_version": crl.get("version")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@registry_router.get("/crl")
def api_get_crl():
    """Returns the latest signed Certificate Revocation List (CRL)."""
    return get_current_crl()

@registry_router.post("/verify")
def api_verify_crypto(req: VerifyRequest):
    """Server-side endpoint to verify a signed QR payload."""
    return crypto_verify(req.payload)
