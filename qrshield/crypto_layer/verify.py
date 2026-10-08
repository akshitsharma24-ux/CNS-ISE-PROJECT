"""
Cryptographic Verification Engine (M3).
Implements the 5-step verification algorithm:
1. No qrs -> 'none'
2. Parse token -> 'invalid' / 'unknown_issuer'
3. Certificate verify with pinned root & CRL check -> 'revoked'
4. Expiry & domain binding check -> 'expired' / 'domain_mismatch'
5. Token Ed25519 signature verify -> 'valid' / 'invalid'
"""
import time
import base64
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from qrshield.crypto_layer.keys import load_public_key_b64
from qrshield.crypto_layer.token import (
    extract_token_from_url,
    build_signature_message,
    canonicalize_url
)
from qrshield.crypto_layer.pki import (
    verify_issuer_certificate,
    verify_domain_binding
)
from qrshield.crypto_layer.revocation import is_revoked

# Local in-memory certificate cache for instant local and offline verification (F28)
CERTIFICATE_CACHE: Dict[str, Dict[str, Any]] = {}
PINNED_ROOT_KEY: Optional[ed25519.Ed25519PublicKey] = None
CACHED_CRL: Optional[Dict[str, Any]] = None

def set_pinned_root_key(pubkey: ed25519.Ed25519PublicKey):
    """Sets the application pinned root public key."""
    global PINNED_ROOT_KEY
    PINNED_ROOT_KEY = pubkey

def cache_certificate(issuer_id: str, cert_dict: Dict[str, Any]):
    """Caches an issuer certificate locally for offline validation."""
    CERTIFICATE_CACHE[issuer_id] = cert_dict

def set_cached_crl(crl_dict: Dict[str, Any]):
    """Updates the cached Certificate Revocation List."""
    global CACHED_CRL
    CACHED_CRL = crl_dict

def verify(payload: str) -> Dict[str, Any]:
    """
    Contract specified in QRshield Master Plan:
    crypto_layer.verify(payload:str) -> {
        "status":"none|valid|invalid|unknown_issuer|revoked|expired|domain_mismatch",
        "issuer":{"name":str, "domain":str, "key_id":str} | None
    }
    """
    if not payload:
        return {"status": "none", "issuer": None}

    # Step 1: No qrs parameter -> status 'none'
    token_dict, canonical_url = extract_token_from_url(payload)
    if token_dict is None:
        return {"status": "none", "issuer": None}

    if token_dict.get("error") or token_dict.get("v") != 1:
        return {"status": "invalid", "issuer": None}

    issuer_id = token_dict.get("iss")
    key_id = token_dict.get("kid", "key-1")
    loc_id = token_dict.get("loc", "")
    iat = token_dict.get("iat", 0)
    exp = token_dict.get("exp", 0)
    sig_b64 = token_dict.get("sig", "")

    if not issuer_id or not sig_b64:
        return {"status": "invalid", "issuer": None}

    # Step 2: Lookup issuer certificate (cache first, then registry)
    cert = CERTIFICATE_CACHE.get(issuer_id)
    if not cert:
        try:
            import json
            from qrshield.registry.admin import SessionLocal, IssuerRecord
            db = SessionLocal()
            try:
                rec = db.query(IssuerRecord).filter_by(issuer_id=issuer_id).first()
                if rec and rec.certificate_json:
                    cert = json.loads(rec.certificate_json)
                    CERTIFICATE_CACHE[issuer_id] = cert
            finally:
                db.close()
        except Exception:
            pass

    if not cert:
        return {"status": "unknown_issuer", "issuer": None}

    issuer_info = {
        "name": cert.get("name", "Unknown"),
        "domain": cert.get("domain", ""),
        "key_id": key_id,
        "issuer_id": issuer_id,
        "location_id": loc_id
    }

    # Step 3: Verify certificate with pinned root key & CRL
    global PINNED_ROOT_KEY, CACHED_CRL
    if PINNED_ROOT_KEY is None:
        try:
            from qrshield.registry.admin import get_or_create_root_key
            _, PINNED_ROOT_KEY = get_or_create_root_key()
        except Exception:
            pass

    if PINNED_ROOT_KEY is not None:
        cert_ok, _ = verify_issuer_certificate(cert, PINNED_ROOT_KEY)
        if not cert_ok:
            return {"status": "invalid", "issuer": issuer_info}

    # Check CRL
    if CACHED_CRL is None:
        try:
            from qrshield.registry.admin import get_current_crl
            CACHED_CRL = get_current_crl()
        except Exception:
            pass

    if CACHED_CRL is not None:
        revoked_iss, _ = is_revoked(CACHED_CRL, issuer_id)
        revoked_key, _ = is_revoked(CACHED_CRL, key_id)
        if revoked_iss or revoked_key:
            return {"status": "revoked", "issuer": issuer_info}


    # Step 4: Expiry and Domain Binding check
    now = int(time.time())
    if exp > 0 and now > exp:
        return {"status": "expired", "issuer": issuer_info}

    if not verify_domain_binding(cert, payload):
        return {"status": "domain_mismatch", "issuer": issuer_info}

    # Step 5: Verify the token Ed25519 signature over canonical URL
    try:
        padding = len(sig_b64) % 4
        if padding:
            sig_b64 += "=" * (4 - padding)
        sig_bytes = base64.urlsafe_b64decode(sig_b64)

        issuer_pubkey_b64 = cert.get("issuer_pubkey", "")
        issuer_pubkey = load_public_key_b64(issuer_pubkey_b64)

        msg = build_signature_message(canonical_url, issuer_id, key_id, loc_id, iat, exp)
        issuer_pubkey.verify(sig_bytes, msg)
        return {"status": "valid", "issuer": issuer_info}
    except InvalidSignature:
        return {"status": "invalid", "issuer": issuer_info}
    except Exception:
        return {"status": "invalid", "issuer": issuer_info}
