"""
Certificate Revocation List (CRL) Management (F26, F28).
Maintains root-signed CRL data structure carrying version, issue timestamp,
revoked issuer/key IDs, and revocation reasons.
"""
import json
import base64
import time
from typing import Dict, Any, List, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

def create_signed_crl(
    revoked_entries: List[Dict[str, Any]],
    root_private_key: ed25519.Ed25519PrivateKey,
    version: int = 1
) -> Dict[str, Any]:
    """
    Creates a signed CRL structure signed by the root authority.
    """
    now = int(time.time())
    crl_data = {
        "version": version,
        "issued_at": now,
        "next_update": now + (7 * 24 * 3600),  # 7 days
        "revoked": revoked_entries  # list of {"id": str, "revoked_at": int, "reason": str}
    }

    crl_canonical = json.dumps(crl_data, sort_keys=True, separators=(',', ':')).encode("utf-8")
    sig = root_private_key.sign(b"QRSHIELD-CRL-v1\x00" + crl_canonical)

    crl_data["sig"] = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    return crl_data

def verify_crl(crl: Dict[str, Any], root_public_key: ed25519.Ed25519PublicKey) -> Tuple[bool, str]:
    """Verifies cryptographic signature on the CRL."""
    try:
        crl_copy = dict(crl)
        sig_b64 = crl_copy.pop("sig", None)
        if not sig_b64:
            return False, "CRL signature missing"

        padding = len(sig_b64) % 4
        if padding:
            sig_b64 += "=" * (4 - padding)
        sig_bytes = base64.urlsafe_b64decode(sig_b64)

        canonical_bytes = json.dumps(crl_copy, sort_keys=True, separators=(',', ':')).encode("utf-8")
        root_public_key.verify(sig_bytes, b"QRSHIELD-CRL-v1\x00" + canonical_bytes)
        return True, "CRL valid"
    except InvalidSignature:
        return False, "Invalid CRL signature"
    except Exception as e:
        return False, f"CRL verification error: {str(e)}"

def is_revoked(crl: Dict[str, Any], identifier: str) -> Tuple[bool, str]:
    """
    Checks if an issuer_id or key_id is present in the CRL.
    """
    if not crl:
        return False, ""
    revoked_list = crl.get("revoked", [])
    for entry in revoked_list:
        if entry.get("id") == identifier:
            return True, entry.get("reason", "Revocation requested")
    return False, ""
