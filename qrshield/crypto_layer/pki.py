"""
Mini-PKI: Certificate issuance, pinned root authority, and domain binding (F24).
Signs and verifies issuer certificates with Ed25519.
Enforces strict domain binding: an issuer cannot sign for domains outside its certificate.
"""
import json
import base64
import time
from urllib.parse import urlparse
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from qrshield.crypto_layer.keys import export_public_key_b64, load_public_key_b64

# Pinned Root Public Key for QRshield (Demo trust anchor)
PINNED_ROOT_PUBLIC_KEY_B64 = "k8vW6vWpZcTz5gT1xV2B7qM4yH6nK3jL8aP9wE2rT1Y"  # Default fallback placeholder

def create_issuer_certificate(
    issuer_id: str,
    name: str,
    domain: str,
    issuer_public_key: ed25519.Ed25519PublicKey,
    root_private_key: ed25519.Ed25519PrivateKey,
    valid_from: int = None,
    valid_to: int = None
) -> Dict[str, Any]:
    """
    Creates an X.509-style JSON issuer certificate signed by the Root Authority.
    """
    now = int(time.time())
    if valid_from is None:
        valid_from = now - 3600  # 1 hour ago
    if valid_to is None:
        valid_to = now + (365 * 24 * 3600)  # 1 year validity

    cert_data = {
        "v": 1,
        "issuer_id": issuer_id,
        "name": name,
        "domain": domain.lower().strip(),
        "issuer_pubkey": export_public_key_b64(issuer_public_key),
        "valid_from": valid_from,
        "valid_to": valid_to
    }

    # Canonical message for certificate signature
    cert_canonical = json.dumps(cert_data, sort_keys=True, separators=(',', ':')).encode("utf-8")
    cert_sig = root_private_key.sign(b"QRSHIELD-CERT-v1\x00" + cert_canonical)

    cert_data["sig"] = base64.urlsafe_b64encode(cert_sig).decode("ascii").rstrip("=")
    return cert_data

def verify_issuer_certificate(
    cert: Dict[str, Any],
    root_public_key: ed25519.Ed25519PublicKey
) -> Tuple[bool, str]:
    """
    Validates certificate cryptographic signature against pinned root authority
    and verifies the temporal validity window.
    """
    try:
        cert_copy = dict(cert)
        sig_b64 = cert_copy.pop("sig", None)
        if not sig_b64:
            return False, "Certificate signature missing"

        padding = len(sig_b64) % 4
        if padding:
            sig_b64 += "=" * (4 - padding)
        sig_bytes = base64.urlsafe_b64decode(sig_b64)

        canonical_bytes = json.dumps(cert_copy, sort_keys=True, separators=(',', ':')).encode("utf-8")
        root_public_key.verify(sig_bytes, b"QRSHIELD-CERT-v1\x00" + canonical_bytes)

        # Check temporal validity
        now = int(time.time())
        if now < cert.get("valid_from", 0):
            return False, "Certificate not yet active"
        if now > cert.get("valid_to", 0):
            return False, "Certificate expired"

        return True, "Certificate valid"
    except InvalidSignature:
        return False, "Invalid certificate signature"
    except Exception as e:
        return False, f"Certificate validation error: {str(e)}"

def verify_domain_binding(cert: Dict[str, Any], target_url: str) -> bool:
    """
    Verifies that the target URL host matches or is a valid subdomain of
    the domain bound in the issuer certificate (F24).
    """
    parsed = urlparse(target_url)
    host = (parsed.hostname or parsed.netloc.split(":")[0]).lower()
    certified_domain = cert.get("domain", "").lower()

    if not certified_domain or not host:
        return False

    # Exact match: pay.citypark.example == pay.citypark.example
    if host == certified_domain:
        return True

    # Subdomain match: api.citypark.example ends with .citypark.example
    if host.endswith("." + certified_domain):
        return True

    return False
