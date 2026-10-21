"""
Mini-PKI: root-signed issuer certificates and strict domain binding (F24).

Certificates are compact JSON documents signed with Ed25519 by the registry root key
(whose public half is pinned in the verifier). An issuer may only certify URLs whose host
is its bound domain or a subdomain of it.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from qrshield.crypto_layer.keys import b64u_decode, b64u_encode, export_public_key_b64
from qrshield.netutil import hostname_of, is_ip_literal, is_valid_hostname, split_host

CERT_CONTEXT = b"QRSHIELD-CERT-v1\x00"
DEFAULT_KEY_ID = "key-1"
DEFAULT_VALIDITY_SECONDS = 365 * 24 * 3600


class CertificateError(ValueError):
    pass


def validate_certified_domain(domain: str) -> str:
    """Normalise and sanity-check a domain an issuer wants to be bound to.

    Rejects IP literals, malformed names and bare public suffixes (an issuer bound to
    "com" or "co.in" could otherwise certify every site under that suffix).
    """
    value = (domain or "").strip().lower().rstrip(".")
    if not is_valid_hostname(value) or is_ip_literal(value) or "." not in value:
        raise CertificateError(f"'{domain}' is not a valid domain name")
    parts = split_host(value)
    if not parts.sld or not parts.suffix or parts.registered == parts.suffix:
        raise CertificateError(f"'{domain}' is a bare public suffix and cannot be certified")
    return value


def _canonical_cert_bytes(cert: Dict[str, Any]) -> bytes:
    body = {k: v for k, v in cert.items() if k != "sig"}
    return CERT_CONTEXT + json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def create_issuer_certificate(
    issuer_id: str,
    name: str,
    domain: str,
    issuer_public_key: ed25519.Ed25519PublicKey,
    root_private_key: ed25519.Ed25519PrivateKey,
    valid_from: Optional[int] = None,
    valid_to: Optional[int] = None,
    key_id: str = DEFAULT_KEY_ID,
) -> Dict[str, Any]:
    now = int(time.time())
    cert = {
        "v": 1,
        "issuer_id": issuer_id,
        "name": name,
        "domain": validate_certified_domain(domain),
        "kid": key_id,
        "issuer_pubkey": export_public_key_b64(issuer_public_key),
        "valid_from": now - 300 if valid_from is None else int(valid_from),
        "valid_to": now + DEFAULT_VALIDITY_SECONDS if valid_to is None else int(valid_to),
    }
    cert["sig"] = b64u_encode(root_private_key.sign(_canonical_cert_bytes(cert)))
    return cert


def verify_issuer_certificate(
    cert: Dict[str, Any], root_public_key: ed25519.Ed25519PublicKey, now: Optional[int] = None
) -> Tuple[bool, str]:
    """Check the root signature and validity window of an issuer certificate."""
    try:
        sig = b64u_decode(cert.get("sig") or "")
        root_public_key.verify(sig, _canonical_cert_bytes(cert))
    except (InvalidSignature, ValueError, AttributeError, TypeError):
        return False, "certificate is not signed by the pinned root key"
    now = int(time.time()) if now is None else now
    if now < int(cert.get("valid_from", 0)):
        return False, "certificate is not yet valid"
    if now > int(cert.get("valid_to", 0)):
        return False, "certificate has expired"
    return True, "certificate valid"


def verify_domain_binding(cert: Dict[str, Any], target_url: str) -> bool:
    """True only if the URL host equals the certified domain or is a true subdomain of it."""
    host = hostname_of(target_url)
    bound = str(cert.get("domain", "")).lower().rstrip(".")
    if not host or not bound:
        return False
    return host == bound or host.endswith("." + bound)
