"""
M3: Crypto Layer (Signed QR Codes with Mini-PKI)
Exposes crypto_layer.verify(payload: str) contract.
"""
from qrshield.crypto_layer.verify import (
    verify,
    set_pinned_root_key,
    cache_certificate,
    set_cached_crl,
    CERTIFICATE_CACHE
)
from qrshield.crypto_layer.keys import (
    generate_keypair,
    export_public_key_b64,
    load_public_key_b64,
    export_private_key_b64,
    load_private_key_b64
)
from qrshield.crypto_layer.token import (
    sign_url_token,
    extract_token_from_url,
    canonicalize_url
)
from qrshield.crypto_layer.pki import (
    create_issuer_certificate,
    verify_issuer_certificate,
    verify_domain_binding
)
from qrshield.crypto_layer.revocation import (
    create_signed_crl,
    verify_crl,
    is_revoked
)

__all__ = [
    "verify",
    "set_pinned_root_key",
    "cache_certificate",
    "set_cached_crl",
    "CERTIFICATE_CACHE",
    "generate_keypair",
    "export_public_key_b64",
    "load_public_key_b64",
    "export_private_key_b64",
    "load_private_key_b64",
    "sign_url_token",
    "extract_token_from_url",
    "canonicalize_url",
    "create_issuer_certificate",
    "verify_issuer_certificate",
    "verify_domain_binding",
    "create_signed_crl",
    "verify_crl",
    "is_revoked"
]
