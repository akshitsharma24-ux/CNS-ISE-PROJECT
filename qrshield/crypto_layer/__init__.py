"""
M3: Crypto layer (signed QR codes with a mini-PKI).
Exposes the `crypto_layer.verify(payload)` contract.
"""
from qrshield.crypto_layer.keys import (
    b64u_decode,
    b64u_encode,
    export_private_key_b64,
    export_public_key_b64,
    generate_keypair,
    load_private_key_b64,
    load_public_key_b64,
)
from qrshield.crypto_layer.pki import (
    CertificateError,
    create_issuer_certificate,
    validate_certified_domain,
    verify_domain_binding,
    verify_issuer_certificate,
)
from qrshield.crypto_layer.revocation import (
    create_signed_crl,
    is_revoked,
    key_revocation_id,
    verify_crl,
)
from qrshield.crypto_layer.token import (
    TokenError,
    canonicalize_url,
    extract_token_from_url,
    sign_url_token,
)
from qrshield.crypto_layer.verify import (
    DEFAULT_STORE,
    TrustStore,
    cache_certificate,
    set_cached_crl,
    set_pinned_root_key,
    verify,
)

__all__ = [
    "b64u_decode", "b64u_encode", "export_private_key_b64", "export_public_key_b64",
    "generate_keypair", "load_private_key_b64", "load_public_key_b64",
    "CertificateError", "create_issuer_certificate", "validate_certified_domain",
    "verify_domain_binding", "verify_issuer_certificate",
    "create_signed_crl", "is_revoked", "key_revocation_id", "verify_crl",
    "TokenError", "canonicalize_url", "extract_token_from_url", "sign_url_token",
    "DEFAULT_STORE", "TrustStore", "cache_certificate", "set_cached_crl",
    "set_pinned_root_key", "verify",
]
