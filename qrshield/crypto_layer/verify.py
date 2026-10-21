"""
M3 verification: trust store + the signed-QR verification algorithm.

Algorithm (every failure is *closed*: no pinned root means nothing verifies):

 1. No `qrs` parameter                          -> "none" (unsigned; falls to M1 + M2)
 2. Malformed token                             -> "invalid"
 3. Issuer certificate unknown, or not signed by
    the pinned root / outside its validity      -> "unknown_issuer"
 4. Issuer or key listed in the signed CRL      -> "revoked"
 5. Ed25519 signature over the canonical URL    -> "invalid" on failure
 6. URL host outside the certified domain       -> "domain_mismatch"
 7. Token past `exp`                            -> "expired"
 8. Otherwise                                   -> "valid"

The signature is verified before expiry/domain are trusted, so a forged token can never
downgrade itself to the milder "expired" verdict.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from qrshield.crypto_layer.keys import b64u_decode, load_public_key_b64
from qrshield.crypto_layer.pki import verify_domain_binding, verify_issuer_certificate
from qrshield.crypto_layer.revocation import is_revoked, key_revocation_id, verify_crl
from qrshield.crypto_layer.token import build_signature_message, extract_token_from_url

CLOCK_SKEW_SECONDS = 600


class TrustStore:
    """Pinned root key + issuer certificate cache + latest verified CRL (F28 offline mode)."""

    def __init__(
        self,
        root_public_key: Optional[ed25519.Ed25519PublicKey] = None,
        resolver: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
    ):
        self._lock = threading.RLock()
        self.root_public_key = root_public_key
        self.resolver = resolver          # registry lookup used on a cache miss
        self._certs: Dict[str, Dict[str, Any]] = {}
        self._crl: Optional[Dict[str, Any]] = None

    def set_root(self, public_key: ed25519.Ed25519PublicKey) -> None:
        with self._lock:
            if self.root_public_key is not None and self.root_public_key != public_key:
                self._certs.clear()       # trust anchor changed: nothing cached stays valid
                self._crl = None
            self.root_public_key = public_key

    def add_certificate(self, cert: Dict[str, Any]) -> None:
        with self._lock:
            self._certs[cert["issuer_id"]] = cert

    def get_certificate(self, issuer_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            cert = self._certs.get(issuer_id)
        if cert is None and self.resolver is not None:
            try:
                cert = self.resolver(issuer_id)
            except Exception:
                cert = None
            if cert:
                self.add_certificate(cert)
        return cert

    def install_crl(self, crl: Dict[str, Any]) -> Tuple[bool, str]:
        """Accept a CRL only if root-signed and not older than the one we hold."""
        with self._lock:
            if self.root_public_key is None:
                return False, "no pinned root key"
            ok, msg = verify_crl(crl, self.root_public_key)
            if not ok:
                return False, msg
            if self._crl is not None and int(crl.get("version", 0)) < int(self._crl.get("version", 0)):
                return False, "CRL rollback rejected"
            self._crl = crl
            return True, "CRL installed"

    @property
    def crl(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._crl

    def clear(self) -> None:
        with self._lock:
            self._certs.clear()
            self._crl = None


DEFAULT_STORE = TrustStore()


# ---- convenience wrappers that act on the default store (module contract) -----
def set_pinned_root_key(public_key: ed25519.Ed25519PublicKey) -> None:
    DEFAULT_STORE.set_root(public_key)


def cache_certificate(issuer_id: str, cert: Dict[str, Any]) -> None:
    DEFAULT_STORE.add_certificate({**cert, "issuer_id": issuer_id})


def set_cached_crl(crl: Dict[str, Any]) -> Tuple[bool, str]:
    return DEFAULT_STORE.install_crl(crl)


def _result(status: str, issuer: Optional[Dict[str, Any]] = None, detail: str = "") -> Dict[str, Any]:
    return {"status": status, "issuer": issuer, "detail": detail}


def verify(payload: str, store: Optional[TrustStore] = None, now: Optional[int] = None) -> Dict[str, Any]:
    """crypto_layer.verify contract: {"status", "issuer", "detail"}."""
    store = store or DEFAULT_STORE
    now = int(time.time()) if now is None else int(now)
    if not payload:
        return _result("none")

    token, canonical = extract_token_from_url(payload)
    if token is None:
        return _result("none", detail="unsigned QR code")
    if "error" in token:
        return _result("invalid", detail=f"malformed token ({token['error']})")

    issuer_id, key_id, loc = token["iss"], token["kid"], token["loc"]

    if store.root_public_key is None:
        return _result("unknown_issuer", detail="no pinned root key configured; cannot verify")

    cert = store.get_certificate(issuer_id)
    if not cert:
        return _result("unknown_issuer", detail=f"issuer '{issuer_id}' is not registered")

    ok, why = verify_issuer_certificate(cert, store.root_public_key, now)
    if not ok:
        return _result("unknown_issuer", detail=why)

    issuer_info = {
        "issuer_id": issuer_id,
        "name": cert.get("name", "Unknown"),
        "domain": cert.get("domain", ""),
        "key_id": key_id,
        "location_id": loc,
        "issued_at": token["iat"],
        "token_expires_at": token["exp"],
        "cert_valid_to": cert.get("valid_to"),
    }

    crl = store.crl
    for ident in (issuer_id, key_revocation_id(issuer_id, key_id)):
        revoked, reason = is_revoked(crl, ident)
        if revoked:
            return _result("revoked", issuer_info, f"revoked by registry: {reason}")

    if cert.get("kid", key_id) != key_id:
        return _result("invalid", issuer_info, "token key id does not match the certified key")

    try:
        message = build_signature_message(canonical, issuer_id, key_id, loc, token["iat"], token["exp"])
        issuer_pub = load_public_key_b64(cert["issuer_pubkey"])
        issuer_pub.verify(b64u_decode(token["sig"]), message)
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return _result("invalid", issuer_info, "signature does not verify against the certified key")

    # Signature is genuine from here on: the remaining checks are about *policy*.
    if not verify_domain_binding(cert, payload):
        return _result("domain_mismatch", issuer_info, "issuer is not authorised for this domain")
    if token["iat"] > now + CLOCK_SKEW_SECONDS:
        return _result("invalid", issuer_info, "token issued in the future")
    if token["exp"] and now > token["exp"]:
        return _result("expired", issuer_info, "token validity window has passed")
    return _result("valid", issuer_info, "signature, certificate chain and domain binding verified")
