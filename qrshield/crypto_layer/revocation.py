"""
Certificate Revocation List (F26, F28).

A root-signed, versioned list of revoked identifiers:
  * `<issuer_id>`            - the whole issuer is revoked
  * `<issuer_id>:<key_id>`   - a single signing key is revoked (rotation / key theft)

Versions only ever increase; verifiers refuse to roll back to an older list.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from qrshield.crypto_layer.keys import b64u_decode, b64u_encode

CRL_CONTEXT = b"QRSHIELD-CRL-v1\x00"
CRL_VALIDITY_SECONDS = 7 * 24 * 3600


def key_revocation_id(issuer_id: str, key_id: str) -> str:
    return f"{issuer_id}:{key_id}"


def _canonical_crl_bytes(crl: Dict[str, Any]) -> bytes:
    body = {k: v for k, v in crl.items() if k != "sig"}
    return CRL_CONTEXT + json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def create_signed_crl(
    revoked_entries: List[Dict[str, Any]],
    root_private_key: ed25519.Ed25519PrivateKey,
    version: int = 1,
) -> Dict[str, Any]:
    now = int(time.time())
    crl = {
        "version": int(version),
        "issued_at": now,
        "next_update": now + CRL_VALIDITY_SECONDS,
        "revoked": revoked_entries,   # [{"id": str, "revoked_at": int, "reason": str}]
    }
    crl["sig"] = b64u_encode(root_private_key.sign(_canonical_crl_bytes(crl)))
    return crl


def verify_crl(crl: Dict[str, Any], root_public_key: ed25519.Ed25519PublicKey) -> Tuple[bool, str]:
    try:
        root_public_key.verify(b64u_decode(crl.get("sig") or ""), _canonical_crl_bytes(crl))
    except (InvalidSignature, ValueError, AttributeError, TypeError):
        return False, "CRL signature is invalid"
    return True, "CRL valid"


def is_revoked(crl: Optional[Dict[str, Any]], identifier: str) -> Tuple[bool, str]:
    if not crl:
        return False, ""
    for entry in crl.get("revoked", []):
        if entry.get("id") == identifier:
            return True, str(entry.get("reason", "revoked"))
    return False, ""
