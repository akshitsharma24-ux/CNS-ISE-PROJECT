"""
Ed25519 key management and base64url helpers (F23).

Only audited primitives from the `cryptography` package are used - no hand-rolled crypto.
"""
from __future__ import annotations

import base64
import binascii
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def b64u_encode(raw: bytes) -> str:
    """base64url without padding (compact, URL- and QR-friendly)."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    """Strict base64url decode that tolerates stripped padding."""
    if not isinstance(text, str):
        raise ValueError("base64url value must be a string")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64url: {exc}") from exc


def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def export_public_key_b64(public_key: ed25519.Ed25519PublicKey) -> str:
    return b64u_encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    )


def export_private_key_b64(private_key: ed25519.Ed25519PrivateKey) -> str:
    return b64u_encode(
        private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def load_public_key_b64(text: str) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(b64u_decode(text))


def load_private_key_b64(text: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(b64u_decode(text))
