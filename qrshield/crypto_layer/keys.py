"""
Ed25519 Key Management and Serialization (F23).
Uses standard cryptography.hazmat.primitives.asymmetric.ed25519.
Audited primitives: Never hand-roll crypto.
"""
import base64
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generates an Ed25519 private/public keypair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def export_public_key_b64(public_key: ed25519.Ed25519PublicKey) -> str:
    """Exports raw 32-byte public key as base64url string."""
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")

def load_public_key_b64(b64_str: str) -> ed25519.Ed25519PublicKey:
    """Loads Ed25519 public key from base64url string."""
    # Add padding if stripped
    padding = len(b64_str) % 4
    if padding:
        b64_str += "=" * (4 - padding)
    raw_bytes = base64.urlsafe_b64decode(b64_str)
    return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)

def export_private_key_b64(private_key: ed25519.Ed25519PrivateKey) -> str:
    """Exports raw 32-byte private key as base64url string."""
    raw_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")

def load_private_key_b64(b64_str: str) -> ed25519.Ed25519PrivateKey:
    """Loads Ed25519 private key from base64url string."""
    padding = len(b64_str) % 4
    if padding:
        b64_str += "=" * (4 - padding)
    raw_bytes = base64.urlsafe_b64decode(b64_str)
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw_bytes)
