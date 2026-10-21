"""
Canonical URL encoding and the compact QR token (F23, F25).

A signed QR is an ordinary URL with one extra query parameter, so any phone camera still
opens the business URL (graceful degradation). QRshield additionally verifies the token.

Token (binary, base64url in `?qrs=`; ~140 chars so the printed code stays easy to scan):

    0x01 | iat u32 | exp u32 | len+iss | len+kid | len+loc | Ed25519 signature (64 B)

Signed message (domain separated, NUL-delimited, never reusable in another protocol):

    "QRSHIELD-v1" 00 canonical_url 00 iss 00 kid 00 loc 00 iat 00 exp
"""
from __future__ import annotations

import struct
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlunparse

from cryptography.hazmat.primitives.asymmetric import ed25519

from qrshield.crypto_layer.keys import b64u_decode, b64u_encode
from qrshield.netutil import safe_urlparse

DOMAIN_SEPARATOR = "QRSHIELD-v1"
TOKEN_VERSION = 1
TOKEN_PARAM = "qrs"
MAX_FIELD = 64
_DEFAULT_PORTS = {"http": 80, "https": 443}


class TokenError(ValueError):
    """Raised for tokens/URLs that cannot be canonicalised, signed or parsed."""


def canonicalize_url(url: str) -> str:
    """Deterministic URL form shared by signer and verifier.

    Lower-cases scheme and host, drops the default port and fragment, forces an explicit
    path, strips the `qrs` parameter and sorts the remaining query. URLs carrying userinfo
    (`user@host`) are rejected outright: it is the classic host-spoofing trick.
    """
    parsed = safe_urlparse((url or "").strip())
    if parsed is None or parsed.scheme.lower() not in ("http", "https"):
        raise TokenError("only absolute http(s) URLs can be signed")
    try:
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise TokenError(f"invalid host/port: {exc}") from exc
    if not host:
        raise TokenError("URL has no host")
    if parsed.username is not None or parsed.password is not None:
        raise TokenError("URLs with userinfo are not allowed")

    scheme = parsed.scheme.lower()
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        netloc = f"{netloc}:{port}"
    query = sorted(
        (k, v)
        for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        if k.lower() != TOKEN_PARAM
    )
    return urlunparse((scheme, netloc, parsed.path or "/", "", urlencode(query), ""))


def build_signature_message(
    canonical_url: str, issuer_id: str, key_id: str, location_id: str, iat: int, exp: int
) -> bytes:
    for name, value in (("issuer", issuer_id), ("key id", key_id), ("location", location_id)):
        if "\x00" in value:
            raise TokenError(f"{name} must not contain NUL")
    parts = [DOMAIN_SEPARATOR, canonical_url, issuer_id, key_id, location_id, str(int(iat)), str(int(exp))]
    return "\x00".join(parts).encode("utf-8")


def _pack_field(value: str, name: str) -> bytes:
    raw = value.encode("utf-8")
    if not raw or len(raw) > MAX_FIELD:
        raise TokenError(f"{name} must be 1-{MAX_FIELD} bytes")
    return bytes([len(raw)]) + raw


def pack_token(issuer_id: str, key_id: str, location_id: str, iat: int, exp: int, signature: bytes) -> str:
    if len(signature) != 64:
        raise TokenError("Ed25519 signatures are 64 bytes")
    if not (0 <= iat < 2**32 and 0 <= exp < 2**32):
        raise TokenError("timestamps must fit in 32 bits")
    body = (
        bytes([TOKEN_VERSION])
        + struct.pack(">II", int(iat), int(exp))
        + _pack_field(issuer_id, "issuer")
        + _pack_field(key_id, "key id")
        + _pack_field(location_id, "location")
        + signature
    )
    return b64u_encode(body)


def unpack_token(token_b64: str) -> Dict[str, Any]:
    """Parse a token; raises TokenError on any structural problem."""
    try:
        raw = b64u_decode(token_b64)
    except ValueError as exc:
        raise TokenError("malformed base64") from exc
    if len(raw) < 1 + 8 + 3 + 64:
        raise TokenError("token too short")
    version = raw[0]
    if version != TOKEN_VERSION:
        raise TokenError(f"unsupported token version {version}")
    iat, exp = struct.unpack(">II", raw[1:9])
    pos = 9
    fields = []
    for _ in range(3):
        if pos >= len(raw):
            raise TokenError("truncated token")
        n = raw[pos]
        pos += 1
        chunk = raw[pos : pos + n]
        if n == 0 or len(chunk) != n:
            raise TokenError("truncated token field")
        try:
            fields.append(chunk.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise TokenError("non-UTF-8 field") from exc
        pos += n
    signature = raw[pos:]
    if len(signature) != 64:
        raise TokenError("bad signature length")
    return {
        "v": version, "iss": fields[0], "kid": fields[1], "loc": fields[2],
        "iat": iat, "exp": exp, "sig": b64u_encode(signature),
    }


def sign_url_token(
    url: str,
    private_key: ed25519.Ed25519PrivateKey,
    issuer_id: str,
    key_id: str,
    location_id: str = "counter-01",
    iat: int = 0,
    exp: int = 0,
) -> Tuple[str, Dict[str, Any]]:
    """Sign `url` and return (signed_url, token_dict). exp=0 means "does not expire"."""
    canonical = canonicalize_url(url)
    message = build_signature_message(canonical, issuer_id, key_id, location_id, iat, exp)
    signature = private_key.sign(message)
    token_b64 = pack_token(issuer_id, key_id, location_id, iat, exp, signature)

    parsed = safe_urlparse(url.strip())
    query = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k.lower() != TOKEN_PARAM]
    query.append((TOKEN_PARAM, token_b64))
    signed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(query), parsed.fragment))
    token = {"v": TOKEN_VERSION, "iss": issuer_id, "kid": key_id, "loc": location_id,
             "iat": int(iat), "exp": int(exp), "sig": b64u_encode(signature)}
    return signed_url, token


def extract_token_from_url(url: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """Return (token_dict | None, canonical_url_without_qrs).

    None  -> the URL carries no `qrs` parameter (unsigned, not an error).
    {"error": ...} -> a `qrs` parameter is present but unusable.
    """
    parsed = safe_urlparse((url or "").strip())
    if parsed is None:
        return {"error": "unparseable_url"}, ""
    values = [v for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k.lower() == TOKEN_PARAM]
    if not values:
        try:
            return None, canonicalize_url(url)
        except TokenError:
            return None, ""
    try:
        canonical = canonicalize_url(url)
    except TokenError as exc:
        return {"error": str(exc)}, ""
    if len(values) != 1:                       # ambiguous duplicate tokens
        return {"error": "duplicate_token_parameter"}, canonical
    try:
        return unpack_token(values[0]), canonical
    except TokenError as exc:
        return {"error": str(exc)}, canonical
