"""
Canonical URL Encoding and QR Token Serialization (F23, F25).
Domain separation context: 'QRSHIELD-v1'.
Graceful degradation: Normal scanners open clean URL while QRshield verifies token.
"""
import json
import base64
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

DOMAIN_SEPARATOR = "QRSHIELD-v1"

def canonicalize_url(url: str) -> str:
    """
    Standardizes a URL for deterministic cryptographic signing/verification:
    1. Strips any existing 'qrs' parameter.
    2. Lowercases scheme and host.
    3. Normalizes path (empty path -> '/').
    4. Sorts all query parameters alphabetically by key.
    5. Strips fragment (#...).
    """
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"

    # Parse and filter query parameters
    query_tuples = parse_qsl(parsed.query, keep_blank_values=True)
    filtered = [(k, v) for k, v in query_tuples if k.lower() != "qrs"]
    # Sort deterministically
    sorted_params = sorted(filtered, key=lambda x: (x[0], x[1]))
    new_query = urlencode(sorted_params)

    # Reconstruct canonical URL (empty fragment)
    canonical = urlunparse((scheme, netloc, path, "", new_query, ""))
    return canonical

def build_signature_message(
    canonical_url: str,
    issuer_id: str,
    key_id: str,
    location_id: str,
    iat: int,
    exp: int
) -> bytes:
    """
    Constructs the domain-separated canonical byte sequence for signing.
    sig_payload = "QRSHIELD-v1" | canonical_url | iss | kid | loc | iat | exp
    Delimited by null bytes (\x00) to prevent field ambiguity or injection.
    """
    parts = [
        DOMAIN_SEPARATOR,
        canonical_url,
        str(issuer_id),
        str(key_id),
        str(location_id),
        str(iat),
        str(exp)
    ]
    return "\x00".join(parts).encode("utf-8")

def sign_url_token(
    url: str,
    private_key: ed25519.Ed25519PrivateKey,
    issuer_id: str,
    key_id: str,
    location_id: str = "counter-01",
    iat: int = 0,
    exp: int = 0
) -> Tuple[str, Dict[str, Any]]:
    """
    Signs a URL and embeds the signature in a 'qrs' parameter.
    Returns:
      (signed_url, token_dict)
    """
    canonical_url = canonicalize_url(url)
    msg = build_signature_message(canonical_url, issuer_id, key_id, location_id, iat, exp)

    raw_sig = private_key.sign(msg)
    sig_b64 = base64.urlsafe_b64encode(raw_sig).decode("ascii").rstrip("=")

    token = {
        "v": 1,
        "iss": issuer_id,
        "kid": key_id,
        "loc": location_id,
        "iat": iat,
        "exp": exp,
        "sig": sig_b64
    }

    # Encode token as compact JSON and base64url
    token_json = json.dumps(token, separators=(',', ':'))
    token_b64 = base64.urlsafe_b64encode(token_json.encode("utf-8")).decode("ascii").rstrip("=")

    # Embed in target URL
    parsed = urlparse(url)
    queries = parse_qsl(parsed.query, keep_blank_values=True)
    queries = [(k, v) for k, v in queries if k.lower() != "qrs"]
    queries.append(("qrs", token_b64))
    new_query = urlencode(queries)

    signed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    return signed_url, token

def extract_token_from_url(url: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """
    Extracts and parses the 'qrs' token from a URL.
    Returns: (token_dict_or_None, canonical_url_without_qrs)
    """
    canonical_url = canonicalize_url(url)
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))

    token_b64 = params.get("qrs")
    if not token_b64:
        return None, canonical_url

    try:
        # Add padding
        padding = len(token_b64) % 4
        if padding:
            token_b64 += "=" * (4 - padding)
        token_json_bytes = base64.urlsafe_b64decode(token_b64)
        token_dict = json.loads(token_json_bytes.decode("utf-8"))
        return token_dict, canonical_url
    except Exception:
        return {"error": "malformed_token"}, canonical_url
