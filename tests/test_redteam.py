"""
Red-Team Attack Suite (F38).
Systematic security verification across cryptographic forgeries,
SSRF evasion payloads, XSS/injection strings, and edge-case malformed inputs.
"""
import time
import pytest
from qrshield.crypto_layer import (
    generate_keypair,
    create_issuer_certificate,
    sign_url_token,
    verify,
    set_pinned_root_key,
    cache_certificate,
    set_cached_crl,
    create_signed_crl
)
from qrshield.url_layer.fetch_safe import is_ip_allowed, safe_resolve_host
from qrshield.capture.payload_types import parse_payload_type
from qrshield.capture.decode import capture_and_decode

@pytest.fixture(autouse=True)
def init_redteam_env():
    root_priv, root_pub = generate_keypair()
    set_pinned_root_key(root_pub)

    # Legitimate issuer
    legit_priv, legit_pub = generate_keypair()
    cert = create_issuer_certificate(
        issuer_id="legit-corp",
        name="Legit Corporation",
        domain="legit.example",
        issuer_public_key=legit_pub,
        root_private_key=root_priv
    )
    cache_certificate("legit-corp", cert)

    # Empty CRL initially
    crl = create_signed_crl([], root_priv, version=1)
    set_cached_crl(crl)

    return {
        "root_priv": root_priv,
        "root_pub": root_pub,
        "legit_priv": legit_priv,
        "legit_pub": legit_pub,
        "cert": cert
    }

# --- Red-Team Category 1: Cryptographic Attack Scenarios ---

def test_redteam_forged_signature(init_redteam_env):
    """Attack 1: Attacker generates random Ed25519 key and forges signature claiming legit-corp."""
    attacker_priv, _ = generate_keypair()
    forged_url, _ = sign_url_token(
        url="https://legit.example/login",
        private_key=attacker_priv,
        issuer_id="legit-corp",
        key_id="key-1"
    )
    res = verify(forged_url)
    assert res["status"] == "invalid", "Forged signature must be rejected!"

def test_redteam_self_signed_untrusted_root(init_redteam_env):
    """Attack 2: Attacker generates rogue root authority and signs their own certificate."""
    rogue_root_priv, _ = generate_keypair()
    attacker_priv, attacker_pub = generate_keypair()

    rogue_cert = create_issuer_certificate(
        issuer_id="rogue-bank",
        name="Rogue Phishing Bank",
        domain="rogue-bank.example",
        issuer_public_key=attacker_pub,
        root_private_key=rogue_root_priv  # NOT signed by pinned root!
    )
    cache_certificate("rogue-bank", rogue_cert)

    rogue_url, _ = sign_url_token(
        url="https://rogue-bank.example/login",
        private_key=attacker_priv,
        issuer_id="rogue-bank",
        key_id="key-1"
    )
    res = verify(rogue_url)
    assert res["status"] == "invalid", "Self-signed certificate not rooted in pinned key must be rejected!"

def test_redteam_domain_binding_violation(init_redteam_env):
    """Attack 3: Legitimate business key is used to sign a third-party or lookalike domain."""
    legit_priv = init_redteam_env["legit_priv"]
    # legit-corp is only certified for 'legit.example'
    unauthorized_url, _ = sign_url_token(
        url="https://phishing-site.example/login",
        private_key=legit_priv,
        issuer_id="legit-corp",
        key_id="key-1"
    )
    res = verify(unauthorized_url)
    assert res["status"] == "domain_mismatch", "Cross-domain signing must trigger domain_mismatch!"

def test_redteam_expired_token_replay(init_redteam_env):
    """Attack 4: Replaying an old token past expiration time."""
    legit_priv = init_redteam_env["legit_priv"]
    expired_url, _ = sign_url_token(
        url="https://legit.example/parking",
        private_key=legit_priv,
        issuer_id="legit-corp",
        key_id="key-1",
        iat=int(time.time()) - 10000,
        exp=int(time.time()) - 100  # Expired
    )
    res = verify(expired_url)
    assert res["status"] == "expired", "Expired token must be rejected!"

def test_redteam_revoked_key_crl(init_redteam_env):
    """Attack 5: Using compromised/revoked key listed in signed CRL."""
    legit_priv = init_redteam_env["legit_priv"]
    root_priv = init_redteam_env["root_priv"]

    url, _ = sign_url_token(
        url="https://legit.example/payment",
        private_key=legit_priv,
        issuer_id="legit-corp",
        key_id="key-1",
        iat=int(time.time()),
        exp=int(time.time()) + 3600
    )

    # Publish revocation
    revoked_crl = create_signed_crl([
        {"id": "legit-corp", "revoked_at": int(time.time()), "reason": "Compromised key"}
    ], root_priv, version=2)
    set_cached_crl(revoked_crl)

    res = verify(url)
    assert res["status"] == "revoked", "Revoked issuer must be rejected by CRL!"

# --- Red-Team Category 2: SSRF Network Evasion Scenarios ---

@pytest.mark.parametrize("ssrf_target", [
    "127.0.0.1",
    "127.0.1.5",
    "10.0.0.1",
    "172.16.0.5",
    "192.168.1.1",
    "169.254.169.254",  # AWS/GCP Metadata
    "100.64.0.1",       # Carrier-Grade NAT
    "0.0.0.0",
    "::1"
])
def test_redteam_ssrf_ip_ranges(ssrf_target):
    """Verifies that SSRF filter catches loopback, private, and metadata IP targets."""
    allowed, reason = is_ip_allowed(ssrf_target)
    assert allowed is False
    assert "SSRF blocked" in reason

# --- Red-Team Category 3: XSS & Risky Injection Schemes ---

def test_redteam_xss_scheme_detection():
    """Verifies javascript: and data: schemes are immediately classified as risky schemes."""
    p1 = "javascript:alert('pwned')"
    ptype1, meta1 = parse_payload_type(p1)
    assert ptype1 == "risky_scheme"

    p2 = "data:text/html,<script>alert(1)</script>"
    ptype2, meta2 = parse_payload_type(p2)
    assert ptype2 == "risky_scheme"

# --- Red-Team Category 4: Malformed Image Inputs ---

def test_redteam_malformed_image_input():
    """Verifies the capture module never crashes on corrupt bytes or partial headers."""
    garbage_bytes = b"CORRUPT_HEADER_NOT_A_VALID_IMAGE_BYTES_12345"
    res = capture_and_decode(garbage_bytes)
    assert res["success"] is False
    assert res["error"] is not None
