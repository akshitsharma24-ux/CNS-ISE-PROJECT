"""
Unit tests for M3: Crypto Layer (Signed QR codes and Mini-PKI)
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
    create_signed_crl,
    canonicalize_url
)

@pytest.fixture(autouse=True)
def setup_pki():
    # Setup fresh root key and issuer certificate before each test
    root_priv, root_pub = generate_keypair()
    issuer_priv, issuer_pub = generate_keypair()

    set_pinned_root_key(root_pub)

    cert = create_issuer_certificate(
        issuer_id="citypark-01",
        name="Mumbai Smart City Parking",
        domain="pay.citypark.example",
        issuer_public_key=issuer_pub,
        root_private_key=root_priv
    )
    cache_certificate("citypark-01", cert)

    # Empty CRL initially
    crl = create_signed_crl([], root_priv, version=1)
    set_cached_crl(crl)

    return {
        "root_priv": root_priv,
        "root_pub": root_pub,
        "issuer_priv": issuer_priv,
        "issuer_pub": issuer_pub,
        "cert": cert
    }

def test_canonicalize_url():
    u1 = "HTTPS://Pay.CityPark.Example:443/m/42?b=2&a=1&qrs=oldtoken#frag"
    c1 = canonicalize_url(u1)
    assert c1 == "https://pay.citypark.example:443/m/42?a=1&b=2"

def test_unsigned_url_returns_none():
    res = verify("https://spit.ac.in")
    assert res["status"] == "none"
    assert res["issuer"] is None

def test_valid_signed_url(setup_pki):
    issuer_priv = setup_pki["issuer_priv"]
    signed_url, token = sign_url_token(
        url="https://pay.citypark.example/m/42",
        private_key=issuer_priv,
        issuer_id="citypark-01",
        key_id="key-1",
        location_id="andheri-west-04",
        iat=int(time.time()),
        exp=int(time.time()) + 3600
    )
    res = verify(signed_url)
    assert res["status"] == "valid"
    assert res["issuer"]["name"] == "Mumbai Smart City Parking"
    assert res["issuer"]["domain"] == "pay.citypark.example"

def test_tampered_url_fails_signature(setup_pki):
    issuer_priv = setup_pki["issuer_priv"]
    signed_url, _ = sign_url_token(
        url="https://pay.citypark.example/m/42",
        private_key=issuer_priv,
        issuer_id="citypark-01",
        key_id="key-1",
        iat=int(time.time()),
        exp=int(time.time()) + 3600
    )
    # Attacker edits URL from /m/42 to /m/99
    tampered_url = signed_url.replace("/m/42", "/m/99")
    res = verify(tampered_url)
    assert res["status"] == "invalid"

def test_domain_mismatch_rejected(setup_pki):
    issuer_priv = setup_pki["issuer_priv"]
    # Legitimate issuer attempts to sign for a domain not in its certificate
    signed_url, _ = sign_url_token(
        url="https://evil-lookalike.example/m/42",
        private_key=issuer_priv,
        issuer_id="citypark-01",
        key_id="key-1",
        iat=int(time.time()),
        exp=int(time.time()) + 3600
    )
    res = verify(signed_url)
    assert res["status"] == "domain_mismatch"

def test_expired_token(setup_pki):
    issuer_priv = setup_pki["issuer_priv"]
    signed_url, _ = sign_url_token(
        url="https://pay.citypark.example/m/42",
        private_key=issuer_priv,
        issuer_id="citypark-01",
        key_id="key-1",
        iat=int(time.time()) - 7200,
        exp=int(time.time()) - 3600  # Expired 1 hour ago
    )
    res = verify(signed_url)
    assert res["status"] == "expired"

def test_revoked_certificate(setup_pki):
    issuer_priv = setup_pki["issuer_priv"]
    root_priv = setup_pki["root_priv"]

    signed_url, _ = sign_url_token(
        url="https://pay.citypark.example/m/42",
        private_key=issuer_priv,
        issuer_id="citypark-01",
        key_id="key-1",
        iat=int(time.time()),
        exp=int(time.time()) + 3600
    )
    # Revoke issuer in CRL
    revoked_crl = create_signed_crl([
        {"id": "citypark-01", "revoked_at": int(time.time()), "reason": "Compromised key"}
    ], root_priv, version=2)
    set_cached_crl(revoked_crl)

    res = verify(signed_url)
    assert res["status"] == "revoked"
