"""M3: signed QR tokens, mini-PKI, CRL and the verification algorithm."""
import pytest

from qrshield.crypto_layer import (
    CertificateError, TokenError, TrustStore, canonicalize_url, create_issuer_certificate,
    create_signed_crl, extract_token_from_url, generate_keypair, sign_url_token,
    validate_certified_domain, verify, verify_domain_binding,
)
from qrshield.crypto_layer.token import pack_token, unpack_token

NOW = 1_800_000_000


@pytest.fixture()
def pki():
    root_priv, root_pub = generate_keypair()
    issuer_priv, issuer_pub = generate_keypair()
    cert = create_issuer_certificate("citypark-01", "City Parking", "pay.citypark.example",
                                     issuer_pub, root_priv, valid_from=NOW - 1000, valid_to=NOW + 10**7)
    store = TrustStore(root_pub)
    store.add_certificate(cert)
    assert store.install_crl(create_signed_crl([], root_priv, version=1))[0]
    return dict(root_priv=root_priv, root_pub=root_pub, issuer_priv=issuer_priv, cert=cert, store=store)


def sign(pki, url="https://pay.citypark.example/m/42", loc="meter-4", iat=NOW, exp=NOW + 3600, priv=None, iss="citypark-01"):
    return sign_url_token(url, priv or pki["issuer_priv"], iss, "key-1", loc, iat, exp)[0]


# ---------------------------------------------------------------- canonicalisation
def test_canonicalization_is_deterministic():
    a = canonicalize_url("HTTPS://Pay.CityPark.Example:443/m/42?b=2&a=1#frag")
    b = canonicalize_url("https://pay.citypark.example/m/42?a=1&b=2")
    assert a == b == "https://pay.citypark.example/m/42?a=1&b=2"


def test_canonicalization_strips_qrs_and_keeps_nondefault_port():
    assert canonicalize_url("http://x.example:8080/p?qrs=zzz&k=v") == "http://x.example:8080/p?k=v"


@pytest.mark.parametrize("bad", ["ftp://x.example/a", "javascript:alert(1)", "https://user:pw@x.example/",
                                 "https://user@pay.citypark.example/", "http://[x", "https:///nohost", ""])
def test_canonicalization_rejects_unsafe_urls(bad):
    with pytest.raises(TokenError):
        canonicalize_url(bad)


# ---------------------------------------------------------------- token format
def test_token_roundtrip_and_compact_size():
    sig = bytes(range(64))
    tok = pack_token("citypark-01", "key-1", "meter-4", NOW, NOW + 3600, sig)
    parsed = unpack_token(tok)
    assert (parsed["iss"], parsed["kid"], parsed["loc"], parsed["iat"], parsed["exp"]) == (
        "citypark-01", "key-1", "meter-4", NOW, NOW + 3600)
    assert len(tok) < 140, "token must stay small so the printed QR stays easy to scan"


@pytest.mark.parametrize("junk", ["", "AAAA", "!!!notbase64", "A" * 300])
def test_unpack_rejects_garbage(junk):
    with pytest.raises(TokenError):
        unpack_token(junk)


def test_signed_url_fits_in_small_qr(pki):
    assert len(sign(pki).encode()) < 250   # master plan target for payload size


# ---------------------------------------------------------------- verification
def test_valid_token(pki):
    res = verify(sign(pki), pki["store"], now=NOW + 10)
    assert res["status"] == "valid"
    assert res["issuer"]["name"] == "City Parking" and res["issuer"]["location_id"] == "meter-4"


def test_unsigned_url_is_none_not_error(pki):
    assert verify("https://pay.citypark.example/m/42", pki["store"], now=NOW)["status"] == "none"


def test_no_exp_means_non_expiring(pki):
    url = sign(pki, exp=0)
    assert verify(url, pki["store"], now=NOW + 10**6)["status"] == "valid"


def test_expired(pki):
    assert verify(sign(pki), pki["store"], now=NOW + 7200)["status"] == "expired"


def test_edited_url_invalidates_signature(pki):
    url = sign(pki).replace("/m/42", "/m/99")
    assert verify(url, pki["store"], now=NOW)["status"] == "invalid"


def test_forged_signature_cannot_hide_behind_expiry(pki):
    """A forged token that is also 'expired' must still be INVALID (BLOCK), never merely expired."""
    attacker, _ = generate_keypair()
    url = sign(pki, priv=attacker, exp=NOW - 10)
    assert verify(url, pki["store"], now=NOW)["status"] == "invalid"


def test_wrong_key_for_issuer(pki):
    attacker, _ = generate_keypair()
    assert verify(sign(pki, priv=attacker), pki["store"], now=NOW)["status"] == "invalid"


def test_unknown_issuer(pki):
    assert verify(sign(pki, iss="ghost-corp"), pki["store"], now=NOW)["status"] == "unknown_issuer"


def test_self_signed_certificate_not_rooted_in_pinned_key(pki):
    rogue_root, _ = generate_keypair()
    rogue_priv, rogue_pub = generate_keypair()
    rogue_cert = create_issuer_certificate("rogue", "Rogue Bank", "rogue.example", rogue_pub, rogue_root,
                                           valid_from=NOW - 10, valid_to=NOW + 10**6)
    pki["store"].add_certificate(rogue_cert)
    url = sign_url_token("https://rogue.example/login", rogue_priv, "rogue", "key-1", "x", NOW, NOW + 100)[0]
    assert verify(url, pki["store"], now=NOW)["status"] == "unknown_issuer"


def test_domain_binding_blocks_cross_domain_signing(pki):
    url = sign(pki, url="https://phishing-site.example/login")
    assert verify(url, pki["store"], now=NOW)["status"] == "domain_mismatch"


def test_lookalike_suffix_is_not_a_subdomain(pki):
    url = sign(pki, url="https://evilpay.citypark.example.attacker.com/m/42")
    assert verify(url, pki["store"], now=NOW)["status"] == "domain_mismatch"


def test_subdomain_of_certified_domain_is_allowed(pki):
    assert verify(sign(pki, url="https://api.pay.citypark.example/x"), pki["store"], now=NOW)["status"] == "valid"


def test_revoked_issuer(pki):
    url = sign(pki)
    crl = create_signed_crl([{"id": "citypark-01", "revoked_at": NOW, "reason": "stolen"}], pki["root_priv"], version=2)
    assert pki["store"].install_crl(crl)[0]
    assert verify(url, pki["store"], now=NOW)["status"] == "revoked"


def test_revoked_single_key_only_affects_that_issuer(pki):
    url = sign(pki)
    crl = create_signed_crl([{"id": "other-issuer:key-1", "revoked_at": NOW, "reason": "x"}], pki["root_priv"], version=2)
    pki["store"].install_crl(crl)
    assert verify(url, pki["store"], now=NOW)["status"] == "valid"
    crl3 = create_signed_crl([{"id": "citypark-01:key-1", "revoked_at": NOW, "reason": "rotated"}], pki["root_priv"], version=3)
    pki["store"].install_crl(crl3)
    assert verify(url, pki["store"], now=NOW)["status"] == "revoked"


def test_crl_rollback_is_rejected(pki):
    pki["store"].install_crl(create_signed_crl([{"id": "citypark-01", "revoked_at": NOW, "reason": "x"}], pki["root_priv"], version=5))
    ok, msg = pki["store"].install_crl(create_signed_crl([], pki["root_priv"], version=4))
    assert not ok and "rollback" in msg
    assert verify(sign(pki), pki["store"], now=NOW)["status"] == "revoked"


def test_crl_signed_by_wrong_key_is_rejected(pki):
    rogue, _ = generate_keypair()
    ok, _ = pki["store"].install_crl(create_signed_crl([], rogue, version=9))
    assert not ok


def test_fail_closed_without_pinned_root(pki):
    store = TrustStore(None)
    store.add_certificate(pki["cert"])
    assert verify(sign(pki), store, now=NOW)["status"] == "unknown_issuer"


def test_expired_certificate_is_not_trusted(pki):
    assert verify(sign(pki), pki["store"], now=NOW + 10**8)["status"] == "unknown_issuer"


def test_duplicate_token_parameter_is_invalid(pki):
    url = sign(pki)
    assert verify(url + "&qrs=" + url.split("qrs=")[1], pki["store"], now=NOW)["status"] == "invalid"


def test_token_cannot_be_replayed_on_another_issuer_cert(pki):
    other_priv, other_pub = generate_keypair()
    cert2 = create_issuer_certificate("other-01", "Other", "pay.citypark.example", other_pub, pki["root_priv"],
                                      valid_from=NOW - 10, valid_to=NOW + 10**6)
    pki["store"].add_certificate(cert2)
    url = sign(pki)                                   # signed by citypark-01
    swapped = extract_token_from_url(url)[0]
    assert swapped["iss"] == "citypark-01"
    forged = url.replace(url.split("qrs=")[1], pack_token("other-01", "key-1", "meter-4", NOW, NOW + 3600,
                                                          __import__("base64").urlsafe_b64decode(swapped["sig"] + "==")))
    assert verify(forged, pki["store"], now=NOW)["status"] == "invalid"


# ---------------------------------------------------------------- domain helpers
@pytest.mark.parametrize("ok", ["pay.citypark.example", "spit.ac.in", "Shop.Example.COM."])
def test_valid_certified_domains(ok):
    assert validate_certified_domain(ok)


@pytest.mark.parametrize("bad", ["com", "co.in", "ac.in", "127.0.0.1", "localhost", "-bad.com", "a b.com", ""])
def test_bare_suffix_and_garbage_domains_rejected(bad):
    with pytest.raises(CertificateError):
        validate_certified_domain(bad)


def test_domain_binding_helper():
    cert = {"domain": "citypark.example"}
    assert verify_domain_binding(cert, "https://citypark.example/x")
    assert verify_domain_binding(cert, "https://a.b.citypark.example/x")
    assert not verify_domain_binding(cert, "https://citypark.example.evil.com/x")
    assert not verify_domain_binding(cert, "https://notcitypark.example/x")
    assert not verify_domain_binding(cert, "https://citypark.example@evil.com/x")
