"""
Red-team suite: the attack table of docs/threat_model.md, executed against the real registry + verifier.
Each test names the attack and asserts both the verdict AND that the system never reports 'certified' wrongly.
"""
import base64
import time

import pytest

from qrshield.crypto_layer import (
    TrustStore, create_issuer_certificate, create_signed_crl, extract_token_from_url, generate_keypair, sign_url_token, verify,
)
from qrshield.crypto_layer.token import pack_token
from qrshield.engine import decide

URL = "https://pay.citypark.example/m/42"


def printed(registry, url=URL, **kw):
    return registry.sign_for_issuer("citypark-01", url, kw.pop("loc", "meter-42"), kw.pop("hours", 48))["signed_url"]


def status(registry, url):
    return verify(url, registry.store)["status"]


def engine_verdict(registry, url):
    sig = verify(url, registry.store)
    return decide({"score": 0.0, "signals": [], "payload_type": "url"}, {"score": 0.0, "status": "ok", "signals": []}, sig)


# ---------------------------------------------------------------- 1. attacker prints own code with a fake token
def test_attack_fake_token_random_bytes(registry):
    fake = f"{URL}?qrs={base64.urlsafe_b64encode(bytes(range(100))).decode().rstrip('=')}"
    assert status(registry, fake) == "invalid"
    assert engine_verdict(registry, fake)["verdict"] == "BLOCK"


def test_attack_signature_from_attackers_own_key_claiming_the_real_issuer(registry):
    priv, _ = generate_keypair()
    url = sign_url_token(URL, priv, "citypark-01", "key-1", "meter-42", int(time.time()), int(time.time()) + 3600)[0]
    assert status(registry, url) == "invalid"


# ---------------------------------------------------------------- 2. self-signed / rogue registry
def test_attack_self_signed_certificate_with_a_rogue_root(registry):
    rogue_root, _ = generate_keypair()
    priv, pub = generate_keypair()
    cert = create_issuer_certificate("rogue-bank", "Rogue Bank", "rogue-bank.example", pub, rogue_root)
    registry.store.add_certificate(cert)               # even if the attacker smuggles it into the local cache
    url = sign_url_token("https://rogue-bank.example/login", priv, "rogue-bank", "key-1", "x", int(time.time()), 0)[0]
    assert status(registry, url) == "unknown_issuer"
    assert engine_verdict(registry, url)["verdict"] == "BLOCK"


def test_attack_cache_poisoning_replaces_a_real_certificate_with_a_forged_one(registry):
    rogue_root, _ = generate_keypair()
    priv, pub = generate_keypair()
    forged_cert = create_issuer_certificate("citypark-01", "City Parking", "pay.citypark.example", pub, rogue_root)
    genuine = printed(registry)
    registry.store.add_certificate(forged_cert)        # attacker swaps the cached certificate
    assert status(registry, genuine) == "unknown_issuer", "forged certs not rooted in the pinned key must never verify"


# ---------------------------------------------------------------- 3. cross-domain signing (lookalike)
def test_attack_legit_key_certifies_a_lookalike_domain(registry):
    url = registry.sign_for_issuer("citypark-01", "https://pay-citypark.example.evil.com/m/42")["signed_url"]
    assert status(registry, url) == "domain_mismatch" and engine_verdict(registry, url)["verdict"] == "BLOCK"


# ---------------------------------------------------------------- 4. stripping the token (downgrade)
def test_attack_stripped_token_is_never_certified(registry):
    stripped = printed(registry).split("?qrs=")[0]
    d = engine_verdict(registry, stripped)
    assert status(registry, stripped) == "none" and not d["certified"]


# ---------------------------------------------------------------- 5. editing the URL inside a valid token
@pytest.mark.parametrize("edit", [lambda u: u.replace("/m/42", "/m/43"), lambda u: u.replace("pay.citypark", "pay.citypark2"),
                                   lambda u: u.replace("https://", "http://"), lambda u: u + "&extra=1", lambda u: u.replace("m/42", "m/42/")])
def test_attack_any_edit_breaks_the_signature(registry, edit):
    assert status(registry, edit(printed(registry))) in ("invalid", "domain_mismatch")


def test_attack_edit_token_fields_individually(registry):
    """Every field in the token is covered by the signature: changing any one of them must fail verification."""
    url = printed(registry)
    tok = extract_token_from_url(url)[0]
    base = dict(issuer_id=tok["iss"], key_id=tok["kid"], location_id=tok["loc"], iat=tok["iat"], exp=tok["exp"],
                signature=base64.urlsafe_b64decode(tok["sig"] + "=="))
    edits = [dict(location_id="elsewhere"), dict(exp=tok["exp"] + 86400), dict(iat=tok["iat"] - 1),
             dict(key_id="key-2"), dict(issuer_id="spit-admit")]
    for edit in edits:
        edited = url.split("qrs=")[0] + "qrs=" + pack_token(**{**base, **edit})
        assert status(registry, edited) in ("invalid", "unknown_issuer", "domain_mismatch"), edit


# ---------------------------------------------------------------- 6. replay of a genuine code elsewhere (documented limit)
def test_replay_of_a_genuine_signed_code_verifies_and_exposes_its_location(registry):
    url = printed(registry, loc="andheri-meter-04")
    res = verify(url, registry.store)
    assert res["status"] == "valid", "signatures cannot detect a faithful copy - this is the documented limit"
    assert res["issuer"]["location_id"] == "andheri-meter-04", "the bound location lets a verifier/registry compare against where it was scanned"


# ---------------------------------------------------------------- 7. time & revocation
def test_attack_replay_after_expiry(registry):
    url = registry.sign_for_issuer("citypark-01", URL, "m", validity_hours=1)["signed_url"]
    assert verify(url, registry.store, now=int(time.time()) + 2 * 3600)["status"] == "expired"


def test_attack_stolen_key_after_revocation(registry):
    old = printed(registry)
    registry.revoke_issuer("citypark-01", "key stolen")
    assert status(registry, old) == "revoked" and engine_verdict(registry, old)["verdict"] == "BLOCK"


def test_attack_crl_rollback_hides_a_revocation(registry):
    code = printed(registry)
    registry.revoke_issuer("citypark-01", "stolen")
    stale = create_signed_crl([], registry._root_priv, version=1)            # attacker replays the pre-revocation list
    ok, why = registry.store.install_crl(stale)
    assert not ok and "rollback" in why
    assert status(registry, code) == "revoked", "the old list must not resurrect a revoked issuer"


def test_attack_forged_crl_signed_by_someone_else(registry):
    rogue, _ = generate_keypair()
    ok, _ = registry.store.install_crl(create_signed_crl([], rogue, version=99))
    assert not ok


def test_key_rotation_invalidates_the_stolen_old_key(registry):
    stolen = printed(registry)
    registry.rotate_issuer_key("citypark-01")
    assert status(registry, stolen) == "revoked"
    assert status(registry, printed(registry)) == "valid"


# ---------------------------------------------------------------- 8. fail closed
def test_no_trust_anchor_means_nothing_verifies(registry):
    empty = TrustStore(None)
    empty.add_certificate(registry.get_certificate("citypark-01"))
    assert verify(printed(registry), empty)["status"] == "unknown_issuer"


def test_certified_requires_a_positive_verification_never_a_default(registry):
    for url in ("https://pay.citypark.example/m/42", "https://spit.ac.in/", "upi://pay?pa=x@ybl"):
        assert not engine_verdict(registry, url)["certified"]
