"""Registry service: issuer lifecycle, signed CRL, feedback queue, key custody."""
import json

import pytest

from qrshield.crypto_layer import extract_token_from_url, verify
from qrshield.registry import Registry, RegistryError


def sign_via(registry, issuer="citypark-01", url="https://pay.citypark.example/m/42", **kw):
    return registry.sign_for_issuer(issuer, url, **kw)["signed_url"]


def test_demo_issuers_seeded_with_generated_keys(registry, home):
    ids = {i["issuer_id"] for i in registry.list_issuers()}
    assert {"citypark-01", "spit-admit"} <= ids
    key_files = list((home / "keys" / "issuers").glob("*.json"))
    assert key_files, "managed issuer keys must live in the runtime home, not in source code"


def test_signed_qr_from_portal_verifies(registry):
    res = verify(sign_via(registry), registry.store)
    assert res["status"] == "valid" and res["issuer"]["domain"] == "pay.citypark.example"


def test_revoke_then_restore_changes_verdict_and_crl_version(registry):
    url = sign_via(registry)
    v1 = registry.current_crl()["version"]
    crl = registry.revoke_issuer("citypark-01", "demo")
    assert crl["version"] > v1
    assert verify(url, registry.store)["status"] == "revoked"
    restored = registry.restore_issuer("citypark-01")
    assert restored["version"] > crl["version"]
    assert verify(url, registry.store)["status"] == "valid"


def test_revoked_issuer_cannot_sign_new_codes(registry):
    registry.revoke_issuer("citypark-01")
    with pytest.raises(RegistryError) as e:
        sign_via(registry)
    assert e.value.status == 409


def test_double_revoke_conflicts(registry):
    registry.revoke_issuer("spit-admit")
    with pytest.raises(RegistryError):
        registry.revoke_issuer("spit-admit")


def test_key_rotation_revokes_old_key_only(registry):
    old = sign_via(registry)
    result = registry.rotate_issuer_key("citypark-01")
    assert result["certificate"]["kid"] == "key-2"
    assert verify(old, registry.store)["status"] == "revoked"          # old key id is on the CRL
    assert verify(sign_via(registry), registry.store)["status"] == "valid"   # new key works
    assert extract_token_from_url(sign_via(registry))[0]["kid"] == "key-2"


def test_state_survives_restart(registry, home):
    from qrshield.crypto_layer import TrustStore
    url = sign_via(registry)
    registry.revoke_issuer("citypark-01", "persisted")
    again = Registry(home=home, trust_store=TrustStore()).ensure_ready()
    assert verify(url, again.store)["status"] == "revoked"
    assert again.root_public_key_b64 == registry.root_public_key_b64


def test_register_custom_issuer_and_reject_bad_input(registry):
    cert = registry.register_issuer("cafe-01", "Chai Point", "chaipoint.example")
    assert cert["domain"] == "chaipoint.example"
    for kwargs in (dict(issuer_id="Bad Id!", name="x" * 5, domain="a.example"),
                   dict(issuer_id="ok-id", name="x", domain="a.example"),
                   dict(issuer_id="ok-id2", name="Name", domain="com"),
                   dict(issuer_id="ok-id3", name="Name", domain="10.0.0.1")):
        with pytest.raises(RegistryError):
            registry.register_issuer(**kwargs)
    with pytest.raises(RegistryError) as e:
        registry.register_issuer("cafe-01", "Dup", "dup.example")
    assert e.value.status == 409


def test_external_public_key_issuer_cannot_be_signed_for_by_portal(registry):
    from qrshield.crypto_layer import export_public_key_b64, generate_keypair
    _, pub = generate_keypair()
    registry.register_issuer("self-key", "Self Keyed", "selfkey.example", export_public_key_b64(pub))
    with pytest.raises(RegistryError):
        registry.sign_for_issuer("self-key", "https://selfkey.example/a")


def test_portal_refuses_url_outside_domain_is_blocked_at_verify(registry):
    """Even the portal can sign anything for a managed key, but verification enforces binding."""
    url = registry.sign_for_issuer("citypark-01", "https://evil.example/pay")["signed_url"]
    assert verify(url, registry.store)["status"] == "domain_mismatch"


def test_feedback_queue_flow(registry):
    rid = registry.add_report("https://paytm-kyc.top/x", "phishing", "seen on poster", verdict="SAFE")
    assert registry.list_reports(status="pending")[0]["report_id"] == rid
    assert registry.review_report(rid, "approve") == "approved"
    assert registry.approved_reports()[0]["url"] == "https://paytm-kyc.top/x"
    registry.mark_reports_used([rid], "v2")
    assert registry.approved_reports(only_unused=True) == []


def test_feedback_validation(registry):
    with pytest.raises(RegistryError):
        registry.add_report("https://x.example", "spam")
    with pytest.raises(RegistryError):
        registry.add_report("", "phishing")
    with pytest.raises(RegistryError):
        registry.add_report("x" * 5000, "phishing")
    with pytest.raises(RegistryError):
        registry.review_report("nope", "approve")


def test_audit_trail_records_privileged_actions(registry):
    registry.revoke_issuer("spit-admit", "audit-test", actor="tester")
    actions = [a["action"] for a in registry.audit_log()]
    assert "issuer.revoke" in actions and "issuer.register" in actions


def test_crl_published_is_root_signed(registry):
    from qrshield.crypto_layer import verify_crl
    crl = registry.revoke_issuer("spit-admit")
    ok, _ = verify_crl(crl, registry.store.root_public_key)
    assert ok


def test_private_keys_not_in_certificates_or_crl(registry):
    blob = json.dumps(registry.list_issuers()) + json.dumps(registry.current_crl())
    for rec in registry.keystore.issuer_dir.glob("*.json"):
        priv = json.loads(rec.read_text())["private_key"]
        assert priv not in blob
