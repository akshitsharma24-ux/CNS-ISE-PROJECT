"""Token inspector (verification trace), attack lab and the Merkle transparency log."""
import hashlib
import time

import pytest

from qrshield.crypto_layer import generate_keypair, sign_url_token, verify
from qrshield.crypto_layer import transparency as T
from qrshield.crypto_layer.trace import trace
from qrshield.registry import Registry
from qrshield.registry.lab import run_attacks


@pytest.fixture()
def reg(home):
    from qrshield.crypto_layer import TrustStore
    r = Registry(home=home, trust_store=TrustStore()).ensure_ready()
    yield r
    r.close()


def _signed(reg, issuer="citypark-01", url="https://pay.citypark.example/m/42", hours=48):
    return reg.sign_for_issuer(issuer, url, "bay-7", hours)["signed_url"]


# ------------------------------------------------------------------ trace
def test_trace_agrees_with_the_real_verifier_on_every_outcome(reg):
    good = _signed(reg)
    other = reg.sign_for_issuer("spit-admit", "https://spit.ac.in/admit", "d", 48)["signed_url"]
    cases = {
        "valid": good, "none": "https://example.com/plain",
        "invalid": good.replace("/m/42", "/m/43"),
        "malformed": "https://pay.citypark.example/m/42?qrs=not-a-token",
        "domain": reg.sign_for_issuer("citypark-01", "https://other.example/x", "d", 48)["signed_url"],
        "other": other,
    }
    for name, payload in cases.items():
        t = trace(payload, reg.store)
        assert t["status"] == verify(payload, reg.store)["status"], name
        assert t["agrees"], f"{name}: replayed steps disagree with the verifier: {[ (s['id'], s['state']) for s in t['steps']]}"


def test_trace_marks_unreached_steps_as_skipped_after_the_first_failure(reg):
    t = trace(_signed(reg).replace("/m/42", "/m/43"), reg.store)
    states = {s["id"]: s["state"] for s in t["steps"]}
    assert t["decided_at"] == "signature" and states["signature"] == "fail"
    assert states["parse"] == states["anchor"] == states["certificate"] == states["revocation"] == "pass"
    assert states["domain"] == states["time"] == "skipped"


def test_trace_exposes_only_public_material(reg):
    blob = repr(trace(_signed(reg), reg.store))
    priv = reg.keystore.issuer_private_key("citypark-01", "key-1")
    from qrshield.crypto_layer import export_private_key_b64
    assert export_private_key_b64(priv) not in blob
    root_priv, _ = reg.keystore.root_keypair()
    assert export_private_key_b64(root_priv) not in blob


def test_trace_of_revoked_and_expired(reg):
    payload = _signed(reg)
    assert trace(payload, reg.store, now=int(time.time()) + 10 * 24 * 3600)["decided_at"] == "time"
    reg.revoke_issuer("citypark-01")
    t = trace(payload, reg.store)
    assert t["status"] == "revoked" and t["decided_at"] == "revocation" and t["agrees"]


# ------------------------------------------------------------------ attack lab
def test_attack_lab_every_forgery_is_rejected_with_the_expected_status(reg):
    res = run_attacks(reg, "citypark-01")
    by_id = {r["id"]: r for r in res["results"]}
    assert by_id["genuine"]["actual"] == "valid"
    assert res["summary"]["all_as_expected"] and res["summary"]["rejected"] == res["summary"]["attacks"] == 9
    assert {r["actual"] for r in res["results"] if r["id"] != "genuine"} <= {"invalid", "unknown_issuer", "domain_mismatch", "expired", "none"}
    assert by_id["wrong_domain"]["decided_at"] == "domain" and by_id["expired"]["decided_at"] == "time"
    assert by_id["forged_signature"]["decided_at"] == "signature" and by_id["unknown_issuer"]["decided_at"] == "certificate"


def test_attack_lab_does_not_change_registry_state(reg):
    before = (reg.current_crl()["version"], len(reg.audit_log()), reg.list_issuers())
    run_attacks(reg, "citypark-01")
    assert (reg.current_crl()["version"], len(reg.audit_log()), reg.list_issuers()) == before


def test_attack_lab_refuses_revoked_and_unknown_issuers(reg):
    from qrshield.registry import RegistryError
    with pytest.raises(RegistryError):
        run_attacks(reg, "nobody")
    reg.revoke_issuer("citypark-01")
    with pytest.raises(RegistryError):
        run_attacks(reg, "citypark-01")


# ------------------------------------------------------------------ Merkle tree
def _leaves(n):
    return [T.leaf_hash(f"event-{i}".encode()) for i in range(n)]


def test_inclusion_proofs_verify_for_every_leaf_of_every_size_and_fail_when_tampered():
    for n in range(1, 34):
        hs = _leaves(n)
        root = T.merkle_root(hs)
        for i in range(n):
            proof = T.inclusion_proof(i, hs)
            assert T.verify_inclusion(hs[i], i, n, proof, root), (n, i)
            assert not T.verify_inclusion(T.leaf_hash(b"forged"), i, n, proof, root)
            assert not T.verify_inclusion(hs[i], (i + 1) % n if n > 1 else 1, n, proof, root)
            if proof:
                bad = [bytes([proof[0][0] ^ 1]) + proof[0][1:]] + proof[1:]
                assert not T.verify_inclusion(hs[i], i, n, bad, root)


def test_consistency_proofs_verify_for_all_prefixes_and_reject_rewritten_history():
    for n in range(1, 26):
        hs = _leaves(n)
        second = T.merkle_root(hs)
        for m in range(1, n + 1):
            proof = T.consistency_proof(m, hs)
            assert T.verify_consistency(m, n, T.merkle_root(hs[:m]), second, proof), (m, n)
            if m < n:
                rewritten = [T.leaf_hash(b"rewritten")] + hs[1:m]
                assert not T.verify_consistency(m, n, T.merkle_root(rewritten), second, proof), (m, n)


def test_leaf_and_node_hashes_are_domain_separated():
    a, b = T.leaf_hash(b"a"), T.leaf_hash(b"b")
    assert T.node_hash(a, b) != T.leaf_hash(a + b), "an inner node must never equal a leaf over the same bytes"
    assert T.merkle_root([]) == hashlib.sha256(b"").digest()


def test_signed_tree_head_binds_size_root_and_time():
    priv, pub = generate_keypair()
    head = T.sign_tree_head(5, T.merkle_root(_leaves(5)), 1_700_000_000, priv)
    assert T.verify_tree_head(head, pub)[0]
    for field, value in (("size", 6), ("timestamp", 1), ("root_hash", "00" * 32)):
        assert not T.verify_tree_head({**head, field: value}, pub)[0], field
    assert not T.verify_tree_head(head, generate_keypair()[1])[0]


# ------------------------------------------------------------------ registry log + endpoints
def test_registry_log_grows_with_lifecycle_events_and_proves_itself(reg):
    snap = reg.log_snapshot()
    n0 = len(snap["entries"])
    assert n0 >= 2 and {e["action"] for e in snap["entries"]} == {"issuer.register"}
    _signed(reg)                                           # signing is not a lifecycle event
    assert len(reg.log_snapshot()["entries"]) == n0
    reg.revoke_issuer("citypark-01")
    reg.restore_issuer("citypark-01")
    reg.rotate_issuer_key("spit-admit")
    snap = reg.log_snapshot()
    assert [e["action"] for e in snap["entries"][n0:]] == ["issuer.revoke", "issuer.restore", "issuer.rotate"]

    from qrshield.crypto_layer import load_public_key_b64
    ok, _ = T.verify_tree_head(snap["head"], load_public_key_b64(snap["root_public_key"]))
    assert ok
    for e in snap["entries"]:
        p = reg.log_inclusion(e["index"])
        assert T.verify_inclusion(T.leaf_hash(reg.log_leaf_data(p["entry"])), p["index"], p["size"],
                                  [bytes.fromhex(h) for h in p["path"]], bytes.fromhex(p["root_hash"]))
    c = reg.log_consistency(n0)
    assert T.verify_consistency(n0, c["second"], bytes.fromhex(c["first_root"]), bytes.fromhex(c["second_root"]),
                                [bytes.fromhex(h) for h in c["path"]])


def test_editing_a_logged_event_breaks_its_inclusion_proof(reg):
    p = reg.log_inclusion(0)
    forged = {**p["entry"], "detail": p["entry"]["detail"] + " (never happened)"}
    assert not T.verify_inclusion(T.leaf_hash(reg.log_leaf_data(forged)), 0, p["size"],
                                  [bytes.fromhex(h) for h in p["path"]], bytes.fromhex(p["root_hash"]))


def test_log_survives_non_ascii_details_the_same_way_in_every_client(reg):
    reg.audit("issuer.register", "unicode-issuer", "name=Café ✓ domain=xn--caf-dma.example")
    e = reg.log_snapshot()["entries"][-1]
    assert reg.log_leaf_data(e).decode("utf-8") == (
        '{"action":"issuer.register","detail":"name=Café ✓ domain=xn--caf-dma.example","subject":"unicode-issuer","time":%d}' % e["time"])


def test_endpoints(client):
    assert client.get("/api/registry/log").json()["head"]["size"] >= 2
    p = client.get("/api/registry/log/proof/0").json()
    assert p["index"] == 0 and isinstance(p["path"], list)
    assert client.get("/api/registry/log/proof/999").status_code == 404
    assert client.get("/api/registry/log/consistency?first=1").json()["first"] == 1
    assert client.get("/api/registry/log/consistency?first=9999").status_code == 400

    signed = client.post("/api/admin/sign", headers=client.admin,
                         json={"issuer_id": "citypark-01", "url": "https://pay.citypark.example/m/9"}).json()["signed_url"]
    t = client.post("/api/registry/inspect", json={"payload": signed}).json()
    assert t["status"] == "valid" and t["agrees"] and [s["id"] for s in t["steps"]][:2] == ["parse", "anchor"]
    assert client.post("/api/registry/inspect", json={"payload": "https://example.com"}).json()["status"] == "none"

    assert client.post("/api/admin/lab/attacks", json={"issuer_id": "citypark-01"}).status_code == 401
    lab = client.post("/api/admin/lab/attacks", headers=client.admin, json={"issuer_id": "citypark-01"}).json()
    assert lab["summary"]["all_as_expected"] and len(lab["results"]) == 10
    assert client.post("/api/admin/lab/attacks", headers=client.admin, json={"issuer_id": "nope"}).status_code == 404
