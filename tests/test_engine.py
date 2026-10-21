"""M4: rule-first fusion. These are the policy decisions of the whole system, so they are tested one by one."""
import pytest

from qrshield.engine import decide


def url(score=0.0, *names, ptype="url"):
    return {"score": score, "payload_type": ptype, "signals": [{"name": n, "text": f"signal {n}", "direction": "risk"} for n in names]}


def cv(score=0.0, status="ok", *names):
    return {"score": score, "status": status, "signals": [{"name": n, "text": f"signal {n}", "direction": "risk"} for n in names]}


def sig(status="none", issuer=None):
    return {"status": status, "issuer": issuer or ({"name": "City Parking", "domain": "pay.citypark.example"} if status == "valid" else None)}


# ---------------------------------------------------------------- crypto decides first
def test_valid_signature_is_safe_and_certified():
    d = decide(url(0.9), cv(0.2), sig("valid"))
    assert d["verdict"] == "SAFE" and d["certified"] and d["risk"] < 0.2
    assert "City Parking" in d["reasons"][0]


def test_valid_signature_but_physically_pasted_is_downgraded():
    d = decide(url(0.0), cv(0.85, "ok", "sticker_edge_detected"), sig("valid"))
    assert d["verdict"] == "SUSPICIOUS" and d["certified"]
    assert any("stuck on top" in r for r in d["reasons"])


@pytest.mark.parametrize("status", ["invalid", "unknown_issuer", "revoked", "domain_mismatch"])
def test_failed_verification_blocks_even_with_clean_link_and_photo(status):
    d = decide(url(0.0), cv(0.0), sig(status))
    assert d["verdict"] == "BLOCK" and not d["certified"] and d["breakdown"]["overrides"] == [f"signature_{status}"]


def test_expired_is_at_least_suspicious_but_phishing_still_blocks():
    assert decide(url(0.0), cv(0.0), sig("expired"))["verdict"] == "SUSPICIOUS"
    assert decide(url(1.0), cv(0.0), sig("expired"))["verdict"] == "BLOCK"


# ---------------------------------------------------------------- unsigned fusion
def test_clean_unsigned_is_safe_and_says_it_cannot_prove_origin():
    d = decide(url(0.05), cv(0.10), sig("none"))
    assert d["verdict"] == "SAFE" and not d["certified"]
    assert any("not digitally signed" in r for r in d["reasons"])


def test_visual_evidence_alone_can_never_block():
    d = decide(url(0.0), cv(0.99, "ok", "sticker_edge_detected"), sig("none"))
    assert d["verdict"] == "SUSPICIOUS" and d["risk"] < 0.65


def test_link_evidence_alone_can_block():
    assert decide(url(0.90, "brand_impersonation"), cv(0.0), sig("none"))["verdict"] == "BLOCK"


def test_two_independent_layers_agreeing_blocks():
    d = decide(url(0.6), cv(0.80), sig("none"))
    assert d["verdict"] == "BLOCK" and "two_layers_agree" in d["breakdown"]["overrides"]


def test_weak_visual_evidence_is_discounted():
    """p=0.5 is where ~11% of genuine photos land (see docs/evaluation.md): it must not worry anyone on its own."""
    assert decide(url(0.0), cv(0.50), sig("none"))["verdict"] == "SAFE"
    assert decide(url(0.0), cv(0.62), sig("none"))["verdict"] == "SAFE"
    assert decide(url(0.0), cv(0.80), sig("none"))["verdict"] == "SUSPICIOUS"


def test_low_quality_photo_cannot_hurt_a_clean_link():
    d = decide(url(0.0), cv(0.9, "low_quality"), sig("none"))
    assert d["verdict"] == "SAFE" and d["breakdown"]["tamper_risk"] == 0.0


def test_inconclusive_photo_counts_less():
    full = decide(url(0.0), cv(0.8, "ok"), sig("none"))["risk"]
    half = decide(url(0.0), cv(0.8, "inconclusive"), sig("none"))["risk"]
    assert half < full


def test_text_only_check_has_no_visual_term():
    d = decide(url(0.05), {"score": 0.0, "status": "not_applicable", "signals": []}, sig("none"))
    assert d["verdict"] == "SAFE"


# ---------------------------------------------------------------- hard overrides
def test_blocklist_hit_blocks_regardless():
    d = decide(url(1.0, "blocklist_match"), cv(0.0), sig("none"))
    assert d["verdict"] == "BLOCK" and d["risk"] == 1.0


def test_dangerous_scheme_blocks():
    assert decide(url(0.97, "dangerous_scheme", ptype="other"), cv(0.0), sig("none"))["verdict"] == "BLOCK"


def test_upi_payee_mismatch_is_at_least_suspicious():
    d = decide(url(0.1, "payee_vpa_mismatch", ptype="upi"), cv(0.0), sig("none"))
    assert d["verdict"] in ("SUSPICIOUS", "BLOCK") and d["risk"] >= 0.60


def test_stacked_codes_are_at_least_suspicious():
    d = decide(url(0.0), cv(0.3, "ok", "stacked_code_pattern"), sig("none"))
    assert d["verdict"] != "SAFE"


def test_two_photos_disagreeing_is_at_least_suspicious():
    d = decide(url(0.0), cv(0.1, "ok", "payload_mismatch_multi_view"), sig("none"))
    assert d["verdict"] != "SAFE"


# ---------------------------------------------------------------- explanations
@pytest.mark.parametrize("args", [
    (url(0.9, "brand_impersonation", "newly_registered_domain"), cv(0.7, "ok", "sticker_edge_detected", "hidden_code_fragments"), sig("none")),
    (url(0.0), cv(0.0), sig("none")), (url(0.0), cv(0.0), sig("invalid")),
])
def test_reasons_are_short_and_never_empty(args):
    reasons = decide(*args)["reasons"]
    assert 1 <= len(reasons) <= 3 and all(isinstance(r, str) and r for r in reasons)


def test_breakdown_is_transparent():
    b = decide(url(0.5), cv(0.5), sig("none"))["breakdown"]
    assert {"url_risk", "tamper_risk", "a", "b", "fused", "signature", "overrides"} <= set(b)
