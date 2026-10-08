"""
Unit tests for M4: Aggregation and Scoring Engine
"""
import pytest
from qrshield.engine import decide

def test_certified_safe():
    url_res = {"score": 0.05, "signals": []}
    cv_res = {"score": 0.10, "status": "ok", "signals": []}
    sig_res = {
        "status": "valid",
        "issuer": {"name": "Smart City Parking", "domain": "citypark.example"}
    }
    dec = decide(url_res, cv_res, sig_res)
    assert dec["verdict"] == "SAFE"
    assert dec["certified"] is True
    assert dec["risk"] < 0.20
    assert any("provably authentic" in r.lower() for r in dec["reasons"])

def test_certified_with_physical_tamper_downgrade():
    url_res = {"score": 0.05, "signals": []}
    cv_res = {"score": 0.85, "status": "ok", "signals": [{"name": "cutline", "text": "Cutlines"}]}
    sig_res = {
        "status": "valid",
        "issuer": {"name": "Smart City Parking", "domain": "citypark.example"}
    }
    dec = decide(url_res, cv_res, sig_res)
    assert dec["verdict"] == "SUSPICIOUS"
    assert dec["certified"] is True
    assert any("physically looks stuck" in r.lower() or "warning" in r.lower() for r in dec["reasons"])

def test_failed_crypto_causes_block():
    url_res = {"score": 0.10, "signals": []}
    cv_res = {"score": 0.10, "status": "ok", "signals": []}
    sig_res = {"status": "invalid", "issuer": None}
    dec = decide(url_res, cv_res, sig_res)
    assert dec["verdict"] == "BLOCK"
    assert dec["certified"] is False
    assert any("cryptographic verification" in r.lower() for r in dec["reasons"])

def test_revoked_crypto_causes_block():
    url_res = {"score": 0.10, "signals": []}
    cv_res = {"score": 0.10, "status": "ok", "signals": []}
    sig_res = {"status": "revoked", "issuer": {"name": "Malicious Merchant"}}
    dec = decide(url_res, cv_res, sig_res)
    assert dec["verdict"] == "BLOCK"
    assert dec["certified"] is False

def test_clean_unsigned_safe():
    url_res = {"score": 0.08, "signals": []}
    cv_res = {"score": 0.12, "status": "ok", "signals": []}
    sig_res = {"status": "none", "issuer": None}
    dec = decide(url_res, cv_res, sig_res)
    assert dec["verdict"] == "SAFE"
    assert dec["certified"] is False
    assert dec["risk"] < 0.30

def test_phishing_url_blocked():
    url_res = {
        "score": 0.88,
        "signals": [{"name": "typosquat_domain", "text": "Domain imitates PhonePe"}]
    }
    cv_res = {"score": 0.15, "status": "ok", "signals": []}
    sig_res = {"status": "none", "issuer": None}
    dec = decide(url_res, cv_res, sig_res)
    assert dec["verdict"] == "BLOCK"
    assert dec["risk"] >= 0.65

def test_sticker_overlay_tamper_detected():
    url_res = {"score": 0.10, "signals": []}
    cv_res = {
        "score": 0.78,
        "status": "ok",
        "signals": [{"name": "sticker_edge_detected", "text": "Sticker boundary detected"}]
    }
    sig_res = {"status": "none", "issuer": None}
    dec = decide(url_res, cv_res, sig_res)
    # Even if URL is clean, physical sticker over parking code is SUSPICIOUS/BLOCK
    assert dec["verdict"] in ("SUSPICIOUS", "BLOCK")

def test_blocklist_hard_override():
    url_res = {
        "score": 0.40,
        "signals": [{"name": "blocklist_match", "text": "Flagged on blocklist"}]
    }
    cv_res = {"score": 0.10, "status": "ok", "signals": []}
    sig_res = {"status": "none", "issuer": None}
    dec = decide(url_res, cv_res, sig_res)
    assert dec["verdict"] == "BLOCK"
    assert dec["risk"] == 1.0
