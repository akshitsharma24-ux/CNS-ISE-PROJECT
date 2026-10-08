"""
Unit tests for M1: URL & Payload ML layer
"""
import pytest
from qrshield.url_layer import analyze
from qrshield.url_layer.brands import check_brand_typosquat, normalize_homoglyphs
from qrshield.url_layer.fetch_safe import is_ip_allowed

def test_benign_college_url():
    res = analyze("https://spit.ac.in/departments/comps")
    assert res["payload_type"] == "url"
    assert res["score"] < 0.35  # Should be classified as SAFE

def test_phishing_typosquat_url():
    res = analyze("https://secure-phonepe-refund.xyz/claim-cashback?amt=2000")
    assert res["payload_type"] == "url"
    assert res["score"] > 0.65  # Should be high risk
    assert any("phonepe" in s["text"].lower() or "xyz" in s["text"].lower() for s in res["signals"])

def test_upi_payee_mismatch():
    res = analyze("upi://pay?pa=scammer99@ybl&pn=StateBankOfIndia&am=2500")
    assert res["payload_type"] == "upi"
    assert res["score"] >= 0.50
    assert any("mismatch" in s["name"].lower() for s in res["signals"])

def test_homoglyph_typosquat():
    # 'pаytm' with cyrillic 'а'
    norm = normalize_homoglyphs("p\u0430ytm")
    assert norm == "paytm"

def test_ssrf_filter():
    # Loopback
    ok, _ = is_ip_allowed("127.0.0.1")
    assert ok is False
    # RFC 1918 Private
    ok, _ = is_ip_allowed("192.168.1.1")
    assert ok is False
    ok, _ = is_ip_allowed("10.0.0.5")
    assert ok is False
    # AWS metadata
    ok, _ = is_ip_allowed("169.254.169.254")
    assert ok is False
    # Public IP
    ok, _ = is_ip_allowed("8.8.8.8")
    assert ok is True
