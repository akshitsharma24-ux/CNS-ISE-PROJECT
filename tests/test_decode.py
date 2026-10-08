"""
Unit tests for M0: Capture, decode, payload typing, and quality gate.
"""
import io
import pytest
import qrcode
import numpy as np
from PIL import Image

from qrshield.capture.decode import capture_and_decode, decode_qr
from qrshield.capture.payload_types import parse_payload_type
from qrshield.capture.quality import assess_image_quality

def make_qr_bytes(data: str) -> bytes:
    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def test_decode_standard_url():
    url = "https://spit.ac.in/departments/comps"
    img_bytes = make_qr_bytes(url)
    res = capture_and_decode(img_bytes)
    assert res["success"] is True
    assert res["payload"] == url
    assert res["payload_type"] == "url"
    assert res["quality"]["status"] in ("ok", "inconclusive", "low_quality")

def test_payload_typing_upi():
    upi_payload = "upi://pay?pa=merchant@icici&pn=CityParking&am=150.00&cu=INR"
    ptype, meta = parse_payload_type(upi_payload)
    assert ptype == "upi"
    assert meta["pa"] == "merchant@icici"
    assert meta["pn"] == "CityParking"
    assert meta["am"] == "150.00"

def test_payload_typing_risky():
    js_payload = "javascript:alert(document.cookie)"
    ptype, meta = parse_payload_type(js_payload)
    assert ptype == "risky_scheme"
    assert "malicious execution scheme" in meta["warning"]

def test_quality_gate_blur():
    # Create an artificially blurry image
    blurred = np.ones((300, 300), dtype=np.uint8) * 128
    quality = assess_image_quality(blurred)
    assert quality["is_blurry"] is True
    assert quality["status"] == "low_quality"
    assert any("blurry" in h.lower() for h in quality["hints"])
