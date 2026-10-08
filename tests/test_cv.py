"""
Unit tests for M2: Visual Tamper Detection (Computer Vision)
"""
import io
import pytest
import cv2
import numpy as np
import qrcode
from PIL import Image

from qrshield.cv_layer import analyze
from qrshield.cv_layer.rectify import rectify_qr_crop
from qrshield.cv_layer.gradcam import generate_tamper_heatmap_overlay

def create_synthetic_qr_image(payload: str, with_sticker_border: bool = False) -> bytes:
    """Generates synthetic QR on a background surface with optional sticker border."""
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(payload)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    qr_np = np.array(qr_img)

    # Place on larger 400x400 canvas (representing wooden table / poster)
    canvas = np.ones((400, 400, 3), dtype=np.uint8) * 210  # light grey wood/plastic

    h, w = qr_np.shape[:2]
    y_off, x_off = 50, 50

    if with_sticker_border:
        # Draw physical sticker backing with distinct color and sharp drop shadow
        cv2.rectangle(canvas, (x_off - 12, y_off - 12), (x_off + w + 14, y_off + h + 14), (80, 80, 80), -1)  # shadow
        cv2.rectangle(canvas, (x_off - 10, y_off - 10), (x_off + w + 10, y_off + h + 10), (255, 255, 250), -1)  # sticker paper

    canvas[y_off:y_off+h, x_off:x_off+w] = qr_np

    _, buf = cv2.imencode(".png", canvas)
    return buf.tobytes()

def test_clean_qr_cv_analysis():
    img_bytes = create_synthetic_qr_image("https://spit.ac.in", with_sticker_border=False)
    res = analyze(img_bytes)
    assert "score" in res
    assert res["status"] in ("ok", "inconclusive")
    assert res["heatmap_png_b64"] is not None
    assert len(res["signals"]) >= 0

def test_tampered_qr_cv_analysis():
    img_bytes = create_synthetic_qr_image("https://scam-parking.example", with_sticker_border=True)
    res = analyze(img_bytes)
    assert res["score"] > 0.40  # Elevated tamper risk due to sticker backing and shadow
    assert res["heatmap_png_b64"] is not None
    assert any("sticker" in s["name"] or "edge" in s["name"] or "cutline" in s["name"] or "color" in s["name"] for s in res["signals"])

def test_multi_angle_analysis():
    img1 = create_synthetic_qr_image("https://citypark.example", with_sticker_border=False)
    img2 = create_synthetic_qr_image("https://citypark.example", with_sticker_border=False)
    res = analyze(img1, img2=img2)
    assert res["status"] == "ok"
    assert res["score"] < 0.50
