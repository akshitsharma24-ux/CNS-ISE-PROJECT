"""
M2: Visual Tamper Detection Module (Computer Vision)
Exposes cv_layer.analyze(img: bytes, img2=None) contract.
"""
from typing import Dict, Any, Optional
import numpy as np

from qrshield.capture.decode import bytes_to_cv2_image, decode_qr
from qrshield.capture.quality import assess_image_quality
from qrshield.cv_layer.rectify import rectify_qr_crop
from qrshield.cv_layer.features_edge import extract_edge_features
from qrshield.cv_layer.features_light import extract_light_features
from qrshield.cv_layer.features_print import extract_print_and_texture_features
from qrshield.cv_layer.classifier import compute_tamper_score
from qrshield.cv_layer.gradcam import generate_tamper_heatmap_overlay
from qrshield.cv_layer.second_photo import verify_second_photo

def analyze(
    img: bytes,
    img2: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Contract specified in QRshield Master Plan:
    cv_layer.analyze(img: bytes, img2=None) -> {
        "score": 0.0-1.0,
        "status": "ok|inconclusive|low_quality",
        "signals": [...],
        "heatmap_png_b64": str|None
    }
    """
    if not img:
        return {
            "score": 0.0,
            "status": "low_quality",
            "signals": [{"name": "empty_input", "value": None, "text": "No image data provided."}],
            "heatmap_png_b64": None
        }

    try:
        cv_img = bytes_to_cv2_image(img)
    except Exception as e:
        return {
            "score": 0.5,
            "status": "low_quality",
            "signals": [{"name": "decode_error", "value": str(e), "text": "Image decoding error."}],
            "heatmap_png_b64": None
        }

    # Detect QR corners and decode
    _, corners, multi_code, multi_details = decode_qr(cv_img)
    quality = assess_image_quality(cv_img, corners)

    if quality["status"] == "low_quality":
        quality_signals = [{
            "name": "quality_warning",
            "value": h,
            "text": h
        } for h in quality["hints"]]
        return {
            "score": 0.50,
            "status": "low_quality",
            "signals": quality_signals,
            "heatmap_png_b64": None
        }

    # Perspective rectification and ROI ring masking
    rectified, masks = rectify_qr_crop(cv_img, corners)

    # Extract multi-physics feature groups
    edge_feats, edge_signals = extract_edge_features(rectified, masks)
    light_feats, light_signals = extract_light_features(rectified, masks)
    print_feats, print_signals = extract_print_and_texture_features(rectified, masks)

    # Fuse features into calibrated tamper probability
    tamper_score, classifier_signals = compute_tamper_score(edge_feats, light_feats, print_feats)

    all_signals = []
    if multi_code:
        all_signals.append({
            "name": "stacked_code_pattern",
            "value": True,
            "text": multi_details or "Multiple overlapping QR regions detected (stacked sticker)."
        })
        tamper_score = max(tamper_score, 0.85)

    all_signals.extend(classifier_signals)
    all_signals.extend(edge_signals)
    all_signals.extend(light_signals)
    all_signals.extend(print_signals)

    # Deduplicate signals by name
    seen_names = set()
    unique_signals = []
    for s in all_signals:
        if s["name"] not in seen_names:
            seen_names.add(s["name"])
            unique_signals.append(s)

    # Generate explainability heatmap overlay (F37)
    heatmap_b64 = generate_tamper_heatmap_overlay(rectified, masks, tamper_score)

    status = "ok"

    # Multi-angle verification handling (F21)
    if img2 is not None:
        try:
            cv_img2 = bytes_to_cv2_image(img2)
            second_res = verify_second_photo(cv_img, cv_img2)
            unique_signals.extend(second_res.get("signals", []))
            # Average scores with weight towards second photo
            tamper_score = 0.45 * tamper_score + 0.55 * second_res["multi_view_tamper_score"]
            status = "ok"
        except Exception:
            pass
    elif 0.38 <= tamper_score <= 0.62:
        status = "inconclusive"
        unique_signals.append({
            "name": "inconclusive_angle",
            "value": True,
            "text": "Tamper probability is borderline. Please take a second photo from ~30 degrees angle."
        })

    return {
        "score": round(float(tamper_score), 4),
        "status": status,
        "signals": unique_signals,
        "heatmap_png_b64": heatmap_b64
    }
