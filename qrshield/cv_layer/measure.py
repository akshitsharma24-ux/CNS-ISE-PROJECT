"""
Shared measurement pipeline for the tamper layer: frame -> corners -> quality -> rectified canvas -> features.
Used identically by training (simulated or real photos) and by live scans.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import numpy as np

from qrshield.capture.decode import analyze_frame
from qrshield.capture.quality import assess_image_quality, order_corners
from qrshield.cv_layer import features as F
from qrshield.cv_layer.rectify import rectify

MIN_COVERAGE = 0.45          # share of the rectified canvas that must be real photo pixels (coverage is also a model feature)


def measure(img: np.ndarray, corners: Optional[np.ndarray] = None) -> Dict[str, Any]:
    """Return {"ok": bool, ...}. On success: features, geom, rect, quality, corners, coverage."""
    stacked, stacked_details, payload = False, "", None
    if corners is None:
        frame = analyze_frame(img)
        if frame.primary is None:
            return {"ok": False, "reason": "no_code", "message": "No QR code found in the image."}
        corners, stacked, stacked_details = frame.primary.corners, frame.stacked, frame.stacked_details
        payload = frame.primary.text
    corners = order_corners(corners)
    quality = assess_image_quality(img, corners)
    rect, coverage = rectify(img, corners)
    out: Dict[str, Any] = {"ok": True, "quality": quality, "corners": corners, "rect": rect, "coverage": coverage,
                           "stacked": stacked, "stacked_details": stacked_details, "payload": payload}
    if quality["status"] == "low_quality":
        out.update(ok=False, reason="low_quality", message="; ".join(quality["hints"]) or "The photo quality is too low.")
        return out
    if coverage < MIN_COVERAGE:
        out.update(ok=False, reason="partial_view", message="Step back so the code and the area around it are fully in view.")
        return out
    feats, geom = F.extract(rect, coverage, quality["qr_side_length_px"] or 0.0, quality["skew_ratio"] or 1.0)
    out.update(features=feats, vector=F.vectorize(feats), geom=geom)
    return out
