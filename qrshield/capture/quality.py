"""
Image quality gate (F05).

Quality is measured on the QR region itself (rectified to a canonical size) rather than on
the whole photograph, so a white poster is not mistaken for glare and a busy background is
not mistaken for sharpness. The gate guards the *visual tamper* layer: a poor photo must
produce a "retake" hint, never an unfair verdict.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import cv2
import numpy as np

CANON = 240                 # QR region is warped to CANON x CANON before measuring
MIN_SIDE_PX = 90            # smaller than this and texture analysis is meaningless
BLUR_VAR_MIN = 55.0         # variance of Laplacian on the canonical crop
GLARE_TILE_FRACTION = 0.12
MAX_SKEW = 1.6              # ratio of opposite QR sides (extreme viewing angle)


def order_corners(pts: np.ndarray) -> np.ndarray:
    """Return corners as top-left, top-right, bottom-right, bottom-left."""
    pts = np.asarray(pts, dtype=np.float32).reshape(-1, 2)
    s = pts.sum(axis=1)
    d = np.diff(pts, axis=1).ravel()
    return np.array([pts[np.argmin(s)], pts[np.argmin(d)], pts[np.argmax(s)], pts[np.argmax(d)]], dtype=np.float32)


def _side_lengths(c: np.ndarray) -> List[float]:
    return [float(np.linalg.norm(c[i] - c[(i + 1) % 4])) for i in range(4)]


def qr_crop(gray: np.ndarray, corners: np.ndarray) -> np.ndarray:
    dst = np.array([[0, 0], [CANON - 1, 0], [CANON - 1, CANON - 1], [0, CANON - 1]], dtype=np.float32)
    m = cv2.getPerspectiveTransform(order_corners(corners), dst)
    return cv2.warpPerspective(gray, m, (CANON, CANON), flags=cv2.INTER_AREA)


def assess_image_quality(img: Optional[np.ndarray], corners: Optional[np.ndarray] = None) -> Dict[str, Any]:
    if img is None or img.size == 0:
        return {"status": "low_quality", "blur_score": 0.0, "is_blurry": True, "glare_ratio": 0.0,
                "is_glare": False, "qr_side_length_px": None, "is_too_small": True, "skew_ratio": None,
                "hints": ["The image could not be read."]}

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img
    h, w = gray.shape[:2]
    hints: List[str] = []

    side = None
    skew = None
    region = gray
    if corners is not None and np.size(corners) >= 8:
        c = order_corners(corners)
        sides = _side_lengths(c)
        side = float(np.mean(sides))
        skew = max(max(sides[0], sides[2]) / max(min(sides[0], sides[2]), 1e-3),
                   max(sides[1], sides[3]) / max(min(sides[1], sides[3]), 1e-3))
        try:
            region = qr_crop(gray, c)
        except cv2.error:
            region = gray

    # Blur: variance of the Laplacian of the canonical QR crop
    blur_score = float(cv2.Laplacian(region, cv2.CV_64F).var())
    is_blurry = blur_score < BLUR_VAR_MIN
    if is_blurry:
        hints.append("Hold steady - the code looks blurry. Tap to focus and retake.")

    # Glare: tiles of the QR region that lost all contrast while bright (washed-out highlight)
    t = CANON // 6
    washed = 0
    for ty in range(6):
        for tx in range(6):
            tile = region[ty * t:(ty + 1) * t, tx * t:(tx + 1) * t]
            if int(tile.max()) - int(tile.min()) < 25 and tile.mean() > 200:
                washed += 1
    glare_ratio = washed / 36.0
    is_glare = glare_ratio > GLARE_TILE_FRACTION
    if is_glare:
        hints.append("Tilt the phone slightly to avoid the reflection on the code.")

    is_small = False
    if side is not None:
        if side < MIN_SIDE_PX:
            is_small = True
            hints.append("Move closer - the code is too small in the frame.")
        if skew is not None and skew > MAX_SKEW:
            hints.append("Hold the phone more square-on to the code.")
    elif min(h, w) < 200:
        is_small = True
        hints.append("The image resolution is very low.")

    status = "low_quality" if (is_blurry or is_small) else ("inconclusive" if is_glare else "ok")
    return {
        "status": status,
        "blur_score": round(blur_score, 1), "is_blurry": is_blurry,
        "glare_ratio": round(glare_ratio, 3), "is_glare": is_glare,
        "qr_side_length_px": round(side, 1) if side else None, "is_too_small": is_small,
        "skew_ratio": round(skew, 2) if skew else None,
        "hints": hints,
    }
