"""
Image quality gate (F05)
Evaluates sharpness (Laplacian variance), glare (saturated pixels),
and physical pixel size of the QR code to guide user capture and
protect downstream CV and URL models from noisy evaluations.
"""
import cv2
import numpy as np
from typing import Dict, Any, List, Optional

def assess_image_quality(
    img: np.ndarray,
    corners: Optional[np.ndarray] = None
) -> Dict[str, Any]:
    """
    Evaluates blur, glare, and resolution of the input image.

    Parameters:
        img: BGR or Grayscale numpy image
        corners: Detected QR 4 corner points if available

    Returns:
        dict:
            - blur_score: float (Laplacian variance)
            - is_blurry: bool
            - glare_ratio: float (fraction of saturated pixels)
            - is_glare: bool
            - qr_side_length_px: float or None
            - is_too_small: bool
            - status: "ok" | "low_quality" | "inconclusive"
            - hints: list[str] of actionable suggestions
    """
    hints: List[str] = []

    if img is None or img.size == 0:
        return {
            "status": "low_quality",
            "blur_score": 0.0,
            "is_blurry": True,
            "glare_ratio": 1.0,
            "is_glare": False,
            "qr_side_length_px": 0.0,
            "is_too_small": True,
            "hints": ["Image could not be read or is empty."]
        }

    # Convert to grayscale if necessary
    if len(img.shape) == 3:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    else:
        gray = img

    h, w = gray.shape[:2]

    # 1. Blur Detection using Laplacian Variance
    lap_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
    # Typical threshold: < 60 indicates moderate to severe blur
    is_blurry = lap_var < 50.0
    if is_blurry:
        hints.append("Hold steady - image appears blurry.")

    # 2. Glare Detection (percentage of near-saturated pixels)
    # Highlight pixels > 250 in 8-bit scale
    saturated_pixels = np.sum(gray >= 250)
    total_pixels = gray.size
    glare_ratio = float(saturated_pixels / max(total_pixels, 1))
    # If over 6% is pure white glare, reflection is high
    is_glare = glare_ratio > 0.06
    if is_glare:
        hints.append("Tilt to avoid glare - reflections detected on surface.")

    # 3. QR code pixel size
    qr_side_length = None
    is_too_small = False
    if corners is not None and len(corners) > 0:
        pts = np.squeeze(corners)
        if pts.shape == (4, 2):
            side1 = np.linalg.norm(pts[0] - pts[1])
            side2 = np.linalg.norm(pts[1] - pts[2])
            side3 = np.linalg.norm(pts[2] - pts[3])
            side4 = np.linalg.norm(pts[3] - pts[0])
            qr_side_length = float(np.mean([side1, side2, side3, side4]))
            # If the QR code side length is less than 110 pixels, resolution is low
            if qr_side_length < 110.0:
                is_too_small = True
                hints.append("Move closer - QR code is too small in frame.")
    else:
        # If no corners, evaluate against overall image dimensions
        if min(h, w) < 200:
            is_too_small = True
            hints.append("Image resolution is very low.")

    # Determine overall status
    if is_blurry or is_too_small:
        status = "low_quality"
    elif is_glare:
        status = "inconclusive"
    else:
        status = "ok"

    return {
        "blur_score": round(lap_var, 2),
        "is_blurry": is_blurry,
        "glare_ratio": round(glare_ratio, 4),
        "is_glare": is_glare,
        "qr_side_length_px": round(qr_side_length, 1) if qr_side_length else None,
        "is_too_small": is_too_small,
        "status": status,
        "hints": hints
    }
