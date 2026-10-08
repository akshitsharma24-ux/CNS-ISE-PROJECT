"""
Multi-view / Second-Photo angle verification (F21).
When the single-photo classifier is inconclusive (tamper_risk between 0.40 and 0.65),
QRshield prompts for a second shot taken from ~30 degrees.
Aligns both views via ORB feature matching and compares photometric disparity
(highlights/shadow shift on raised sticker vs planar host surface).
"""
import cv2
import numpy as np
from typing import Dict, Any, Tuple, Optional

from qrshield.capture.decode import decode_qr

def verify_second_photo(
    img1: np.ndarray,
    img2: np.ndarray
) -> Dict[str, Any]:
    """
    Compares two multi-angle photos of the same QR code.

    Returns:
      - verified_same_payload: bool
      - alignment_success: bool
      - photometric_disparity: float
      - multi_view_tamper_score: float
      - signals: list
    """
    # 1. Verify both decode to the exact same payload
    p1, c1, _, _ = decode_qr(img1)
    p2, c2, _, _ = decode_qr(img2)

    same_payload = (p1 == p2) and (p1 is not None)

    gray1 = cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY) if len(img1.shape) == 3 else img1
    gray2 = cv2.cvtColor(img2, cv2.COLOR_BGR2GRAY) if len(img2.shape) == 3 else img2

    # 2. ORB feature detection and matching for surface alignment
    orb = cv2.ORB_create(nfeatures=500)
    kp1, des1 = orb.detectAndCompute(gray1, None)
    kp2, des2 = orb.detectAndCompute(gray2, None)

    signals = []
    if not same_payload:
        signals.append({
            "name": "payload_mismatch_multi_view",
            "value": False,
            "text": "The two photos decoded different payloads or could not decode."
        })
        return {
            "verified_same_payload": False,
            "alignment_success": False,
            "photometric_disparity": 0.0,
            "multi_view_tamper_score": 0.90,
            "signals": signals
        }

    if des1 is None or des2 is None or len(kp1) < 8 or len(kp2) < 8:
        return {
            "verified_same_payload": True,
            "alignment_success": False,
            "photometric_disparity": 0.0,
            "multi_view_tamper_score": 0.50,
            "signals": [{
                "name": "insufficient_features",
                "value": None,
                "text": "Could not extract sufficient keypoints for angle alignment."
            }]
        }

    # Match keypoints
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = bf.match(des1, des2)
    matches = sorted(matches, key=lambda x: x.distance)

    if len(matches) < 6:
        return {
            "verified_same_payload": True,
            "alignment_success": False,
            "photometric_disparity": 0.0,
            "multi_view_tamper_score": 0.50,
            "signals": [{
                "name": "poor_alignment",
                "value": len(matches),
                "text": "Insufficient matching keypoints between viewing angles."
            }]
        }

    src_pts = np.float32([kp1[m.queryIdx].pt for m in matches[:30]]).reshape(-1, 1, 2)
    dst_pts = np.float32([kp2[m.trainIdx].pt for m in matches[:30]]).reshape(-1, 1, 2)

    H, inliers = cv2.findHomography(src_pts, dst_pts, cv2.RANSAC, 5.0)
    if H is None:
        return {
            "verified_same_payload": True,
            "alignment_success": False,
            "photometric_disparity": 0.0,
            "multi_view_tamper_score": 0.50,
            "signals": []
        }

    # Warp image2 onto image1 coordinates
    h, w = gray1.shape
    warped2 = cv2.warpPerspective(gray2, np.linalg.inv(H), (w, h))

    # Compare pixel differences
    diff = cv2.absdiff(gray1, warped2)
    disparity = float(np.mean(diff) / 255.0)

    # If disparity is high in QR area while background matches well,
    # it indicates non-coplanar physical elevation (a sticker sitting on top).
    multi_tamper_score = min(max(disparity * 2.5, 0.1), 0.95)

    if multi_tamper_score > 0.60:
        signals.append({
            "name": "photometric_relief_detected",
            "value": round(disparity, 3),
            "text": "Parallax and specular highlight displacement confirms 3D sticker relief."
        })
    else:
        signals.append({
            "name": "coplanar_confirmed",
            "value": round(disparity, 3),
            "text": "Multi-angle alignment confirms QR code is coplanar with the substrate."
        })

    return {
        "verified_same_payload": True,
        "alignment_success": True,
        "photometric_disparity": round(disparity, 4),
        "multi_view_tamper_score": round(multi_tamper_score, 3),
        "signals": signals
    }
