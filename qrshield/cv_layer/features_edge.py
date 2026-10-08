"""
Edge and boundary discontinuity feature extraction (F15).
Detects physical sticker borders, double cutlines, and peeking original QR fragments.
"""
import cv2
import numpy as np
from typing import Dict, Any, Tuple

def extract_edge_features(
    rectified_bgr: np.ndarray,
    masks: Dict[str, np.ndarray]
) -> Tuple[Dict[str, float], list]:
    """
    Computes gradient magnitude, straight cutline edges, and peeking QR fragment metrics.
    """
    gray = cv2.cvtColor(rectified_bgr, cv2.COLOR_BGR2GRAY)
    qz_mask = masks["quiet_zone"]
    surface_mask = masks["surface"]
    ring_mask = qz_mask | surface_mask  # perimeter transition zone

    # 1. Gradient magnitude via Sobel
    grad_x = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
    grad_y = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
    grad_mag = np.sqrt(grad_x**2 + grad_y**2)

    # Edge strength specifically along the sticker transition ring (excluding inner black modules)
    qr_dilated = cv2.dilate(masks["qr_core"].astype(np.uint8), cv2.getStructuringElement(cv2.MORPH_RECT, (9, 9)))
    safe_ring = ring_mask & (qr_dilated == 0)

    ring_edge_energy = float(np.mean(grad_mag[safe_ring])) if np.any(safe_ring) else 0.0
    surface_edge_energy = float(np.mean(grad_mag[surface_mask])) if np.any(surface_mask) else 0.0
    if ring_edge_energy < 12.0:
        edge_discontinuity_ratio = 1.0
    else:
        edge_discontinuity_ratio = float(ring_edge_energy / max(surface_edge_energy, 6.0))



    # 2. Canny edges and Hough line detection for straight sticker borders
    canny = cv2.Canny(gray, 50, 150)
    # Mask Canny to only inspect the quiet zone and inner surface, excluding the QR core modules
    qr_dilated = cv2.dilate(masks["qr_core"].astype(np.uint8), cv2.getStructuringElement(cv2.MORPH_RECT, (9, 9)))
    ring_canny = canny.copy()
    ring_canny[~ring_mask] = 0
    ring_canny[qr_dilated > 0] = 0
    # Zero out image frame boundary
    ring_canny[:6, :] = 0
    ring_canny[-6:, :] = 0
    ring_canny[:, :6] = 0
    ring_canny[:, -6:] = 0

    lines = cv2.HoughLinesP(ring_canny, 1, np.pi / 180, threshold=30, minLineLength=25, maxLineGap=8)



    parallel_edge_count = 0
    if lines is not None:
        for line in lines:
            pts = line.reshape(-1)
            if len(pts) >= 4:
                x1, y1, x2, y2 = pts[0], pts[1], pts[2], pts[3]
                dx = abs(x2 - x1)
                dy = abs(y2 - y1)
                # Lines roughly horizontal (dy small) or vertical (dx small)
                if dx < 6 or dy < 6:
                    parallel_edge_count += 1


    # 3. Double-border contour detection
    # Look for rectangular contours in the ring region
    contours, _ = cv2.findContours(canny, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
    concentric_rect_count = 0
    h, w = gray.shape
    for cnt in contours:
        area = cv2.contourArea(cnt)
        if 0.15 * (h * w) < area < 0.85 * (h * w):
            peri = cv2.arcLength(cnt, True)
            approx = cv2.approxPolyDP(cnt, 0.03 * peri, True)
            if len(approx) == 4 and cv2.isContourConvex(approx):
                concentric_rect_count += 1

    # 4. Peeking QR pattern fragments outside the code
    # QR patterns have high local variance and binary distribution (black/white blocks)
    surface_pixels = gray[surface_mask]
    surface_std = float(np.std(surface_pixels))
    peeking_fragment_indicator = 1.0 if (surface_std > 55.0 and concentric_rect_count >= 1) else 0.0

    features = {
        "edge_ring_energy": round(ring_edge_energy, 2),
        "edge_discontinuity_ratio": round(edge_discontinuity_ratio, 3),
        "parallel_cutline_count": float(parallel_edge_count),
        "concentric_rect_count": float(concentric_rect_count),
        "peeking_fragment_indicator": peeking_fragment_indicator
    }

    signals = []
    if edge_discontinuity_ratio > 1.85:
        signals.append({
            "name": "sticker_edge_discontinuity",
            "value": edge_discontinuity_ratio,
            "text": "Distinct boundary discontinuity detected around QR perimeter."
        })
    if parallel_edge_count >= 3:
        signals.append({
            "name": "cutline_detected",
            "value": parallel_edge_count,
            "text": "Straight cutlines parallel to QR modules detected (sticker overlay marker)."
        })
    if concentric_rect_count >= 2:
        signals.append({
            "name": "double_border",
            "value": concentric_rect_count,
            "text": "Concentric double-border detected indicating physical sticker."
        })

    return features, signals
