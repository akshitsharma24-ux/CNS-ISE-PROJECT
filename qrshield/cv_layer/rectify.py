"""
QR Perspective Rectification and ROI Ring Partitioning (F14).
Extracts QR corners, computes homography, and warps to a standardized
square with surrounding context (1.5x QR width). Defines three analytical ROIs:
1. QR core
2. Quiet-zone ring
3. Surrounding surface ring
"""
import cv2
import numpy as np
from typing import Tuple, Dict, Optional, Any

TARGET_SIZE = 300  # Standard rectified dimension: 300x300 pixels
QR_INNER_RATIO = 0.60  # QR code occupies inner 60% (180x180 px)
QUIET_ZONE_RATIO = 0.75  # Quiet zone extends to 75% (225x225 px)

def order_corner_points(pts: np.ndarray) -> np.ndarray:
    """
    Orders 4 points in canonical top-left, top-right, bottom-right, bottom-left sequence.
    """
    pts = np.squeeze(pts).astype(np.float32)
    rect = np.zeros((4, 2), dtype=np.float32)

    # Sum of coords: top-left has minimum sum, bottom-right has maximum sum
    s = pts.sum(axis=1)
    rect[0] = pts[np.argmin(s)]
    rect[2] = pts[np.argmax(s)]

    # Difference of coords: top-right has minimum diff, bottom-left has maximum diff
    diff = np.diff(pts, axis=1)
    rect[1] = pts[np.argmin(diff)]
    rect[3] = pts[np.argmax(diff)]

    return rect

def rectify_qr_crop(
    img: np.ndarray,
    corners: Optional[np.ndarray] = None
) -> Tuple[np.ndarray, Dict[str, np.ndarray]]:
    """
    Warp image to rectified 300x300 coordinate space including surrounding surface.

    Returns:
      rectified_bgr: 300x300 np.ndarray
      masks: dict containing boolean masks for 'qr_core', 'quiet_zone', 'surface'
    """
    h, w = img.shape[:2]

    # If no corners provided, attempt to detect or fallback to center crop
    if corners is None or len(corners) == 0:
        detector = cv2.QRCodeDetector()
        _, corners, _ = detector.detectAndDecode(img)

    if corners is not None and len(corners) > 0:
        pts = order_corner_points(corners)
    else:
        # Fallback bounding box around center
        cx, cy = w / 2.0, h / 2.0
        half = min(w, h) * 0.35
        pts = np.array([
            [cx - half, cy - half],
            [cx + half, cy - half],
            [cx + half, cy + half],
            [cx - half, cy + half]
        ], dtype=np.float32)

    # Target points for the QR corners in the 300x300 canvas
    # With QR_INNER_RATIO = 0.60, QR core will sit between margin and (TARGET_SIZE - margin)
    margin = (1.0 - QR_INNER_RATIO) / 2.0 * TARGET_SIZE
    qr_max = TARGET_SIZE - margin

    dst_pts = np.array([
        [margin, margin],
        [qr_max, margin],
        [qr_max, qr_max],
        [margin, qr_max]
    ], dtype=np.float32)

    # Perspective homography with border replication to avoid artificial black boundaries
    H = cv2.getPerspectiveTransform(pts, dst_pts)
    rectified_bgr = cv2.warpPerspective(
        img, H, (TARGET_SIZE, TARGET_SIZE),
        flags=cv2.INTER_LINEAR,
        borderMode=cv2.BORDER_REPLICATE
    )


    # Generate ROI Masks
    masks = {}

    # 1. QR Core Mask (inner region)
    qr_mask = np.zeros((TARGET_SIZE, TARGET_SIZE), dtype=bool)
    qr_mask[int(margin):int(qr_max), int(margin):int(qr_max)] = True
    masks["qr_core"] = qr_mask

    # 2. Quiet Zone Ring Mask (band between QR core and quiet boundary)
    qz_margin = (1.0 - QUIET_ZONE_RATIO) / 2.0 * TARGET_SIZE
    qz_max = TARGET_SIZE - qz_margin
    qz_full = np.zeros((TARGET_SIZE, TARGET_SIZE), dtype=bool)
    qz_full[int(qz_margin):int(qz_max), int(qz_margin):int(qz_max)] = True
    masks["quiet_zone"] = qz_full & (~qr_mask)

    # 3. Outer Surface Ring Mask (perimeter area outside quiet zone)
    masks["surface"] = ~qz_full

    return rectified_bgr, masks
