"""
QR rectification and region geometry for the tamper layer (F14).

The photo is warped (homography from the decoded QR corners) so the code sits in the centre of a
fixed 384x384 canvas with exactly one QR-width of surrounding surface on every side:

        +-----------------+     S = 384 px
        |     surface     |     Q = 128 px  (QR width)
        |   +---------+   |     every feature is measured in these canonical units, so
        |   |   QR    |   |     it does not depend on how large the code is in the photo
        |   +---------+   |
        +-----------------+
"""
from __future__ import annotations

from typing import Tuple

import cv2
import numpy as np

from qrshield.capture.quality import order_corners

S = 384
Q = 128
M = (S - Q) // 2                 # margin = 128 px = one QR width

_yy, _xx = np.mgrid[0:S, 0:S]
# Chebyshev distance outside the QR square (negative inside). 1 px ~ 1/128 of a QR width.
DIST = np.maximum(np.abs(_xx - (S - 1) / 2.0), np.abs(_yy - (S - 1) / 2.0)) - Q / 2.0

CORE = DIST < -2                 # QR modules (shrunk by 2 px to avoid the edge)


def ring(lo: float, hi: float) -> np.ndarray:
    """Boolean mask of pixels whose distance outside the QR lies in [lo, hi)."""
    return (DIST >= lo) & (DIST < hi)


def rectify(img: np.ndarray, corners: np.ndarray) -> Tuple[np.ndarray, float]:
    """Return (rectified BGR canvas, fraction of the canvas covered by real photo pixels)."""
    src = order_corners(corners)
    dst = np.array([[M, M], [M + Q - 1, M], [M + Q - 1, M + Q - 1], [M, M + Q - 1]], dtype=np.float32)
    h = cv2.getPerspectiveTransform(src, dst)
    rect = cv2.warpPerspective(img, h, (S, S), flags=cv2.INTER_AREA if Q < 0.8 * np.linalg.norm(src[1] - src[0]) else cv2.INTER_LINEAR,
                               borderMode=cv2.BORDER_REPLICATE)
    ones = np.full(img.shape[:2], 255, np.uint8)
    valid = cv2.warpPerspective(ones, h, (S, S), flags=cv2.INTER_NEAREST, borderMode=cv2.BORDER_CONSTANT, borderValue=0)
    return rect, float((valid > 0).mean())
