"""
Grad-CAM & Visual Saliency Heatmap Generator (F20, F37).
Creates an explainable heatmap overlay highlighting detected sticker edges,
double boundaries, and shadow artifacts. Encodes the result as base64 PNG
for inline display in the UI.
"""
import io
import base64
import cv2
import numpy as np
from PIL import Image
from typing import Optional

def generate_tamper_heatmap_overlay(
    rectified_bgr: np.ndarray,
    masks: dict,
    tamper_risk: float
) -> str:
    """
    Renders a Grad-CAM / edge-saliency heatmap on top of the rectified QR crop.
    Returns a data URI base64 encoded PNG string.
    """
    h, w = rectified_bgr.shape[:2]
    gray = cv2.cvtColor(rectified_bgr, cv2.COLOR_BGR2GRAY)

    # Compute high-frequency spatial gradients around the transition perimeter
    grad_x = cv2.Sobel(gray, cv2.CV_32F, 1, 0, ksize=3)
    grad_y = cv2.Sobel(gray, cv2.CV_32F, 0, 1, ksize=3)
    mag = cv2.magnitude(grad_x, grad_y)

    qz_mask = masks.get("quiet_zone", np.zeros((h, w), dtype=bool))
    surface_mask = masks.get("surface", np.zeros((h, w), dtype=bool))
    ring = (qz_mask | surface_mask).astype(np.float32)

    # Focus saliency energy on the boundary transition ring
    ring_dilated = cv2.dilate(ring, cv2.getStructuringElement(cv2.MORPH_RECT, (5, 5)))
    saliency = mag * ring_dilated

    # If tamper risk is high, intensify the boundary glow
    intensity_scale = max(0.2, tamper_risk)
    saliency = cv2.GaussianBlur(saliency, (15, 15), 0)

    # Normalize to [0, 255]
    sal_norm = np.zeros((h, w), dtype=np.uint8)
    if np.max(saliency) > 0:
        cv2.normalize(saliency, sal_norm, 0, 255, cv2.NORM_MINMAX, dtype=cv2.CV_8U)

    # Modulate intensity based on tamper risk
    sal_norm = (sal_norm * intensity_scale).astype(np.uint8)

    # Apply JET colormap (blue = low, yellow/red = high tamper focus)
    heatmap_color = cv2.applyColorMap(sal_norm, cv2.COLORMAP_JET)

    # Alpha blend overlay onto original rectified BGR
    # Higher risk -> more prominent red highlight
    alpha = 0.45 if tamper_risk >= 0.50 else 0.25
    overlay = cv2.addWeighted(rectified_bgr, 1.0 - alpha, heatmap_color, alpha, 0)

    # If high risk, also draw subtle border around detected sticker edge
    if tamper_risk >= 0.60:
        # Find outer bounding box of quiet zone
        y_idx, x_idx = np.where(qz_mask)
        if len(x_idx) > 0:
            x1, y1 = np.min(x_idx), np.min(y_idx)
            x2, y2 = np.max(x_idx), np.max(y_idx)
            cv2.rectangle(overlay, (x1, y1), (x2, y2), (0, 0, 255), 2)
            cv2.putText(overlay, "Sticker Boundary", (x1, max(15, y1 - 6)),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 0, 255), 1, cv2.LINE_AA)

    # Encode to base64 PNG
    success, buffer = cv2.imencode(".png", overlay)
    if not success:
        return ""

    b64_str = base64.b64encode(buffer).decode("utf-8")
    return f"data:image/png;base64,{b64_str}"
