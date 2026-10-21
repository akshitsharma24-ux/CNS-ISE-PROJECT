"""
Evidence overlay for the UI (F37).

Draws what the tamper layer actually MEASURED on the rectified view of the code - not a decorative
heat-map: detected straight boundaries, the shadow band along them, ink-dark module-sized blobs
outside the code (a hidden original?), and rectangular frames around the code.
"""
from __future__ import annotations

import base64
from typing import Any, Dict, List, Tuple

import cv2
import numpy as np

from qrshield.cv_layer.rectify import M, Q, S

RED, ORANGE, CYAN, YELLOW, GREEN = (68, 68, 239), (11, 158, 245), (212, 182, 6), (21, 204, 250), (129, 185, 16)


def render(rect_bgr: np.ndarray, geom: Dict[str, Any], tamper_score: float) -> Tuple[str, List[Dict[str, str]]]:
    """Return (data-URI PNG, legend entries for what is drawn)."""
    img = cv2.resize(rect_bgr, (S * 2, S * 2), interpolation=cv2.INTER_CUBIC)
    k = 2
    over = img.copy()
    legend: List[Dict[str, str]] = []

    cv2.rectangle(img, (M * k, M * k), ((M + Q) * k, (M + Q) * k), GREEN, 2)

    for side in geom.get("sides", []):
        if not side["edge"]:
            continue
        pos = side["pos"]
        name = side["side"]
        if name == "top":
            y = int((M - 1 - pos) * k); a, b = (M * k, y), ((M + Q) * k, y); band = ((M * k, y - 12 * k), ((M + Q) * k, y))
        elif name == "bottom":
            y = int((M + Q + pos) * k); a, b = (M * k, y), ((M + Q) * k, y); band = ((M * k, y), ((M + Q) * k, y + 12 * k))
        elif name == "left":
            x = int((M - 1 - pos) * k); a, b = (x, M * k), (x, (M + Q) * k); band = ((x - 12 * k, M * k), (x, (M + Q) * k))
        else:
            x = int((M + Q + pos) * k); a, b = (x, M * k), (x, (M + Q) * k); band = ((x, M * k), (x + 12 * k, (M + Q) * k))
        if side.get("shadow", 0) > 3.0:
            cv2.rectangle(over, band[0], band[1], ORANGE, -1)
        cv2.line(img, a, b, RED, 2, cv2.LINE_AA)
    if any(s["edge"] for s in geom.get("sides", [])):
        legend.append({"color": "#ef4444", "label": "Straight boundary around the code (sticker edge?)"})
    if any(s.get("shadow", 0) > 3.0 and s["edge"] for s in geom.get("sides", [])):
        legend.append({"color": "#f59e0b", "label": "Shadow band along the boundary (raised paper)"})

    for (x, y, w, h) in geom.get("blobs", []):
        cv2.rectangle(img, (x * k, y * k), ((x + w) * k, (y + h) * k), CYAN, 1)
    if geom.get("blobs"):
        legend.append({"color": "#06b6d4", "label": "Dark module-sized blocks outside the code (hidden code?)"})

    for quad in geom.get("rects", []):
        cv2.polylines(img, [np.asarray(quad, np.int32) * k], True, YELLOW, 1, cv2.LINE_AA)
    if geom.get("rects"):
        legend.append({"color": "#facc15", "label": "Frame / card enclosing the code"})

    img = cv2.addWeighted(over, 0.28, img, 0.72, 0)
    ok, buf = cv2.imencode(".png", img)
    return "data:image/png;base64," + base64.b64encode(buf.tobytes()).decode("ascii"), legend
