"""
Occlusion-sensitivity map for the tamper model (explainable AI for the visual layer).

The tamper model is a gradient-boosted tree on hand-built physical features, so there is no network to
back-propagate through. Instead we ask the model directly: *"if this part of the photo were blanked out, how
much would the tamper probability change?"*  A square window slides over the rectified canvas; each window is
replaced by a heavily blurred copy of itself (colour kept, edges / grain / hidden blocks removed), the full
feature vector is re-measured and re-scored, and

    saliency(cell) = margin(original) - margin(occluded)       (booster log-odds, so it never saturates)

is accumulated per pixel (averaged where windows overlap). Positive = this region is evidence FOR tampering,
negative = this region argues against it. This is the model-agnostic cousin of Grad-CAM and it is exact, because
it re-runs the real feature extractor and the real classifier rather than approximating them.
"""
from __future__ import annotations

import base64
from typing import Any, Dict

import cv2
import numpy as np

from qrshield.cv_layer import features as F, model as CM
from qrshield.cv_layer.rectify import M, Q, S

WINDOW = 96                      # occlusion window, canvas pixels (the QR itself is Q = 128 wide)
GRID = 5                         # GRID x GRID windows -> GRID**2 extra feature extractions (~70 ms each)
_BLUR_SIGMA = 28.0
_MIN_PEAK = 0.30                 # log-odds; if no window moves the model by at least this much, report "no hot spot"


def _occlude(rect: np.ndarray, blurred: np.ndarray, x0: int, y0: int) -> np.ndarray:
    out = rect.copy()
    out[y0:y0 + WINDOW, x0:x0 + WINDOW] = blurred[y0:y0 + WINDOW, x0:x0 + WINDOW]
    return out


def occlusion_map(art: Dict[str, Any], rect: np.ndarray, coverage: float, qr_px: float, skew: float,
                  ) -> Dict[str, Any]:
    """Return {"base", "map" (S x S float32, +ve = supports tamper), "peak", "cells"} for one rectified canvas."""
    feats, _ = F.extract(rect, coverage, qr_px, skew)
    base = float(CM.margin(art, F.vectorize(feats))[0])
    blurred = cv2.GaussianBlur(rect, (0, 0), _BLUR_SIGMA)
    starts = np.linspace(0, S - WINDOW, GRID).round().astype(int)

    acc = np.zeros((S, S), np.float32)
    cnt = np.zeros((S, S), np.float32)
    cells = []
    for y0 in starts:
        for x0 in starts:
            feats, _ = F.extract(_occlude(rect, blurred, int(x0), int(y0)), coverage, qr_px, skew)
            drop = float(base - CM.margin(art, F.vectorize(feats))[0])
            acc[y0:y0 + WINDOW, x0:x0 + WINDOW] += drop
            cnt[y0:y0 + WINDOW, x0:x0 + WINDOW] += 1.0
            cells.append({"x": int(x0), "y": int(y0), "drop": round(drop, 4)})
    sal = acc / np.maximum(cnt, 1.0)
    return {"base": base, "map": sal, "peak": float(np.abs(sal).max()), "cells": cells}


def render(rect: np.ndarray, sal: np.ndarray, peak: float) -> str:
    """Blend the map over the rectified photo: red = pushes towards 'tampered', blue = pushes towards 'genuine'."""
    scale = max(peak, _MIN_PEAK)
    pos = np.clip(sal / scale, 0.0, 1.0)
    neg = np.clip(-sal / scale, 0.0, 1.0)
    pos = cv2.GaussianBlur(pos, (0, 0), 6)
    neg = cv2.GaussianBlur(neg, (0, 0), 6)

    base = cv2.resize(rect, (S * 2, S * 2), interpolation=cv2.INTER_CUBIC).astype(np.float32)
    pos2 = cv2.resize(pos, (S * 2, S * 2), interpolation=cv2.INTER_CUBIC)[..., None]
    neg2 = cv2.resize(neg, (S * 2, S * 2), interpolation=cv2.INTER_CUBIC)[..., None]
    red = np.array([60, 60, 240], np.float32)           # BGR
    blue = np.array([235, 150, 40], np.float32)
    out = base * (1 - 0.55 * pos2 - 0.45 * neg2) + red * 0.55 * pos2 + blue * 0.45 * neg2
    out = np.clip(out, 0, 255).astype(np.uint8)
    cv2.rectangle(out, (M * 2, M * 2), ((M + Q) * 2, (M + Q) * 2), (129, 185, 16), 2)       # where the QR sits
    ok, buf = cv2.imencode(".png", out)
    return "data:image/png;base64," + base64.b64encode(buf.tobytes()).decode("ascii")


def _where(cx: float, cy: float) -> str:
    """Plain-language position of a window centre relative to the code in the middle of the canvas."""
    if M <= cx <= M + Q and M <= cy <= M + Q:
        return "on the code itself"
    vert = "above" if cy < M else "below" if cy > M + Q else ""
    horiz = "left of" if cx < M else "right of" if cx > M + Q else ""
    return f"{vert + ' and ' if vert and horiz else vert}{horiz} the code".replace("  ", " ").strip()


def explain(art: Dict[str, Any], rect: np.ndarray, coverage: float, qr_px: float, skew: float) -> Dict[str, Any]:
    res = occlusion_map(art, rect, coverage, qr_px, skew)
    top = max(res["cells"], key=lambda c: c["drop"])
    hot = top["drop"] >= _MIN_PEAK
    return {"png_b64": render(rect, res["map"], res["peak"]), "peak": round(res["peak"], 3), "hot_spot": hot,
            "hot_spot_where": _where(top["x"] + WINDOW / 2, top["y"] + WINDOW / 2) if hot else None,
            "method": f"occlusion sensitivity, {GRID}x{GRID} windows of {WINDOW}px"}
