"""
Second-photo verification (F21).

When one photo is inconclusive the user is asked for a second shot from ~30 degrees. Both photos are
rectified onto the QR plane (a sticker lies in the same plane as its surface, so both views align),
then three things are checked:

  1. consistency - both photos must decode to the SAME payload;
  2. an independent look - the tamper model is run on the second photo too;
  3. a photometric differential - after plane alignment, gloss/highlights move differently over a
     sticker of another material than over the surface around it.

The differential cue is only a weak supporting signal: physical parallax from a ~0.1 mm sticker is far
below phone resolution, so it is deliberately NOT used as a primary detector.
"""
from __future__ import annotations

from typing import Any, Dict

import cv2
import numpy as np

from qrshield.cv_layer.rectify import ring

_OUTER = ring(84, 124)


def _norm_l(rect_bgr: np.ndarray) -> np.ndarray:
    lab = cv2.cvtColor(rect_bgr, cv2.COLOR_BGR2LAB).astype(np.float32)
    l = cv2.GaussianBlur(lab[..., 0] * (100.0 / 255.0), (0, 0), 2.0)
    return l / max(float(np.median(l[_OUTER])), 1.0)             # exposure-normalise against the surface


def differential_cue(m1: Dict[str, Any], m2: Dict[str, Any]) -> Dict[str, float]:
    """How differently the paper around the code and the surface changed between the two views (0..1)."""
    edge_pos = [s["pos"] for s in m1["geom"]["sides"] if s["edge"]]
    inner_hi = int(np.median(edge_pos)) - 3 if edge_pos else 16
    inner_hi = int(np.clip(inner_hi, 8, 40))
    inner, outer = ring(4, inner_hi), ring(min(inner_hi + 8, 84), 124)
    d = np.abs(_norm_l(m1["rect"]) - _norm_l(m2["rect"])) * 100.0
    d_in, d_out = float(d[inner].mean()), float(d[outer].mean())
    magnitude = max(d_in, d_out)
    ratio = (d_in + 1.0) / (d_out + 1.0)
    dev = max(ratio, 1.0 / ratio) - 1.0
    cue = float(np.clip((dev - 0.6) / 1.6, 0.0, 1.0)) if magnitude > 3.0 else 0.0
    return {"cue": cue, "d_inner": d_in, "d_outer": d_out, "ratio": ratio}
