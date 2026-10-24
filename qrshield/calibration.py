"""Calibration metrics for the probabilistic layers: does a score of 0.8 really mean "about 80 % are attacks"?"""
from __future__ import annotations

from typing import Any, Dict, Sequence

import numpy as np


def reliability_bins(y_true: Sequence[int], p: Sequence[float], n_bins: int = 10) -> Dict[str, Any]:
    """Equal-width reliability table plus Expected Calibration Error (ECE), maximum calibration error and Brier score."""
    y = np.asarray(y_true, dtype=float)
    p = np.clip(np.asarray(p, dtype=float), 0.0, 1.0)
    if len(y) == 0 or len(y) != len(p):
        raise ValueError("y_true and p must be non-empty and of equal length")
    idx = np.minimum((p * n_bins).astype(int), n_bins - 1)
    bins, ece, mce = [], 0.0, 0.0
    for b in range(n_bins):
        sel = idx == b
        n = int(sel.sum())
        if n == 0:
            continue
        conf, acc = float(p[sel].mean()), float(y[sel].mean())
        gap = abs(conf - acc)
        ece += gap * n / len(y)
        mce = max(mce, gap)
        bins.append({"lo": round(b / n_bins, 2), "hi": round((b + 1) / n_bins, 2), "n": n,
                     "mean_score": round(conf, 4), "observed_rate": round(acc, 4)})
    return {"n": int(len(y)), "ece": round(float(ece), 4), "mce": round(float(mce), 4),
            "brier": round(float(np.mean((p - y) ** 2)), 4), "bins": bins}
