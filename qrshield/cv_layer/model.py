"""Runtime wrapper for the M2 tamper model: LightGBM + isotonic calibration, with tree-SHAP contributions."""
from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional, Sequence, Tuple

import lightgbm as lgb
import numpy as np

from qrshield import model_store
from qrshield.cv_layer.features import FEATURE_ORDER

_BOOSTERS: Dict[int, lgb.Booster] = {}
_LOCK = threading.Lock()


def _booster(art: Dict[str, Any]) -> lgb.Booster:
    with _LOCK:
        b = _BOOSTERS.get(id(art))
        if b is None:
            b = lgb.Booster(model_str=art["booster_str"])
            _BOOSTERS[id(art)] = b
        return b


def active() -> Optional[Dict[str, Any]]:
    art = model_store.load("cv")
    if art and art.get("feature_order") != FEATURE_ORDER:
        raise RuntimeError("CV model was trained with a different feature set; retrain with `make train-cv`")
    return art


def predict(art: Dict[str, Any], X: np.ndarray) -> np.ndarray:
    raw = _booster(art).predict(np.asarray(X, dtype=np.float32).reshape(-1, len(FEATURE_ORDER)))
    return np.clip(art["calibrator"].predict(raw), 0.0, 1.0)


def margin(art: Dict[str, Any], X: np.ndarray) -> np.ndarray:
    """Uncalibrated log-odds of the booster. Unlike predict(), it does not saturate at 0/1, so small changes stay visible."""
    return _booster(art).predict(np.asarray(X, dtype=np.float32).reshape(-1, len(FEATURE_ORDER)), raw_score=True)


def contributions(art: Dict[str, Any], vec: Sequence[float]) -> List[Tuple[str, float]]:
    c = _booster(art).predict(np.asarray([vec], dtype=np.float32), pred_contrib=True)[0][:-1]
    return sorted(zip(art["feature_order"], map(float, c)), key=lambda kv: kv[1], reverse=True)
