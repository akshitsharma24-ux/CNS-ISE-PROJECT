"""
Runtime wrapper around the M1 artefact: a two-model blend, calibrated.

  * LightGBM on ~50 structured URL features (host shape, brand impersonation, path/query)
  * a hashed character 3-5-gram logistic model on host + path text
The two probabilities are averaged and passed through an isotonic calibrator, so a score of 0.8
means roughly "80% of URLs scored like this were phishing" on the (class-balanced) training
corpus. Both models are stored as portable arrays/text, never as pickled library objects.
"""
from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional, Sequence, Tuple

import lightgbm as lgb
import numpy as np
import scipy.sparse as sp
from sklearn.feature_extraction.text import HashingVectorizer

from qrshield import model_store
from qrshield.url_layer.features import FEATURE_ORDER

NGRAM_FEATURES = 2 ** 18
_HV = HashingVectorizer(analyzer="char", ngram_range=(3, 5), n_features=NGRAM_FEATURES,
                        alternate_sign=False, norm=None)
_BOOSTERS: Dict[int, lgb.Booster] = {}
_LOCK = threading.Lock()


def _booster(artefact: Dict[str, Any]) -> lgb.Booster:
    key = id(artefact)
    with _LOCK:
        b = _BOOSTERS.get(key)
        if b is None:
            b = lgb.Booster(model_str=artefact["booster_str"])
            _BOOSTERS[key] = b
        return b


def active() -> Optional[Dict[str, Any]]:
    art = model_store.load("url")
    if art and art.get("feature_order") != FEATURE_ORDER:
        raise RuntimeError("URL model was trained with a different feature set; retrain with `make train-url`")
    return art


def ngram_matrix(texts: Sequence[str], idf: np.ndarray) -> sp.csr_matrix:
    """Hashed counts -> sublinear tf -> idf weighting -> L2 normalisation (sklearn TF-IDF recipe)."""
    m = _HV.transform(list(texts)).tocsr().astype(np.float64)
    m.data = 1.0 + np.log(m.data)
    m = m.multiply(idf.reshape(1, -1)).tocsr()
    norms = np.sqrt(m.multiply(m).sum(axis=1)).A1
    norms[norms == 0] = 1.0
    return sp.diags(1.0 / norms) @ m


def ngram_scores(artefact: Dict[str, Any], texts: Sequence[str]) -> np.ndarray:
    ng = artefact["ngram"]
    z = ngram_matrix(texts, ng["idf"]) @ ng["coef"] + ng["intercept"]
    return 1.0 / (1.0 + np.exp(-z))


def raw_scores(artefact: Dict[str, Any], rows: Sequence[Sequence[float]], texts: Sequence[str]) -> Tuple[np.ndarray, np.ndarray]:
    p_lgb = _booster(artefact).predict(np.asarray(rows, dtype=np.float32))
    return p_lgb, ngram_scores(artefact, texts)


def predict_proba(artefact: Dict[str, Any], rows: Sequence[Sequence[float]], texts: Sequence[str]) -> np.ndarray:
    p_lgb, p_ng = raw_scores(artefact, rows, texts)
    return np.clip(artefact["calibrator"].predict((p_lgb + p_ng) / 2.0), 0.0, 1.0)


def contributions(artefact: Dict[str, Any], row: Sequence[float]) -> List[Tuple[str, float]]:
    """Tree-SHAP contributions (log-odds) of the structured model, most risk-increasing first."""
    contrib = _booster(artefact).predict(np.asarray([row], dtype=np.float32), pred_contrib=True)[0][:-1]
    return sorted(zip(artefact["feature_order"], map(float, contrib)), key=lambda kv: kv[1], reverse=True)
