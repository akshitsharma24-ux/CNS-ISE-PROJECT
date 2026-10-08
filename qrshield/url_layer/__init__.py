"""
M1: URL / Payload ML Classifier Module
Exposes url_layer.analyze(payload: str) contract.
"""
import os
import joblib
import numpy as np
from typing import Dict, Any, List

from qrshield.capture.payload_types import parse_payload_type
from qrshield.url_layer.upi import analyze_upi_payload
from qrshield.url_layer.features import extract_url_features, FEATURE_ORDER, LOCAL_BLOCKLIST_DOMAINS
from qrshield.url_layer.fetch_safe import expand_and_inspect_redirects

_MODEL_CACHE = None

def _load_model():
    global _MODEL_CACHE
    if _MODEL_CACHE is not None:
        return _MODEL_CACHE

    model_path = os.path.join(os.path.dirname(__file__), "model.joblib")
    if os.path.exists(model_path):
        try:
            _MODEL_CACHE = joblib.load(model_path)
            return _MODEL_CACHE
        except Exception:
            pass
    return None

def analyze(payload: str, offline: bool = True) -> Dict[str, Any]:
    """
    Contract specified in QRshield Master Plan:
    url_layer.analyze(payload: str) -> {
        "score": 0.0-1.0,
        "payload_type": "url|upi|other",
        "signals": [{"name": str, "value": any, "text": str}]
    }
    """
    if not payload:
        return {
            "score": 0.0,
            "payload_type": "other",
            "signals": [{"name": "empty", "value": None, "text": "Empty payload"}]
        }

    ptype, pmeta = parse_payload_type(payload)

    # 1. UPI Payload Handling (F11)
    if ptype == "upi":
        upi_analysis = analyze_upi_payload(payload)
        return {
            "score": upi_analysis["score"],
            "payload_type": "upi",
            "signals": upi_analysis["signals"]
        }

    # 2. Risky Schemes (javascript:, data:, intent://)
    if ptype == "risky_scheme":
        return {
            "score": 0.95,
            "payload_type": "other",
            "signals": [{
                "name": "dangerous_scheme",
                "value": pmeta.get("scheme"),
                "text": pmeta.get("warning", "Inherently dangerous execution scheme detected.")
            }]
        }

    # 3. Non-URL, Non-UPI payload (WiFi, tel, text, etc.)
    if ptype != "url":
        return {
            "score": 0.05,
            "payload_type": "other",
            "signals": [{
                "name": f"benign_{ptype}",
                "value": ptype,
                "text": f"Payload is standard non-executable {ptype.upper()} data."
            }]
        }

    # 4. Web URL Analysis (F06 - F10, F12)
    features, signals, meta = extract_url_features(payload, offline=offline)

    # Hard Override: Local Blocklist Match (F10)
    if meta.get("is_blocklisted", False):
        return {
            "score": 1.0,
            "payload_type": "url",
            "signals": signals
        }

    # Safe redirect inspection for shorteners
    if "bit.ly" in payload or "tinyurl" in payload or "t.co" in payload or "cutt.ly" in payload:
        redir_res = expand_and_inspect_redirects(payload)
        signals.extend(redir_res.get("signals", []))
        if redir_res.get("domain_changed"):
            # Update domain features based on final target
            features["double_slash_redirect"] = 1.0

    # Model inference
    model_obj = _load_model()
    if model_obj is not None:
        clf = model_obj["model"]
        row = np.array([[features[f] for f in FEATURE_ORDER]], dtype=np.float32)
        try:
            prob = float(clf.predict_proba(row)[0, 1])
        except Exception:
            prob = 0.5
    else:
        # Fallback rule-based heuristic if model.joblib not present
        score = 0.1
        if features["is_typosquat"]:
            score += 0.5
        if features["is_ip_host"]:
            score += 0.4
        if features["is_abused_tld"]:
            score += 0.3
        if features["keyword_count"] >= 2:
            score += 0.25
        if features["brand_in_sub_path"]:
            score += 0.4
        prob = min(max(score, 0.0), 1.0)

    # Hard heuristic bounds for critical signals
    if features["is_typosquat"] and prob < 0.70:
        prob = 0.75
    if features["brand_in_sub_path"] and prob < 0.65:
        prob = 0.70
    if features["is_ip_host"] and prob < 0.65:
        prob = 0.70

    return {
        "score": round(float(prob), 4),
        "payload_type": "url",
        "signals": signals
    }
