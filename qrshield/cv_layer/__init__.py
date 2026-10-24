"""
M2: visual tamper detection.  Exposes the `cv_layer.analyze(img, img2=None)` contract:

    {"score": 0..1, "status": "ok|inconclusive|low_quality", "signals": [...], "heatmap_png_b64": str|None}

`score` is the calibrated probability that a sticker was pasted over another surface or code.
`heatmap_png_b64` is an evidence overlay of what was measured (see evidence.py).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

import numpy as np

from qrshield.capture.decode import bytes_to_cv2_image
from qrshield.cv_layer import evidence, model as CM, saliency
from qrshield.cv_layer.features import FEATURE_ORDER
from qrshield.cv_layer.measure import measure
from qrshield.cv_layer.second_photo import differential_cue

INCONCLUSIVE_BAND = (0.38, 0.62)
STACKED_SCORE = 0.88

# explanation groups: (signal name, features that belong to it, sentence)
_GROUPS = [
    ("sticker_edge_detected", [f for f in FEATURE_ORDER if f.startswith(("edge_", "ring_"))],
     "A straight, sticker-like boundary surrounds the code."),
    ("sticker_elevation_shadow", ["shadow_max", "shadow_mean", "shadow_asym"],
     "A thin shadow runs along the boundary, as if a sheet sits on top of the surface."),
    ("paper_color_discrepancy", ["de_inner_outer", "dL_inner_outer", "db_inner_outer", "dsat_inner_outer"],
     "The paper around the code is a different colour/white-point from the surface."),
    ("print_texture_mismatch", ["noise_ratio", "noise_diff", "lbp_chi2", "lap_ratio"],
     "The print grain around the code differs from the surface it sits on."),
    ("gloss_mismatch", ["hl_inner", "hl_outer", "hl_diff"],
     "Highlights behave differently on the code's paper than on the surrounding surface."),
    ("hidden_code_fragments", ["surround_dark_frac", "n_module_blobs", "blob_area_frac", "qz_dark_frac", "qz_std_rel"],
     "Dark, module-sized blocks sit outside the code - part of another code may be hidden underneath."),
    ("double_layer_border", ["n_enclosing_rects", "enclosing_margin", "double_border"],
     "The code sits inside a frame or card, with a second border - layered paper."),
]


def _sig(name: str, value: Any, text: str, direction: str = "risk") -> Dict[str, Any]:
    return {"name": name, "value": value, "text": text, "direction": direction}


def _result(score: float, status: str, signals: List[Dict[str, Any]], heatmap: Optional[str] = None, **details: Any) -> Dict[str, Any]:
    return {"score": round(float(min(max(score, 0.0), 1.0)), 4), "status": status, "signals": signals,
            "heatmap_png_b64": heatmap, "details": details}


def _explain(art: Dict[str, Any], vec: np.ndarray, geom: Dict[str, Any]) -> List[Dict[str, Any]]:
    contrib = dict(CM.contributions(art, vec))
    scored = sorted(((sum(contrib.get(f, 0.0) for f in feats), name, text) for name, feats, text in _GROUPS), reverse=True)
    out = []
    for total, name, text in scored[:3]:
        if total < 0.35:
            break
        if name == "sticker_edge_detected":
            n = sum(1 for s in geom["sides"] if s["edge"])
            if n:
                text = f"A straight, sticker-like boundary was found on {n} side{'s' if n != 1 else ''} of the code."
        out.append(_sig(name, round(total, 2), text))
    return out


def analyze(img: Union[bytes, np.ndarray], img2: Union[bytes, np.ndarray, None] = None,
            corners: Optional[np.ndarray] = None, explain: bool = False) -> Dict[str, Any]:
    """`explain=True` additionally runs the occlusion-sensitivity map (details["saliency"]); it costs ~2 s."""
    if img is None or (isinstance(img, (bytes, bytearray)) and not img):
        return _result(0.0, "low_quality", [_sig("empty_input", None, "No image data provided.", "info")])
    try:
        arr = bytes_to_cv2_image(img) if isinstance(img, (bytes, bytearray)) else img
    except ValueError as exc:
        return _result(0.0, "low_quality", [_sig("decode_error", str(exc), "The image could not be read.", "info")])

    m = measure(arr, corners)
    if not m["ok"]:
        hints = m.get("quality", {}).get("hints") or [m.get("message", "The photo cannot be assessed.")]
        return _result(0.0, "low_quality", [_sig("quality_warning", h, h, "info") for h in hints], reason=m.get("reason"))

    art = CM.active()
    if art is None:
        return _result(0.0, "low_quality", [_sig("model_missing", None, "The tamper model is not installed.", "info")])

    p1 = float(CM.predict(art, m["vector"])[0])
    signals = _explain(art, m["vector"], m["geom"])
    score, status = p1, "ok"
    details: Dict[str, Any] = {"p_first_photo": round(p1, 4), "model_version": art.get("version", "bundled")}

    if m["quality"]["is_glare"]:
        signals.append(_sig("glare", m["quality"]["glare_ratio"], "A reflection covers part of the code, which weakens the visual check.", "info"))

    if m["stacked"]:
        signals.insert(0, _sig("stacked_code_pattern", True, m["stacked_details"] or "Two QR patterns overlap in the frame.", "risk"))
        score = max(score, STACKED_SCORE)

    if img2 is not None:
        try:
            arr2 = bytes_to_cv2_image(img2) if isinstance(img2, (bytes, bytearray)) else img2
            m2 = measure(arr2)
        except ValueError:
            m2 = {"ok": False, "message": "The second photo could not be read."}
        if not m2["ok"]:
            signals.append(_sig("second_photo_unusable", None, m2.get("message", "The second photo could not be used."), "info"))
        elif m["payload"] is not None and m2["payload"] != m["payload"]:
            signals.append(_sig("payload_mismatch_multi_view", False,
                                "The two photos decode to different codes - rescan the same code from a second angle.", "risk"))
            score = max(score, 0.7)
        else:
            p2 = float(CM.predict(art, m2["vector"])[0])
            diff = differential_cue(m, m2)
            score = 0.5 * (p1 + p2)
            weight = float(art.get("second_photo_cue_weight", 0.0))
            if diff["cue"] > 0 and weight > 0:
                score = min(1.0, score + weight * diff["cue"])
                signals.append(_sig("photometric_relief", round(diff["ratio"], 2),
                                    "Between the two angles the code's paper reacts to light differently from the surface around it."))
            else:
                signals.append(_sig("coplanar_confirmed", round(diff["ratio"], 2),
                                    "Both angles agree: the code's paper reacts to light like the surface around it.", "safe"))
            details.update(p_second_photo=round(p2, 4), differential_cue=round(diff["cue"], 3), views=2)
    elif INCONCLUSIVE_BAND[0] <= score <= INCONCLUSIVE_BAND[1]:
        status = "inconclusive"
        signals.append(_sig("inconclusive_angle", True,
                            "The visual check is borderline. Take a second photo from about 30 degrees to the side.", "info"))
    if m["quality"]["is_glare"] and status == "ok" and INCONCLUSIVE_BAND[0] - 0.1 <= score <= INCONCLUSIVE_BAND[1] + 0.1:
        status = "inconclusive"

    overlay, legend = evidence.render(m["rect"], m["geom"], score)
    details["legend"] = legend
    if explain:
        q = m["quality"]
        details["saliency"] = saliency.explain(art, m["rect"], m["coverage"], q["qr_side_length_px"] or 0.0,
                                               q["skew_ratio"] or 1.0)
    return _result(score, status, signals, overlay, **details)
