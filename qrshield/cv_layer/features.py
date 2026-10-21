"""
Physical-overlay features (F15, F16, F17), computed on the rectified 384x384 canvas.

A sticker pasted over a QR code leaves traces that no URL check can see. Each feature group below
targets one physical trace, and everything is a *relative* measurement (QR region vs. its
surroundings, in canonical QR-width units) so it does not depend on camera, distance or lighting:

  edges      straight boundary on each side of the code at a consistent distance  (sticker border)
  shadow     dark band just outside the boundary                                  (sticker thickness)
  colour     paper white-point / saturation vs. the surface                       (different stock)
  texture    noise grain, LBP histogram and sharpness vs. the surface              (different material)
  specular   bright, desaturated highlights near vs. far from the code            (gloss mismatch)
  peeking    ink-dark, module-sized blobs OUTSIDE the code                         (original code peeking out)
  quiet zone ISO quiet zone should be blank                                        (tight / dirty margin)
  frames     rectangles enclosing the code, and double borders                     (card, label + sticker)
"""
from __future__ import annotations

from typing import Dict, List, Tuple

import cv2
import numpy as np
from skimage.feature import local_binary_pattern

from qrshield.cv_layer.rectify import CORE, DIST, M, Q, S, ring

FEATURE_ORDER: List[str] = [
    "edge_n_sides", "edge_ratio_min", "edge_ratio_mean", "edge_strength_mean", "edge_pos_mean", "edge_pos_std",
    "edge_straight", "edge_de_mean", "edge_ratio_top", "edge_ratio_bottom", "edge_ratio_left", "edge_ratio_right",
    "shadow_max", "shadow_mean", "shadow_asym",
    "ring_step_max", "ring_step_pos", "ring_grad_peak_ratio",
    "de_inner_outer", "dL_inner_outer", "db_inner_outer", "dsat_inner_outer",
    "noise_ratio", "noise_diff", "lbp_chi2", "lap_ratio", "hl_inner", "hl_outer", "hl_diff",
    "qz_std_rel", "qz_dark_frac", "surround_dark_frac", "n_module_blobs", "blob_area_frac",
    "n_enclosing_rects", "enclosing_margin", "double_border",
    "core_blur", "ink_white_range", "core_noise", "ctx_noise", "mean_L", "clip_hi", "clip_lo",
    "qr_px", "skew", "coverage", "module_px",
]

_A_INNER = ring(4, 16)
_A_OUTER = ring(84, 124)
_QZ = ring(2, 14)
_QZ_WIDE = ring(2, 20)
_SURROUND = ring(4, 100)
_NSEG, _SEG_LO, _SEG_HI = 4, 8, Q - 8
_PEAK_LO, _PEAK_HI = 3, 112


def _strips(ch: np.ndarray) -> List[np.ndarray]:
    """Four (distance x along-side) strips of a channel: top, bottom, left, right of the QR."""
    top = ch[M - 1::-1, M:M + Q]
    bottom = ch[M + Q:S, M:M + Q]
    left = ch[M:M + Q, M - 1::-1].T
    right = ch[M:M + Q, M + Q:S].T
    return [top, bottom, left, right]


def _estimate_module_px(gray: np.ndarray) -> float:
    core = gray[M + 4:M + Q - 4, M + 4:M + Q - 4]
    thr, _ = cv2.threshold(core, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    binary = (core < thr).astype(np.int8)
    runs: List[int] = []
    for r in range(0, binary.shape[0], 3):
        row = binary[r]
        change = np.flatnonzero(np.diff(row)) + 1
        if len(change) >= 2:
            runs.extend(np.diff(np.concatenate([[0], change, [len(row)]])).tolist())
    if not runs:
        return 6.0
    return float(np.clip(np.percentile(runs, 25), 2.0, 14.0))


def _chi2(a: np.ndarray, b: np.ndarray) -> float:
    return float(0.5 * np.sum((a - b) ** 2 / (a + b + 1e-6)))


def extract(rect_bgr: np.ndarray, coverage: float, qr_px: float, skew: float) -> Tuple[Dict[str, float], Dict[str, object]]:
    """Return (feature dict, geometry dict). Geometry is the measured evidence drawn in the UI overlay."""
    geom: Dict[str, object] = {"sides": [], "blobs": [], "rects": []}
    gray = cv2.cvtColor(rect_bgr, cv2.COLOR_BGR2GRAY)
    lab = cv2.cvtColor(rect_bgr, cv2.COLOR_BGR2LAB).astype(np.float32)
    L = lab[..., 0] * (100.0 / 255.0)
    a, b = lab[..., 1] - 128.0, lab[..., 2] - 128.0
    hsv = cv2.cvtColor(rect_bgr, cv2.COLOR_BGR2HSV)
    Ls = cv2.GaussianBlur(L, (0, 0), 1.0)
    f: Dict[str, float] = {}

    # ------------------------------------------------------------------ per-side straight edges
    sL, sA, sB = _strips(Ls), _strips(a), _strips(b)
    ratios, strengths, poss, straights, des, shadows, sides_with_edge = [], [], [], [], [], [], []
    seg_edges = np.linspace(_SEG_LO, _SEG_HI, _NSEG + 1).astype(int)
    for side, (pl, pa, pb) in enumerate(zip(sL, sA, sB)):
        seg_str, seg_pos, seg_ratio = [], [], []
        for s0, s1 in zip(seg_edges[:-1], seg_edges[1:]):
            prof = pl[:, s0:s1].mean(axis=1)
            g = np.abs(prof[np.minimum(np.arange(M) + 2, M - 1)] - prof[np.maximum(np.arange(M) - 2, 0)])
            window = g[_PEAK_LO:_PEAK_HI]
            k = int(np.argmax(window)) + _PEAK_LO
            seg_str.append(float(g[k]))
            seg_pos.append(k)
            seg_ratio.append(float(g[k] / (np.median(window) + 0.5)))
        ratio, strength, pos = float(np.median(seg_ratio)), float(np.median(seg_str)), float(np.median(seg_pos))
        straight = float(np.std(seg_pos))
        ratios.append(ratio); strengths.append(strength); poss.append(pos); straights.append(straight)
        has_edge = ratio >= 3.0 and strength >= 5.0
        geom["sides"].append({"side": ("top", "bottom", "left", "right")[side], "pos": pos, "ratio": ratio,
                              "strength": strength, "edge": has_edge, "shadow": 0.0})
        if has_edge:
            sides_with_edge.append(side)
            p = int(round(pos))
            prof_l = pl.mean(axis=1)
            lo_in, hi_in = max(p - 12, 0), max(p - 3, 1)
            lo_out, hi_out = min(p + 3, M - 2), min(p + 12, M - 1)
            inner = np.array([pl[lo_in:hi_in].mean(), pa[lo_in:hi_in].mean(), pb[lo_in:hi_in].mean()])
            outer = np.array([pl[lo_out:hi_out].mean(), pa[lo_out:hi_out].mean(), pb[lo_out:hi_out].mean()])
            des.append(float(np.linalg.norm(inner - outer)))
            band = prof_l[min(p + 1, M - 1):min(p + 6, M)]
            far = prof_l[min(p + 10, M - 1):min(p + 24, M)]
            shadows.append(float(far.mean() - band.mean()) if len(band) and len(far) else 0.0)
            geom["sides"][side]["shadow"] = shadows[-1]
        else:
            shadows.append(0.0)

    n_edge = len(sides_with_edge)
    f["edge_n_sides"] = float(n_edge)
    f["edge_ratio_min"], f["edge_ratio_mean"] = float(min(ratios)), float(np.mean(ratios))
    f["edge_strength_mean"] = float(np.mean(strengths))
    ep = [poss[i] for i in sides_with_edge]
    f["edge_pos_mean"] = float(np.mean(ep) / Q) if ep else 0.0
    f["edge_pos_std"] = float(np.std(ep) / Q) if len(ep) > 1 else 0.0
    f["edge_straight"] = float(np.mean([straights[i] for i in sides_with_edge])) if sides_with_edge else 0.0
    f["edge_de_mean"] = float(np.mean(des)) if des else 0.0
    for name, r in zip(("top", "bottom", "left", "right"), ratios):
        f[f"edge_ratio_{name}"] = float(r)
    f["shadow_max"] = float(max(shadows)) if sides_with_edge else 0.0
    f["shadow_mean"] = float(np.mean([shadows[i] for i in sides_with_edge])) if sides_with_edge else 0.0
    f["shadow_asym"] = float(abs((shadows[1] + shadows[3]) - (shadows[0] + shadows[2]))) if sides_with_edge else 0.0

    # ------------------------------------------------------------------ shape-agnostic ring profile
    ring_means = []
    for lo in range(0, 120, 8):
        m = ring(lo, lo + 8)
        ring_means.append(float(Ls[m].mean()))
    rm = np.asarray(ring_means)
    steps = np.abs(np.diff(rm))
    f["ring_step_max"] = float(steps[1:].max())
    f["ring_step_pos"] = float((np.argmax(steps[1:]) + 1) / len(steps))
    grad = cv2.magnitude(cv2.Sobel(Ls, cv2.CV_32F, 1, 0, ksize=3), cv2.Sobel(Ls, cv2.CV_32F, 0, 1, ksize=3))
    gr = np.asarray([float(grad[ring(lo, lo + 8)].mean()) for lo in range(0, 120, 8)])
    f["ring_grad_peak_ratio"] = float(gr[1:].max() / (np.median(gr[1:]) + 1e-3))

    # ------------------------------------------------------------------ colour / white point
    lab_in = np.array([L[_A_INNER].mean(), a[_A_INNER].mean(), b[_A_INNER].mean()])
    lab_out = np.array([L[_A_OUTER].mean(), a[_A_OUTER].mean(), b[_A_OUTER].mean()])
    f["de_inner_outer"] = float(np.linalg.norm(lab_in - lab_out))
    f["dL_inner_outer"] = float(lab_in[0] - lab_out[0])
    f["db_inner_outer"] = float(lab_in[2] - lab_out[2])
    sat = hsv[..., 1].astype(np.float32)
    f["dsat_inner_outer"] = float(sat[_A_INNER].mean() - sat[_A_OUTER].mean())

    # ------------------------------------------------------------------ texture / print character
    hp = L - cv2.GaussianBlur(L, (0, 0), 1.5)
    n_in, n_out = float(hp[_A_INNER].std()), float(hp[_A_OUTER].std())
    f["noise_ratio"] = float((n_in + 0.3) / (n_out + 0.3))
    f["noise_diff"] = float(abs(n_in - n_out))
    lbp = local_binary_pattern(gray, 8, 1, "uniform")
    h_in, _ = np.histogram(lbp[_A_INNER], bins=10, range=(0, 10), density=True)
    h_out, _ = np.histogram(lbp[_A_OUTER], bins=10, range=(0, 10), density=True)
    f["lbp_chi2"] = _chi2(h_in, h_out)
    lap = cv2.Laplacian(gray, cv2.CV_32F)
    f["lap_ratio"] = float((lap[_A_INNER].var() + 1.0) / (lap[_A_OUTER].var() + 1.0))

    # ------------------------------------------------------------------ specular highlights
    hl = (hsv[..., 2] > 225) & (hsv[..., 1] < 45)
    f["hl_inner"], f["hl_outer"] = float(hl[_A_INNER].mean()), float(hl[_A_OUTER].mean())
    f["hl_diff"] = abs(f["hl_inner"] - f["hl_outer"])

    # ------------------------------------------------------------------ QR core statistics
    core_vals = L[CORE]
    ink, white = float(np.percentile(core_vals, 8)), float(np.percentile(core_vals, 92))
    f["ink_white_range"] = white - ink
    f["core_blur"] = float(lap[CORE].var())
    f["core_noise"] = float(hp[CORE & (L > white - 10)].std()) if np.any(CORE & (L > white - 10)) else 0.0
    f["ctx_noise"] = n_out
    f["mean_L"] = float(L.mean())
    f["clip_hi"], f["clip_lo"] = float((gray >= 252).mean()), float((gray <= 3).mean())

    # ------------------------------------------------------------------ quiet zone & peeking original code
    f["qz_std_rel"] = float((L[_QZ].std() + 0.3) / (n_in + 0.3))
    module_px = _estimate_module_px(gray)
    f["module_px"] = module_px
    dark_thr = ink + 0.25 * max(white - ink, 1.0)
    dark = ((L < dark_thr) & _SURROUND).astype(np.uint8)
    f["qz_dark_frac"] = float(((L < dark_thr) & _QZ_WIDE).sum() / _QZ_WIDE.sum())
    f["surround_dark_frac"] = float(dark.sum() / _SURROUND.sum())
    dark = cv2.morphologyEx(dark, cv2.MORPH_OPEN, np.ones((2, 2), np.uint8))
    n, _, stats, _ = cv2.connectedComponentsWithStats(dark, connectivity=8)
    blobs, blob_area = 0, 0
    for i in range(1, n):
        x, y, w, h, area = stats[i]
        if 0.5 * module_px ** 2 <= area <= 10 * module_px ** 2 and 0.5 <= w / max(h, 1) <= 2.0 and area / (w * h) > 0.55:
            blobs += 1
            blob_area += area
            geom["blobs"].append((int(x), int(y), int(w), int(h)))
    f["n_module_blobs"] = float(blobs)
    f["blob_area_frac"] = float(blob_area / _SURROUND.sum())

    # ------------------------------------------------------------------ enclosing rectangles / double borders
    edges = cv2.Canny(cv2.GaussianBlur(gray, (0, 0), 1.2), 40, 110)
    edges[DIST < 3] = 0
    contours, _ = cv2.findContours(edges, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
    margins = []
    for cnt in contours:
        if cv2.arcLength(cnt, True) < 4.0 * Q * 1.1:
            continue
        (cx, cy), (w, h), _ang = cv2.minAreaRect(cnt)
        if not (1.12 * Q <= min(w, h) and max(w, h) <= 3.4 * Q and 0.7 <= w / max(h, 1) <= 1.43):
            continue
        if abs(cx - S / 2) > 0.45 * Q or abs(cy - S / 2) > 0.45 * Q:
            continue
        if cv2.contourArea(cnt) / max(w * h, 1.0) < 0.55:
            continue
        margins.append((min(w, h) / Q - 1.0) / 2.0)
        geom["rects"].append(cv2.boxPoints(((cx, cy), (w, h), _ang)).astype(int).tolist())
    f["n_enclosing_rects"] = float(len(margins))
    f["enclosing_margin"] = float(min(margins)) if margins else 0.0
    srt = sorted(margins)
    f["double_border"] = 1.0 if (len(srt) >= 2 and srt[-1] - srt[0] > 0.08) else 0.0

    f["qr_px"], f["skew"], f["coverage"] = float(qr_px), float(skew), float(coverage)
    return f, geom


def vectorize(f: Dict[str, float]) -> np.ndarray:
    return np.asarray([f[k] for k in FEATURE_ORDER], dtype=np.float32)
