"""
Feature-based tamper classifier (F19).
Fuses edge, lighting, color, print-quality, and texture features
into a calibrated tamper probability score (tamper_risk).
"""
import numpy as np
from typing import Dict, Any, List, Tuple

def compute_tamper_score(
    edge_feats: Dict[str, float],
    light_feats: Dict[str, float],
    print_feats: Dict[str, float]
) -> Tuple[float, List[Dict[str, Any]]]:
    """
    Computes calibrated tamper risk from extracted CV feature groups.
    Returns:
      (tamper_risk, contributing_signals)
    """
    signals = []
    points = 0.0

    # 1. Edge and Boundary Evidence
    discontinuity = edge_feats.get("edge_discontinuity_ratio", 1.0)
    cutlines = edge_feats.get("parallel_cutline_count", 0.0)
    concentric = edge_feats.get("concentric_rect_count", 0.0)
    peeking = edge_feats.get("peeking_fragment_indicator", 0.0)

    if discontinuity > 2.2:
        points += 0.35
        signals.append({
            "name": "sticker_edge_detected",
            "value": discontinuity,
            "text": "Distinct physical sticker boundary detected around QR code."
        })
    elif discontinuity > 1.6:
        points += 0.20

    if cutlines >= 2.0:
        points += 0.25
        signals.append({
            "name": "cutlines_detected",
            "value": cutlines,
            "text": "Straight sticker cutlines detected parallel to QR edges."
        })

    if concentric >= 2.0 or peeking > 0.0:
        points += 0.30
        signals.append({
            "name": "double_layer_border",
            "value": concentric,
            "text": "Double border detected: code appears overlaid on pre-existing print."
        })

    # 2. Lighting and Shadow Evidence
    delta_e = light_feats.get("delta_e_color_mismatch", 0.0)
    shadow = light_feats.get("micro_shadow_score", 0.0)
    gloss = light_feats.get("gloss_differential", 0.0)

    if delta_e > 22.0:
        points += 0.25
        signals.append({
            "name": "paper_color_discrepancy",
            "value": delta_e,
            "text": f"Substrate color mismatch (Delta-E = {delta_e:.1f}) between QR paper and surface."
        })
    elif delta_e > 14.0:
        points += 0.12

    if shadow > 90.0:
        points += 0.20
        signals.append({
            "name": "sticker_elevation_shadow",
            "value": shadow,
            "text": "Micro-shadow cast by physical sticker elevation detected."
        })

    if gloss > 0.15:
        points += 0.15
        signals.append({
            "name": "gloss_mismatch",
            "value": gloss,
            "text": "Surface gloss disparity (reflective sticker on matte backing)."
        })

    # 3. Print Quality & Texture Evidence
    sharpness_ratio = print_feats.get("sharpness_ratio", 1.0)
    lbp_dist = print_feats.get("lbp_texture_chi_sq", 0.0)

    if sharpness_ratio > 3.2 or sharpness_ratio < 0.25:
        points += 0.20
        signals.append({
            "name": "print_dpi_mismatch",
            "value": sharpness_ratio,
            "text": "Severe print DPI sharpness mismatch between code and mounting base."
        })

    if lbp_dist > 0.22:
        points += 0.18
        signals.append({
            "name": "material_texture_mismatch",
            "value": lbp_dist,
            "text": "Material surface texture mismatch detected via LBP analysis."
        })

    # Non-linear probability scaling
    prob = 1.0 / (1.0 + np.exp(-3.5 * (points - 0.45)))
    # Bound within [0.02, 0.98]
    tamper_risk = float(np.clip(prob, 0.02, 0.98))

    return round(tamper_risk, 4), signals
