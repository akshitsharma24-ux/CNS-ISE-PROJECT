"""
Illumination, shadow, and specular reflection features (F16).
Detects 3D sticker elevation via micro-shadows, surface-to-sticker luminance plane
discrepancies, Delta-E colour mismatches, and specular gloss differences.
"""
import cv2
import numpy as np
from typing import Dict, Any, Tuple

def extract_light_features(
    rectified_bgr: np.ndarray,
    masks: Dict[str, np.ndarray]
) -> Tuple[Dict[str, float], list]:
    """
    Extracts photometric and colorimetric features in LAB and HSV spaces.
    """
    lab = cv2.cvtColor(rectified_bgr, cv2.COLOR_BGR2LAB)
    hsv = cv2.cvtColor(rectified_bgr, cv2.COLOR_BGR2HSV)

    l_channel = lab[:, :, 0].astype(np.float64)
    qz_mask = masks["quiet_zone"]
    surface_mask = masks["surface"]
    qr_mask = masks["qr_core"]
    # Dilate QR core to safely isolate quiet zone paper from black finder modules
    qr_dilated = cv2.dilate(qr_mask.astype(np.uint8), cv2.getStructuringElement(cv2.MORPH_RECT, (9, 9)))
    safe_qz = qz_mask & (qr_dilated == 0)


    # 1. Delta-E Colour difference between quiet-zone paper and surface
    qz_lab = lab[safe_qz].astype(np.float64)
    surf_lab = lab[surface_mask].astype(np.float64)

    if len(qz_lab) > 0 and len(surf_lab) > 0:
        mean_qz_lab = np.mean(qz_lab, axis=0)
        mean_surf_lab = np.mean(surf_lab, axis=0)
        # CIE76 Delta-E formula
        delta_e = float(np.sqrt(np.sum((mean_qz_lab - mean_surf_lab) ** 2)))
    else:
        delta_e = 0.0


    # 2. Luminance Plane Fitting on Surface & Residual in QR region
    # Fit plane L(x, y) = a*x + b*y + c using surface pixels
    y_coords, x_coords = np.where(surface_mask)
    if len(x_coords) > 50:
        A = np.column_stack([x_coords, y_coords, np.ones_like(x_coords)])
        z = l_channel[surface_mask]
        plane_params, _, _, _ = np.linalg.lstsq(A, z, rcond=None)

        # Expected surface luminance across the QR area
        y_qr, x_qr = np.where(qz_mask)
        if len(x_qr) > 0:
            expected_l = plane_params[0] * x_qr + plane_params[1] * y_qr + plane_params[2]
            actual_l = l_channel[qz_mask]
            plane_residual_mean = float(np.mean(np.abs(actual_l - expected_l)))
        else:
            plane_residual_mean = 0.0
    else:
        plane_residual_mean = 0.0

    # 3. Micro-shadow detection around sticker boundary
    # A sticker creates a thin dark boundary profile on one or two edges due to height
    # Sample intensity profile strictly outside the QR core
    edge_kernel = np.array([[-1, -1, -1], [2, 2, 2], [-1, -1, -1]], dtype=np.float32)
    shadow_filtered = cv2.filter2D(l_channel, -1, edge_kernel)
    qr_dilated = cv2.dilate(qr_mask.astype(np.uint8), cv2.getStructuringElement(cv2.MORPH_RECT, (11, 11)))
    shadow_zone = (qz_mask | surface_mask) & (qr_dilated == 0)
    micro_shadow_score = float(np.max(shadow_filtered[shadow_zone])) if np.any(shadow_zone) else 0.0


    # 4. Specular Reflection / Gloss differential (HSV)
    # Glossy paper has high V and low S under light
    s_channel = hsv[:, :, 1]
    v_channel = hsv[:, :, 2]
    glossy_pixels_qz = np.sum((v_channel[qz_mask] > 200) & (s_channel[qz_mask] < 35))
    glossy_ratio_qz = float(glossy_pixels_qz / max(len(qz_mask[qz_mask]), 1))

    glossy_pixels_surf = np.sum((v_channel[surface_mask] > 200) & (s_channel[surface_mask] < 35))
    glossy_ratio_surf = float(glossy_pixels_surf / max(len(surface_mask[surface_mask]), 1))

    gloss_differential = float(abs(glossy_ratio_qz - glossy_ratio_surf))

    features = {
        "delta_e_color_mismatch": round(delta_e, 2),
        "luminance_plane_residual": round(plane_residual_mean, 2),
        "micro_shadow_score": round(micro_shadow_score, 2),
        "gloss_differential": round(gloss_differential, 4)
    }

    signals = []
    if delta_e > 18.0:
        signals.append({
            "name": "paper_color_mismatch",
            "value": delta_e,
            "text": f"Paper substrate color mismatch detected (Delta-E = {delta_e:.1f})."
        })
    if micro_shadow_score > 85.0:
        signals.append({
            "name": "micro_shadow_edge",
            "value": micro_shadow_score,
            "text": "Sticker elevation micro-shadow detected at perimeter."
        })
    if gloss_differential > 0.12:
        signals.append({
            "name": "gloss_mismatch",
            "value": gloss_differential,
            "text": "Gloss/specular reflectivity mismatch between QR and host surface."
        })

    return features, signals
