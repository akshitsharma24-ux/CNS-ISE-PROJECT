"""
Print quality, texture, and halftone/moire analysis (F17).
Analyzes DPI sharpness ratio, high-pass noise residuals, FFT moire peaks,
and texture disparity (LBP / GLCM) between sticker and host surface.
"""
import cv2
import numpy as np
from skimage.feature import local_binary_pattern, graycomatrix, graycoprops
from typing import Dict, Any, Tuple

def extract_print_and_texture_features(
    rectified_bgr: np.ndarray,
    masks: Dict[str, np.ndarray]
) -> Tuple[Dict[str, float], list]:
    """
    Computes print-quality differentials and texture mismatch.
    """
    gray = cv2.cvtColor(rectified_bgr, cv2.COLOR_BGR2GRAY)
    qz_mask = masks["quiet_zone"]
    surface_mask = masks["surface"]
    qr_mask = masks["qr_core"]

    # Dilate QR core to safely isolate quiet zone paper from black finder modules
    qr_dilated = cv2.dilate(qr_mask.astype(np.uint8), cv2.getStructuringElement(cv2.MORPH_RECT, (9, 9)))
    safe_qz = qz_mask & (qr_dilated == 0)

    # 1. Sharpness Ratio via Laplacian Variance
    lap = cv2.Laplacian(gray, cv2.CV_64F)
    lap_qz_var = float(np.var(lap[safe_qz])) if np.any(safe_qz) else 1.0
    lap_surf_var = float(np.var(lap[surface_mask])) if np.any(surface_mask) else 1.0
    if lap_qz_var < 15.0 and lap_surf_var < 15.0:
        sharpness_ratio = 1.0
    else:
        sharpness_ratio = float(lap_qz_var / max(lap_surf_var, 10.0))

    # 2. High-pass noise level residual
    # Blurring removes high-frequency halftone; difference yields printer noise pattern
    blurred = cv2.GaussianBlur(gray, (5, 5), 1.0)
    high_pass = cv2.absdiff(gray, blurred)
    noise_qz = float(np.mean(high_pass[safe_qz])) if np.any(safe_qz) else 0.0
    noise_surf = float(np.mean(high_pass[surface_mask])) if np.any(surface_mask) else 0.0
    noise_disparity = float(abs(noise_qz - noise_surf))


    # 3. FFT Radial Spectrum Peaks for Moire / Halftone Screen
    # 2D FFT on quiet zone and surface
    dft = np.fft.fft2(gray.astype(np.float32))
    dft_shift = np.fft.fftshift(dft)
    magnitude_spectrum = 20 * np.log(np.abs(dft_shift) + 1.0)
    # Moire / halftone screen frequency creates energy peaks away from DC center
    fft_high_freq_energy = float(np.mean(magnitude_spectrum[100:200, 100:200]))

    # 4. Local Binary Pattern (LBP) Texture Mismatch
    # Radius 1, 8 points
    lbp = local_binary_pattern(gray, P=8, R=1, method="uniform")
    # Histograms for quiet zone vs surface
    hist_qz, _ = np.histogram(lbp[qz_mask], bins=10, range=(0, 10), density=True)
    hist_surf, _ = np.histogram(lbp[surface_mask], bins=10, range=(0, 10), density=True)
    # Chi-square distance
    lbp_chi_sq = float(0.5 * np.sum(((hist_qz - hist_surf) ** 2) / (hist_qz + hist_surf + 1e-6)))

    # 5. Black-level and Paper-White measurements
    qr_core_pixels = gray[qr_mask]
    paper_white_val = float(np.percentile(gray[qz_mask], 95)) if np.any(qz_mask) else 255.0
    ink_black_val = float(np.percentile(qr_core_pixels, 5)) if len(qr_core_pixels) > 0 else 0.0
    contrast_dynamic_range = float(paper_white_val - ink_black_val)

    features = {
        "sharpness_ratio": round(sharpness_ratio, 3),
        "noise_disparity": round(noise_disparity, 2),
        "fft_halftone_energy": round(fft_high_freq_energy, 2),
        "lbp_texture_chi_sq": round(lbp_chi_sq, 4),
        "contrast_dynamic_range": round(contrast_dynamic_range, 1)
    }

    signals = []
    if sharpness_ratio > 3.0 or sharpness_ratio < 0.30:
        signals.append({
            "name": "print_sharpness_disparity",
            "value": sharpness_ratio,
            "text": f"Sharpness disparity ({sharpness_ratio:.1f}x) indicates two different print resolutions."
        })
    if lbp_chi_sq > 0.18:
        signals.append({
            "name": "texture_material_mismatch",
            "value": lbp_chi_sq,
            "text": "Texture analysis indicates different paper/material substrate."
        })

    return features, signals
