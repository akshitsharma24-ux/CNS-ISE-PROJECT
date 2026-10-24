"""
Camera degradations used to stress-test the tamper model (robustness evaluation).

Each perturbation takes a BGR photo and a severity in {1, 2, 3} (mild, moderate, severe) and returns a degraded
copy. They model what actually goes wrong when someone photographs a code in the street: shaky hands (motion
blur), poor focus, dim light, cheap sensors (noise), heavy messenger-app compression (JPEG), a tilted phone and
a lamp reflecting off the sign (glare). All are deterministic for a given `seed` so evaluation runs are reproducible.
"""
from __future__ import annotations

from typing import Callable, Dict

import cv2
import numpy as np

SEVERITIES = (1, 2, 3)


def gaussian_blur(img: np.ndarray, sev: int, seed: int = 0) -> np.ndarray:
    return cv2.GaussianBlur(img, (0, 0), (0.8, 1.6, 2.6)[sev - 1])


def motion_blur(img: np.ndarray, sev: int, seed: int = 0) -> np.ndarray:
    k = (5, 11, 19)[sev - 1]
    kernel = np.zeros((k, k), np.float32)
    kernel[k // 2, :] = 1.0 / k
    return cv2.filter2D(img, -1, kernel)


def sensor_noise(img: np.ndarray, sev: int, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    noisy = img.astype(np.float32) + rng.normal(0.0, (4.0, 9.0, 16.0)[sev - 1], img.shape)
    return np.clip(noisy, 0, 255).astype(np.uint8)


def jpeg(img: np.ndarray, sev: int, seed: int = 0) -> np.ndarray:
    ok, buf = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, (60, 35, 15)[sev - 1]])
    return cv2.imdecode(buf, cv2.IMREAD_COLOR)


def low_light(img: np.ndarray, sev: int, seed: int = 0) -> np.ndarray:
    return np.clip(img.astype(np.float32) * (0.75, 0.55, 0.38)[sev - 1], 0, 255).astype(np.uint8)


def low_contrast(img: np.ndarray, sev: int, seed: int = 0) -> np.ndarray:
    a = (0.8, 0.6, 0.45)[sev - 1]
    return np.clip((img.astype(np.float32) - 128.0) * a + 128.0, 0, 255).astype(np.uint8)


def downscale(img: np.ndarray, sev: int, seed: int = 0) -> np.ndarray:
    f = (0.7, 0.5, 0.35)[sev - 1]
    small = cv2.resize(img, None, fx=f, fy=f, interpolation=cv2.INTER_AREA)
    return cv2.resize(small, (img.shape[1], img.shape[0]), interpolation=cv2.INTER_LINEAR)


def tilt(img: np.ndarray, sev: int, seed: int = 0) -> np.ndarray:
    """In-plane rotation about the image centre (white-ish border fill from the nearest pixels)."""
    h, w = img.shape[:2]
    m = cv2.getRotationMatrix2D((w / 2, h / 2), (6.0, 15.0, 28.0)[sev - 1] * (1 if seed % 2 else -1), 1.0)
    return cv2.warpAffine(img, m, (w, h), flags=cv2.INTER_LINEAR, borderMode=cv2.BORDER_REPLICATE)


def glare_spot(img: np.ndarray, sev: int, seed: int = 0) -> np.ndarray:
    """A soft specular hot-spot at a random place on the photo."""
    h, w = img.shape[:2]
    rng = np.random.default_rng(seed)
    cx, cy = rng.uniform(0.25, 0.75) * w, rng.uniform(0.25, 0.75) * h
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    r = (0.10, 0.16, 0.24)[sev - 1] * min(h, w)
    g = np.exp(-(((xx - cx) ** 2 + (yy - cy) ** 2) / (2 * r * r)))[..., None]
    return np.clip(img.astype(np.float32) * (1 - 0.85 * g) + 255.0 * 0.85 * g, 0, 255).astype(np.uint8)


PERTURBATIONS: Dict[str, Callable[[np.ndarray, int, int], np.ndarray]] = {
    "gaussian_blur": gaussian_blur, "motion_blur": motion_blur, "sensor_noise": sensor_noise, "jpeg": jpeg,
    "low_light": low_light, "low_contrast": low_contrast, "downscale": downscale, "tilt": tilt, "glare_spot": glare_spot,
}


def apply(name: str, img: np.ndarray, severity: int, seed: int = 0) -> np.ndarray:
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    return PERTURBATIONS[name](img, severity, seed)
