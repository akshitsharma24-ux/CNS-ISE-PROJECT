"""
Procedural "photo of a QR code on a surface" simulator (F22).

Why this exists: the plan's real dataset (~800 phone photos) has to be collected by hand, and the
visual-tamper model needs training data from day one. This module renders physically-motivated
scenes with ground truth that follows the physics, then degrades them like a phone camera:

  surfaces   matte paper, glossy poster, brushed metal, wood, glass, plastic, cardboard, painted wall
  benign     printed label on the surface, framed card, laminated print, GENUINE STICKER (hard negative)
  tampered   a different code stuck over the original: exact fit, smaller, larger, offset/rotated, wrinkled
  physics    sticker shadow + die-cut edge, gloss/specular mismatch, paper white-point mismatch,
             original code peeking out, illumination gradient, vignetting, white balance
  camera     perspective tilt, defocus / motion blur, sensor noise, resolution loss, JPEG

A scene is labelled "tampered" iff a different code really sits under the sticker. A *perfect* cover
is therefore indistinguishable from a genuine sticker - that is a real limit, and it is exactly why
the model is evaluated per tamper style and why the other two layers exist.

IMPORTANT: results on simulated data measure the algorithm, not the real world. Real photos
collected per scripts/collect_cv_dataset.md can be mixed in with `python -m qrshield.cv_layer.train --real`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

import cv2
import numpy as np
import qrcode

SURFACES = ("matte_paper", "glossy_poster", "metal", "wood", "glass", "plastic", "cardboard", "painted_wall")
BENIGN_STYLES = ("printed_flat", "printed_direct", "framed_card", "laminated_print", "genuine_sticker")
BENIGN_WEIGHTS = (0.22, 0.22, 0.12, 0.17, 0.27)
TAMPER_STYLES = ("exact_fit", "smaller", "larger", "offset_rotated", "wrinkled")
TAMPER_WEIGHTS = (0.22, 0.22, 0.18, 0.22, 0.16)
STICKER_MATERIALS = ("matte_paper", "cream_paper", "glossy_vinyl")

_TEXTURES: Dict[Tuple[str, int], np.ndarray] = {}
WORLD = 1500          # world canvas (px)
QW = 340              # QR width in world px
GLOSSY_SURFACES = {"glossy_poster": 0.35, "glass": 0.85, "plastic": 0.45, "metal": 0.22}


@dataclass
class Scene:
    image: np.ndarray                      # BGR uint8 "photo"
    label: int                             # 1 = tampered, 0 = genuine
    meta: Dict[str, Any] = field(default_factory=dict)
    corners: Optional[np.ndarray] = None   # ground-truth corners of the *visible* (top) code in the photo


# ----------------------------------------------------------------------------- helpers
def _stable(*parts: Any) -> int:
    """Deterministic seed from arbitrary parts (Python's str hash is randomised per process)."""
    import zlib
    return zlib.crc32("|".join(map(str, parts)).encode("utf-8"))


def _fbm(rng: np.random.Generator, h: int, w: int, scales=(6, 12, 24, 48), decay=0.55) -> np.ndarray:
    out = np.zeros((h, w), np.float32)
    amp = 1.0
    for g in scales:
        small = rng.standard_normal((g, max(2, int(g * w / h)))).astype(np.float32)
        out += amp * cv2.resize(small, (w, h), interpolation=cv2.INTER_CUBIC)
        amp *= decay
    return out / (np.abs(out).max() + 1e-6)


def _blur(img: np.ndarray, sigma: float) -> np.ndarray:
    return cv2.GaussianBlur(img, (0, 0), sigma) if sigma > 0.05 else img


def _qr_modules(rng: np.random.Generator, payload: Optional[str] = None) -> np.ndarray:
    data = payload or ("https://" + "".join(rng.choice(list("abcdefghijklmnopqrstuvwxyz0123456789"), int(rng.integers(8, 22))))
                       + ".example/" + "".join(rng.choice(list("abcdef0123456789"), int(rng.integers(3, 10)))))
    q = qrcode.QRCode(border=0, error_correction=qrcode.constants.ERROR_CORRECT_M)
    q.add_data(data)
    q.make(fit=True)
    return np.array(q.get_matrix(), dtype=np.uint8)


def _render_code(rng, width: int, ink: float, paper: np.ndarray, qz: float, soften: float,
                 payload: Optional[str] = None) -> Tuple[np.ndarray, np.ndarray]:
    """Return (RGB patch incl. quiet zone, opaque mask) for a QR printed `width` px wide."""
    mods = _qr_modules(rng, payload)
    total = int(round(width * (1 + 2 * qz)))
    pad = int(round(width * qz))
    code = cv2.resize((1.0 - mods).astype(np.float32), (width, width), interpolation=cv2.INTER_NEAREST)
    code = _blur(code, soften)
    patch = np.empty((total, total, 3), np.float32)
    patch[:] = paper
    inner = ink + (1.0 - ink) * code                       # 0 -> ink, 1 -> paper
    patch[pad:pad + width, pad:pad + width] = inner[..., None] * paper.reshape(1, 1, 3)
    return patch, np.ones((total, total), np.float32)


# ----------------------------------------------------------------------------- surfaces
def surface_texture(kind: str, rng: np.random.Generator, size: int = WORLD) -> np.ndarray:
    h = w = size
    if kind == "matte_paper":
        base = rng.uniform(0.80, 0.95)
        tint = rng.uniform(-0.03, 0.03, 3)
        img = base + 0.025 * _fbm(rng, h, w)[..., None] + tint
        img += _blur(rng.standard_normal((h, w)).astype(np.float32), 0.7)[..., None] * 0.016
    elif kind == "glossy_poster":
        img = np.zeros((h, w, 3), np.float32)
        for _ in range(int(rng.integers(3, 6))):                          # big colour regions
            c = rng.uniform(0.1, 0.95, 3)
            f = _fbm(rng, h, w, scales=(2, 3, 5)) * 0.5 + 0.5
            img += f[..., None] * c
        img = img / (img.max() + 1e-6) * rng.uniform(0.65, 0.95)
        for _ in range(int(rng.integers(6, 16))):                         # text-like bars
            y, x = int(rng.integers(0, h - 30)), int(rng.integers(0, w - 300))
            img[y:y + int(rng.integers(5, 14)), x:x + int(rng.integers(120, 420))] *= rng.uniform(0.05, 0.4)
        img += rng.standard_normal((h, w, 1)).astype(np.float32) * 0.006
    elif kind == "metal":
        base = rng.uniform(0.35, 0.68)
        streak = _blur(rng.standard_normal((h, w)).astype(np.float32), 0.8)
        streak = cv2.blur(streak, (61, 1)) * 5.0
        img = base + 0.06 * streak[..., None] + 0.035 * _fbm(rng, h, w)[..., None]
        img = img * np.array([0.97, 1.0, 1.04], np.float32) + rng.uniform(-0.02, 0.02, 3)
    elif kind == "wood":
        c = np.array([0.46, 0.31, 0.18], np.float32) * rng.uniform(0.7, 1.25) + rng.uniform(-0.04, 0.04, 3)
        xx = np.arange(w, dtype=np.float32)[None, :]
        warp = _fbm(rng, h, w, scales=(3, 6, 12)) * 14.0
        grain = np.sin((xx * 0.07 + warp) * rng.uniform(0.7, 1.4))
        img = c[None, None, :] * (1.0 + 0.16 * grain[..., None] + 0.06 * _fbm(rng, h, w)[..., None])
        img += rng.standard_normal((h, w, 1)).astype(np.float32) * 0.008
    elif kind == "glass":
        img = np.full((h, w, 3), rng.uniform(0.07, 0.22), np.float32) + np.array([0.0, 0.01, 0.03], np.float32)
        for _ in range(int(rng.integers(3, 8))):                          # backdrop clutter seen through glass
            cx, cy, r = int(rng.integers(0, w)), int(rng.integers(0, h)), int(rng.integers(80, 340))
            blob = np.zeros((h, w), np.float32)
            cv2.circle(blob, (cx, cy), r, 1.0, -1)
            img += _blur(blob, 60)[..., None] * rng.uniform(0.02, 0.18, 3)
        img += rng.standard_normal((h, w, 1)).astype(np.float32) * 0.005
    elif kind == "plastic":
        hsv = np.uint8([[[rng.integers(0, 180), rng.integers(60, 210), rng.integers(110, 235)]]])
        c = cv2.cvtColor(hsv, cv2.COLOR_HSV2RGB)[0, 0].astype(np.float32) / 255.0
        img = c[None, None, :] * (1.0 + 0.04 * _fbm(rng, h, w)[..., None]) + rng.standard_normal((h, w, 1)).astype(np.float32) * 0.008
    elif kind == "cardboard":
        c = np.array([0.66, 0.52, 0.35], np.float32) * rng.uniform(0.85, 1.1)
        fib = cv2.blur(rng.standard_normal((h, w)).astype(np.float32), (1, 9)) + cv2.blur(rng.standard_normal((h, w)).astype(np.float32), (9, 1))
        img = c[None, None, :] * (1.0 + 0.09 * fib[..., None] + 0.05 * _fbm(rng, h, w)[..., None])
    else:  # painted_wall
        hsv = np.uint8([[[rng.integers(0, 180), rng.integers(10, 80), rng.integers(170, 245)]]])
        c = cv2.cvtColor(hsv, cv2.COLOR_HSV2RGB)[0, 0].astype(np.float32) / 255.0
        img = c[None, None, :] * (1.0 + 0.03 * _fbm(rng, h, w)[..., None]) + rng.standard_normal((h, w, 1)).astype(np.float32) * 0.012
    return np.clip(img, 0, 1).astype(np.float32)


# ----------------------------------------------------------------------------- compositing
def _paste(canvas: np.ndarray, patch: np.ndarray, mask: np.ndarray, cx: float, cy: float, angle: float = 0.0) -> np.ndarray:
    """Paste `patch` centred at (cx, cy) rotated by `angle` degrees; returns the world-space mask."""
    ph, pw = patch.shape[:2]
    m = cv2.getRotationMatrix2D((pw / 2, ph / 2), angle, 1.0)
    m[0, 2] += cx - pw / 2
    m[1, 2] += cy - ph / 2
    big = cv2.warpAffine(patch, m, canvas.shape[1::-1], flags=cv2.INTER_LINEAR, borderMode=cv2.BORDER_CONSTANT)
    big_mask = cv2.warpAffine(mask, m, canvas.shape[1::-1], flags=cv2.INTER_LINEAR, borderMode=cv2.BORDER_CONSTANT)
    big_mask = np.clip(big_mask, 0, 1)
    canvas[:] = canvas * (1 - big_mask[..., None]) + big * big_mask[..., None]
    return big_mask


def _drop_shadow(canvas: np.ndarray, mask: np.ndarray, light: Tuple[float, float], strength: float, blur: float) -> None:
    dx, dy = light
    m = cv2.warpAffine(mask, np.float32([[1, 0, dx], [0, 1, dy]]), mask.shape[::-1])
    shadow = _blur(m, blur) * (1 - mask)
    canvas *= (1 - strength * shadow[..., None])


def _edge_lines(canvas: np.ndarray, mask: np.ndarray, rng: np.random.Generator) -> None:
    """Die-cut edge: thin darker rim plus a faint bright lift on one side."""
    eroded = cv2.erode(mask, np.ones((3, 3), np.uint8))
    rim = np.clip(mask - eroded, 0, 1)
    canvas *= (1 - rim[..., None] * rng.uniform(0.05, 0.22))


def _paper_color(material: str, rng: np.random.Generator) -> np.ndarray:
    if material == "cream_paper":
        return np.array([0.97, 0.95, 0.86], np.float32) * rng.uniform(0.93, 1.0)
    if material == "glossy_vinyl":
        return np.array([0.95, 0.97, 1.0], np.float32) * rng.uniform(0.95, 1.0)
    return np.array([0.97, 0.97, 0.96], np.float32) * rng.uniform(0.90, 1.0)


# ----------------------------------------------------------------------------- the scene
def render_scene(seed: int, label: Optional[int] = None, surface: Optional[str] = None, style: Optional[str] = None,
                 session: int = 0, size: Tuple[int, int] = (1280, 960), payload: Optional[str] = None, view: int = 0,
                 under_payload: Optional[str] = None) -> Scene:
    """Render one photographed scene. The scene (what is stuck where) depends only on `seed`; the
    camera pose, highlight position and exposure also depend on `view`, so view=0/1 are two photos of
    the SAME physical scene (used to evaluate the second-photo check).

    `payload` is what the visible (top) code encodes; `under_payload` is what the original code under a
    tampering sticker encodes. Both default to random URLs."""
    rng = np.random.default_rng(seed)
    srng = np.random.default_rng(_stable(surface or "any", session))               # per-session surface/lighting/camera
    surface = surface or str(rng.choice(SURFACES))
    label = int(rng.random() < 0.5) if label is None else label
    if style is None:
        style = str(rng.choice(TAMPER_STYLES if label else BENIGN_STYLES, p=TAMPER_WEIGHTS if label else BENIGN_WEIGHTS))

    tex_seed = int(srng.integers(1 << 30))
    key = (surface, tex_seed)
    if key not in _TEXTURES:                       # one surface instance per session; reuse across its photos
        if len(_TEXTURES) >= 3:
            _TEXTURES.pop(next(iter(_TEXTURES)))
        _TEXTURES[key] = surface_texture(surface, np.random.default_rng(tex_seed))
    world = _TEXTURES[key].copy()
    gloss = GLOSSY_SURFACES.get(surface, 0.0)
    gloss_map = np.full((WORLD, WORLD), gloss, np.float32)
    # session lighting: direction of the key light (shadow side), colour temperature, exposure
    ang = srng.uniform(0, 2 * np.pi)
    light = (float(np.cos(ang)) * rng.uniform(1.5, 4.5), float(np.sin(ang)) * rng.uniform(1.5, 4.5))
    wb = np.array([srng.uniform(0.88, 1.12), 1.0, srng.uniform(0.88, 1.12)], np.float32)
    exposure = float(srng.uniform(0.62, 1.30))

    cx = cy = WORLD / 2
    ink = float(rng.uniform(0.03, 0.14))
    qz_label = float(rng.uniform(0.10, 0.28))
    meta: Dict[str, Any] = {"surface": surface, "style": style, "label": label, "session": f"{surface}-{session}"}

    def put_label(canvas, offset=(0.0, 0.0), angle=0.0, glossy=False, frame=False, card=False, code=None):
        paper = np.array([0.95, 0.95, 0.94], np.float32) * rng.uniform(0.94, 1.0)
        patch, mask = _render_code(rng, QW, ink, paper, qz_label, soften=rng.uniform(0.3, 0.9), payload=code)
        if frame:
            t = max(3, int(rng.uniform(0.012, 0.03) * patch.shape[0]))
            patch[:t], patch[-t:], patch[:, :t], patch[:, -t:] = 0.08, 0.08, 0.08, 0.08
        m = _paste(canvas, patch, mask, cx + offset[0], cy + offset[1], angle)
        if card or glossy:
            _drop_shadow(canvas, m, light, rng.uniform(0.12, 0.3), rng.uniform(1.5, 4.0))
        if glossy:
            gloss_map[m > 0.5] = rng.uniform(0.35, 0.6)
        return m

    def can_print_direct() -> bool:
        patch = world[int(cy) - 250:int(cy) + 250, int(cx) - 250:int(cx) + 250]
        return float(patch.mean()) > 0.55                  # ink needs a light surface to be readable

    def put_direct(canvas, code=None):
        """Ink printed straight onto the surface: it multiplies the surface, the quiet zone IS the surface."""
        mods = _qr_modules(rng, code)
        img = cv2.resize((1.0 - mods).astype(np.float32), (QW, QW), interpolation=cv2.INTER_NEAREST)
        img = _blur(img, rng.uniform(0.3, 0.9))
        x0, y0 = int(cx - QW / 2), int(cy - QW / 2)
        canvas[y0:y0 + QW, x0:x0 + QW] *= (ink + (1.0 - ink) * img)[..., None]

    def put_sticker(canvas, qr_scale=1.0, qz=0.06, offset=(0.0, 0.0), angle=0.0, material="matte_paper", wrinkle=False):
        paper = _paper_color(material, rng)
        patch, mask = _render_code(rng, int(QW * qr_scale), ink * rng.uniform(0.8, 1.6), paper, qz, soften=rng.uniform(0.3, 0.9),
                                   payload=payload)
        if wrinkle:
            ph = patch.shape[0]
            patch *= (1.0 + 0.045 * _fbm(rng, ph, ph, scales=(3, 5, 9))[..., None])
        _drop_shadow(world, _mask_of(patch, cx + offset[0], cy + offset[1], angle, mask), light, rng.uniform(0.18, 0.5), rng.uniform(1.2, 3.5))
        m = _paste(canvas, patch, mask, cx + offset[0], cy + offset[1], angle)
        _edge_lines(canvas, m, rng)
        if material == "glossy_vinyl":
            gloss_map[m > 0.5] = rng.uniform(0.5, 0.9)
        elif gloss > 0.3:
            gloss_map[m > 0.5] = 0.04                      # matte paper sticker on a glossy surface
        meta["sticker_material"] = material
        # corners of the visible code (quiet zone excluded) in world coordinates
        half = QW * qr_scale / 2
        r = np.deg2rad(angle)
        rot = np.array([[np.cos(r), np.sin(r)], [-np.sin(r), np.cos(r)]], np.float32)
        pts = np.array([[-half, -half], [half, -half], [half, half], [-half, half]], np.float32) @ rot.T
        return pts + np.array([cx + offset[0], cy + offset[1]], np.float32)

    def _mask_of(patch, px, py, angle, mask):
        return _paste(np.zeros((WORLD, WORLD, 3), np.float32), patch, mask, px, py, angle)

    corners_world: np.ndarray
    if label == 0:
        if style == "printed_direct" and not can_print_direct():
            style = meta["style"] = "printed_flat"          # too dark to print directly: use a printed label
        if style == "printed_direct":
            put_direct(world, code=payload)
            corners_world = _label_corners(0.0, 0.0, 0.0)
        elif style == "printed_flat":
            put_label(world, code=payload)
            corners_world = _label_corners(0.0, 0.0, 0.0)
        elif style == "framed_card":
            put_label(world, frame=True, card=True, code=payload)
            corners_world = _label_corners(0.0, 0.0, 0.0)
        elif style == "laminated_print":
            put_label(world, glossy=True, code=payload)
            corners_world = _label_corners(0.0, 0.0, 0.0)
        else:  # genuine_sticker: a sticker on a clean surface, no code underneath
            material = str(rng.choice(STICKER_MATERIALS))
            corners_world = put_sticker(world, qr_scale=1.0, qz=float(rng.uniform(0.05, 0.2)), material=material,
                                        angle=float(rng.uniform(-3, 3)))
    else:
        if can_print_direct() and rng.random() < 0.45:
            put_direct(world, code=under_payload)          # original printed straight onto a light surface
        else:
            put_label(world, glossy=bool(rng.random() < 0.3), frame=bool(rng.random() < 0.3), card=bool(rng.random() < 0.4),
                      code=under_payload)
        material = str(rng.choice(STICKER_MATERIALS, p=[0.45, 0.25, 0.30]))
        if style == "exact_fit":
            corners_world = put_sticker(world, 1.0, qz=qz_label, material=material,
                                        offset=tuple(rng.uniform(-0.012, 0.012, 2) * QW), angle=float(rng.uniform(-0.6, 0.6)))
        elif style == "smaller":
            corners_world = put_sticker(world, float(rng.uniform(0.72, 0.93)), qz=float(rng.uniform(0.03, 0.10)), material=material,
                                        offset=tuple(rng.uniform(-0.04, 0.04, 2) * QW), angle=float(rng.uniform(-2, 2)))
        elif style == "larger":
            corners_world = put_sticker(world, float(rng.uniform(1.05, 1.28)), qz=float(rng.uniform(0.10, 0.25)), material=material,
                                        offset=tuple(rng.uniform(-0.03, 0.03, 2) * QW), angle=float(rng.uniform(-1.5, 1.5)))
        elif style == "offset_rotated":
            corners_world = put_sticker(world, float(rng.uniform(0.88, 1.08)), qz=float(rng.uniform(0.04, 0.14)), material=material,
                                        offset=tuple(rng.uniform(0.07, 0.20, 2) * QW * rng.choice([-1, 1], 2)),
                                        angle=float(rng.uniform(3, 9) * rng.choice([-1, 1])))
        else:  # wrinkled
            corners_world = put_sticker(world, float(rng.uniform(0.92, 1.15)), qz=float(rng.uniform(0.05, 0.16)), material=material,
                                        offset=tuple(rng.uniform(-0.05, 0.05, 2) * QW), angle=float(rng.uniform(-3, 3)), wrinkle=True)

    # ---------------------------------------------------------------- lighting
    vrng = np.random.default_rng(_stable(seed, "view", view))        # everything view-dependent comes from here
    if view:
        exposure *= float(vrng.uniform(0.88, 1.12))
        wb = wb * np.array([vrng.uniform(0.97, 1.03), 1.0, vrng.uniform(0.97, 1.03)], np.float32)
    yy, xx = np.mgrid[0:WORLD, 0:WORLD].astype(np.float32)
    plane = 1.0 + (xx - cx) / WORLD * srng.uniform(-0.35, 0.35) + (yy - cy) / WORLD * srng.uniform(-0.35, 0.35)
    vign = 1.0 - srng.uniform(0.0, 0.35) * (((xx - cx) ** 2 + (yy - cy) ** 2) / (WORLD ** 2 / 2))
    img = world * (plane * vign)[..., None] * wb[None, None, :] * exposure
    if np.any(gloss_map > 0.01):
        hx, hy = cx + vrng.uniform(-0.4, 0.4) * WORLD * 0.5, cy + vrng.uniform(-0.4, 0.4) * WORLD * 0.5
        sx, sy = vrng.uniform(120, 420), vrng.uniform(120, 420)
        spot = np.exp(-(((xx - hx) / sx) ** 2 + ((yy - hy) / sy) ** 2)) * vrng.uniform(0.25, 0.95)
        img = img + (gloss_map * spot)[..., None] * (0.85 + 0.15 * wb)[None, None, :]
        meta["specular"] = float(spot.max())
    meta["exposure"] = round(exposure, 2)

    # ---------------------------------------------------------------- camera: perspective
    out_w, out_h = size
    qpx = float(vrng.uniform(150, 520))
    s = qpx / QW
    rot = vrng.uniform(-14, 14)
    tilt_x, tilt_y = vrng.uniform(-0.00045, 0.00045), vrng.uniform(-0.00045, 0.00045)
    ox = out_w * (0.5 + vrng.uniform(-0.15, 0.15)); oy = out_h * (0.5 + vrng.uniform(-0.15, 0.15))
    r = np.deg2rad(rot)
    a = np.array([[s * np.cos(r), s * np.sin(r), 0], [-s * np.sin(r), s * np.cos(r), 0], [0, 0, 1]], np.float64)
    t1 = np.array([[1, 0, -cx], [0, 1, -cy], [0, 0, 1]], np.float64)
    p = np.array([[1, 0, 0], [0, 1, 0], [tilt_x, tilt_y, 1]], np.float64)
    t2 = np.array([[1, 0, ox], [0, 1, oy], [0, 0, 1]], np.float64)
    h = t2 @ p @ a @ t1
    photo = cv2.warpPerspective(img.astype(np.float32), h, (out_w, out_h), flags=cv2.INTER_AREA if s < 0.9 else cv2.INTER_LINEAR,
                                borderMode=cv2.BORDER_REFLECT_101)
    pts = cv2.perspectiveTransform(corners_world.reshape(-1, 1, 2).astype(np.float64), h).reshape(-1, 2)
    meta.update(qr_px=round(qpx, 1), rot=round(rot, 1), tilt=round(float(max(abs(tilt_x), abs(tilt_y)) * 1e4), 2))

    # ---------------------------------------------------------------- camera: optics + sensor
    crng = np.random.default_rng(_stable(surface, session, "cam"))
    blur = float(vrng.choice([vrng.uniform(0, 0.55), vrng.uniform(0.4, 1.9)], p=[0.62, 0.38]))
    if vrng.random() < 0.14:                                              # motion blur
        k = int(vrng.integers(3, 10)); kern = np.zeros((k, k), np.float32); kern[k // 2, :] = 1.0 / k
        mr = cv2.getRotationMatrix2D((k / 2 - 0.5, k / 2 - 0.5), vrng.uniform(0, 180), 1.0)
        photo = cv2.filter2D(photo, -1, cv2.warpAffine(kern, mr, (k, k)) / max(float(cv2.warpAffine(kern, mr, (k, k)).sum()), 1e-6))
    photo = _blur(photo, blur)
    noise = float(crng.uniform(0.003, 0.028))
    photo = photo + vrng.standard_normal(photo.shape).astype(np.float32) * (noise * (0.4 + photo))
    if vrng.random() < 0.3:                                               # lower-resolution phone / digital zoom
        f = vrng.uniform(0.55, 0.8)
        photo = cv2.resize(cv2.resize(photo, None, fx=f, fy=f, interpolation=cv2.INTER_AREA), (out_w, out_h), interpolation=cv2.INTER_LINEAR)
    bgr = cv2.cvtColor(np.clip(photo, 0, 1), cv2.COLOR_RGB2BGR)
    bgr8 = (bgr * 255.0 + 0.5).astype(np.uint8)
    ok, enc = cv2.imencode(".jpg", bgr8, [cv2.IMWRITE_JPEG_QUALITY, int(crng.integers(60, 96))])
    bgr8 = cv2.imdecode(enc, cv2.IMREAD_COLOR)
    meta.update(blur=round(blur, 2), noise=round(noise, 4))
    return Scene(bgr8, label, meta, pts.astype(np.float32))


def _label_corners(ox: float, oy: float, angle: float) -> np.ndarray:
    half = QW / 2
    c = WORLD / 2
    return np.array([[c - half, c - half], [c + half, c - half], [c + half, c + half], [c - half, c + half]], np.float32)
