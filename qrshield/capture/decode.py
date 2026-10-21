"""
QR detection and decoding (F01, F02, F03).

Decoder order: zxing-cpp (robust on real photos: perspective, glare, rotation, inverted codes)
-> OpenCV QRCodeDetector / Aruco detector -> pyzbar (optional). Each runs on a handful of
cheap pre-processed variants (CLAHE, threshold, upscale) until something decodes.

Every frame also yields the *corner points* of the code (needed by the tamper layer) and a
"stacked code" check: two QR-like regions overlapping in the frame is a strong indicator of a
half-covered sticker.
"""
from __future__ import annotations

import io
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

import cv2
import numpy as np
from PIL import Image, ImageOps

from qrshield import config
from qrshield.capture.payload_types import parse_payload_type
from qrshield.capture.quality import assess_image_quality, order_corners

MAX_SIDE = 2000          # photos are down-scaled so every layer sees a consistent resolution

try:                      # zxing-cpp is the primary decoder; the OpenCV path keeps things working without it
    import zxingcpp
except ImportError:       # pragma: no cover - exercised only on stripped-down installs
    zxingcpp = None


@dataclass
class Code:
    text: str
    corners: np.ndarray            # (4, 2) float32: TL, TR, BR, BL in image coordinates
    source: str
    detail: Dict[str, Any] = field(default_factory=dict)

    @property
    def bbox(self) -> Tuple[float, float, float, float]:
        x, y = self.corners[:, 0], self.corners[:, 1]
        return float(x.min()), float(y.min()), float(x.max()), float(y.max())

    @property
    def area(self) -> float:
        x0, y0, x1, y1 = self.bbox
        return max(0.0, (x1 - x0) * (y1 - y0))


@dataclass
class FrameResult:
    codes: List[Code]
    primary: Optional[Code]
    stacked: bool = False
    stacked_details: str = ""


# --------------------------------------------------------------------------- image loading
def bytes_to_cv2_image(image_bytes: bytes) -> np.ndarray:
    """Decode untrusted image bytes into a BGR array, refusing oversized inputs first."""
    if not image_bytes:
        raise ValueError("empty image")
    if len(image_bytes) > config.MAX_UPLOAD_BYTES:
        raise ValueError("image exceeds the upload size limit")
    try:
        with Image.open(io.BytesIO(image_bytes)) as probe:
            width, height = probe.size
    except Exception as exc:
        raise ValueError(f"not a valid image: {exc}") from exc
    if width * height > config.MAX_IMAGE_PIXELS:
        raise ValueError("image dimensions exceed the safety limit")

    arr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)        # applies EXIF orientation
    if img is None:
        try:
            pil = ImageOps.exif_transpose(Image.open(io.BytesIO(image_bytes))).convert("RGB")
            img = cv2.cvtColor(np.array(pil), cv2.COLOR_RGB2BGR)
        except Exception as exc:
            raise ValueError(f"failed to decode image: {exc}") from exc
    return normalize_resolution(img)


def normalize_resolution(img: np.ndarray) -> np.ndarray:
    h, w = img.shape[:2]
    longest = max(h, w)
    if longest > MAX_SIDE:
        s = MAX_SIDE / longest
        img = cv2.resize(img, (int(w * s), int(h * s)), interpolation=cv2.INTER_AREA)
    return img


# --------------------------------------------------------------------------- decoders
def _zxing(img: np.ndarray) -> List[Code]:
    if zxingcpp is None:
        return []
    try:
        results = zxingcpp.read_barcodes(img, formats=zxingcpp.BarcodeFormat.QRCode)
    except Exception:
        return []
    out = []
    for r in results:
        if not r.valid or not r.text:
            continue
        p = r.position
        pts = np.array([[p.top_left.x, p.top_left.y], [p.top_right.x, p.top_right.y],
                        [p.bottom_right.x, p.bottom_right.y], [p.bottom_left.x, p.bottom_left.y]], dtype=np.float32)
        out.append(Code(r.text, pts, "zxing", {"ec_level": getattr(r, "ec_level", "")}))
    return out


def _opencv(img: np.ndarray) -> List[Code]:
    detectors = [cv2.QRCodeDetector()]
    if hasattr(cv2, "QRCodeDetectorAruco"):
        detectors.append(cv2.QRCodeDetectorAruco())
    for det in detectors:
        try:
            text, pts, _ = det.detectAndDecode(img)
        except cv2.error:
            continue
        if text and pts is not None and np.size(pts) >= 8:
            return [Code(text, order_corners(pts), "opencv")]
    return []


def _pyzbar(img: np.ndarray) -> List[Code]:
    try:
        from pyzbar.pyzbar import decode as zbar_decode
    except Exception:
        return []
    out = []
    try:
        for b in zbar_decode(img):
            if b.type != "QRCODE":
                continue
            text = b.data.decode("utf-8", errors="replace")
            if text and len(b.polygon) == 4:
                pts = np.array([[q.x, q.y] for q in b.polygon], dtype=np.float32)
                out.append(Code(text, order_corners(pts), "pyzbar"))
    except Exception:
        return []
    return out


def _variants(img: np.ndarray) -> Iterator[Tuple[np.ndarray, float]]:
    """Cheap pre-processing variants as (image, scale_factor_vs_original)."""
    yield img, 1.0
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    yield cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(gray), 1.0
    yield cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 7), 1.0
    h, w = gray.shape[:2]
    if max(h, w) <= 1200:
        yield cv2.resize(gray, None, fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC), 2.0
    blur = cv2.GaussianBlur(gray, (0, 0), 3)
    yield cv2.addWeighted(gray, 1.8, blur, -0.8, 0), 1.0
    yield cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1], 1.0


def _iou_like(a: Code, b: Code) -> Tuple[float, float]:
    """Return (intersection / union, intersection / smaller-area) of the two bounding boxes."""
    ax0, ay0, ax1, ay1 = a.bbox
    bx0, by0, bx1, by1 = b.bbox
    iw, ih = min(ax1, bx1) - max(ax0, bx0), min(ay1, by1) - max(ay0, by0)
    if iw <= 0 or ih <= 0:
        return 0.0, 0.0
    inter = iw * ih
    return inter / (a.area + b.area - inter + 1e-6), inter / (min(a.area, b.area) + 1e-6)


def finder_pattern_centres(gray: np.ndarray) -> np.ndarray:
    """Centres of QR finder patterns (concentric 7:5:3-module squares) found anywhere in the frame.

    A QR code has exactly three. Finder patterns that do not belong to any decodable code are the
    visible remnants of another code - for example an original code peeking out from under a sticker.
    """
    scale = min(1.0, 1000.0 / max(gray.shape[:2]))
    g = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA) if scale < 1.0 else gray
    g = cv2.GaussianBlur(g, (3, 3), 0)
    ink = cv2.adaptiveThreshold(g, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY_INV, 25, 8)
    contours, hier = cv2.findContours(ink, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
    if hier is None:
        return np.zeros((0, 2), np.float32)
    hier = hier[0]
    found: List[Tuple[float, float, float]] = []
    for i, cnt in enumerate(contours):
        child = hier[i][2]
        if child < 0:
            continue
        grand = hier[child][2]
        if grand < 0:
            continue
        a0, a1, a2 = (cv2.contourArea(contours[k]) for k in (i, child, grand))
        if a0 < 100 or a1 <= 0 or a2 <= 0:
            continue
        x, y, w, h = cv2.boundingRect(cnt)
        if not (0.6 <= w / max(h, 1) <= 1.6) or a0 / (w * h) < 0.55:
            continue
        if 1.3 <= a0 / a1 <= 2.9 and 1.8 <= a1 / a2 <= 4.3:
            found.append(((x + w / 2) / scale, (y + h / 2) / scale, np.sqrt(a0) / scale))
    merged: List[Tuple[float, float, float]] = []
    for cx, cy, r in sorted(found, key=lambda t: -t[2]):
        if all(np.hypot(cx - mx, cy - my) > 0.6 * max(r, mr) for mx, my, mr in merged):
            merged.append((cx, cy, r))
    return np.asarray([(m[0], m[1]) for m in merged], np.float32).reshape(-1, 2)


def _inside(point: np.ndarray, code: Code, grow: float = 0.15) -> bool:
    c = code.corners.mean(axis=0)
    quad = (c + (code.corners - c) * (1.0 + grow)).astype(np.float32)
    return cv2.pointPolygonTest(quad.reshape(-1, 1, 2), (float(point[0]), float(point[1])), False) >= 0


def _stacked_check(gray: np.ndarray, codes: List[Code]) -> Tuple[bool, str]:
    """A code pasted over another one leaves tell-tale traces: overlapping decodable codes, or extra finder patterns."""
    for i in range(len(codes)):
        for j in range(i + 1, len(codes)):
            iou, smaller = _iou_like(codes[i], codes[j])
            if smaller > 0.15 and iou < 0.85:
                return True, "Two QR codes overlap in the frame - a code may be pasted over another one."
    if not codes:
        return False, ""
    centres = finder_pattern_centres(gray)
    extras = [c for c in centres if not any(_inside(c, code) for code in codes)]
    if len(extras) >= 2:
        return True, f"{len(extras)} extra QR finder patterns were found outside this code - part of another code is visible underneath."
    return False, ""


def analyze_frame(img: np.ndarray) -> FrameResult:
    """Find and decode QR codes in a BGR frame."""
    codes: List[Code] = []
    for variant, scale in _variants(img):
        found = _zxing(variant)
        if found:
            if scale != 1.0:
                for c in found:
                    c.corners = c.corners / scale
            codes = found
            break
    if not codes:
        codes = _opencv(img)
    if not codes:
        codes = _pyzbar(img)
    if not codes:
        return FrameResult([], None)

    codes.sort(key=lambda c: c.area, reverse=True)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img
    stacked, details = _stacked_check(gray, codes)
    return FrameResult(codes, codes[0], stacked, details)


def decode_qr(img: np.ndarray) -> Tuple[Optional[str], Optional[np.ndarray], bool, str]:
    """Compatibility wrapper: (payload, corners, stacked_flag, details)."""
    res = analyze_frame(img)
    if res.primary is None:
        return None, None, False, "No valid QR code detected in image."
    return res.primary.text, res.primary.corners, res.stacked, res.stacked_details


# --------------------------------------------------------------------------- M0 entry point
def capture_and_decode(image_bytes: bytes) -> Dict[str, Any]:
    """Full M0 pipeline: load, decode, type the payload, assess quality."""
    try:
        img = bytes_to_cv2_image(image_bytes)
    except ValueError as exc:
        return {"success": False, "error": str(exc), "payload": None, "payload_type": "other",
                "corners": None, "quality": assess_image_quality(None, None), "multi_code": False,
                "codes": [], "image": None}

    frame = analyze_frame(img)
    quality = assess_image_quality(img, frame.primary.corners if frame.primary else None)
    if frame.primary is None:
        return {"success": False, "error": "No QR code found. Centre the code in the frame and retake the photo.",
                "payload": None, "payload_type": "other", "corners": None, "quality": quality,
                "multi_code": False, "codes": [], "image": img}

    payload = frame.primary.text
    ptype, pmeta = parse_payload_type(payload)
    return {
        "success": True, "error": None,
        "payload": payload, "payload_type": ptype, "payload_meta": pmeta,
        "corners": frame.primary.corners.tolist(), "corners_np": frame.primary.corners,
        "multi_code": frame.stacked, "multi_code_details": frame.stacked_details,
        "codes": [{"text": c.text[:200], "source": c.source} for c in frame.codes],
        "decoder": frame.primary.source,
        "quality": quality, "image": img,
    }
