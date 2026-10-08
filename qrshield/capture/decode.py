"""
QR Detection and Decoding (F01, F02, F03)
Robust multi-stage QR code detector using OpenCV QRCodeDetector with
adaptive pre-processing fallbacks, multi-code / stacked sticker detection,
and corner extraction for perspective rectification.
"""
import io
import cv2
import numpy as np
from PIL import Image
from typing import Dict, Any, Tuple, Optional, List

from qrshield.capture.payload_types import parse_payload_type
from qrshield.capture.quality import assess_image_quality

def bytes_to_cv2_image(image_bytes: bytes) -> np.ndarray:
    """Safely decodes image bytes into a BGR OpenCV numpy array."""
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        # Fallback to PIL in case of exotic header formats
        try:
            pil_img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
        except Exception as e:
            raise ValueError(f"Failed to decode image bytes: {e}")
    return img

def check_overlapping_regions(boxes: List[np.ndarray]) -> bool:
    """
    Checks if any two detected bounding boxes overlap significantly,
    which indicates a sticker pasted over or adjacent to another QR.
    """
    if len(boxes) < 2:
        return False
    # Check pairwise intersection of axis-aligned bounding rectangles
    rects = []
    for b in boxes:
        pts = np.squeeze(b)
        x_min, y_min = np.min(pts, axis=0)
        x_max, y_max = np.max(pts, axis=0)
        rects.append((x_min, y_min, x_max, y_max))

    for i in range(len(rects)):
        for j in range(i + 1, len(rects)):
            r1 = rects[i]
            r2 = rects[j]
            # Intersection coordinates
            ix_min = max(r1[0], r2[0])
            iy_min = max(r1[1], r2[1])
            ix_max = min(r1[2], r2[2])
            iy_max = min(r1[3], r2[3])

            if ix_min < ix_max and iy_min < iy_max:
                inter_area = (ix_max - ix_min) * (iy_max - iy_min)
                area1 = (r1[2] - r1[0]) * (r1[3] - r1[1])
                area2 = (r2[2] - r2[0]) * (r2[3] - r2[1])
                overlap_ratio = inter_area / min(area1, area2 + 1e-6)
                if overlap_ratio > 0.15:  # Over 15% overlap
                    return True
    return False

def check_nested_contours(gray: np.ndarray, corners: np.ndarray) -> bool:
    """
    Detects if the QR code sits inside another larger concentric square-like
    boundary (classic signature of a replacement sticker).
    """
    if corners is None or len(corners) == 0:
        return False
    pts = np.squeeze(corners)
    if pts.shape != (4, 2):
        return False

    qr_center = np.mean(pts, axis=0)
    qr_side = np.mean([
        np.linalg.norm(pts[0] - pts[1]),
        np.linalg.norm(pts[1] - pts[2])
    ])

    # Find external contours
    edges = cv2.Canny(gray, 50, 150)
    contours, _ = cv2.findContours(edges, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)

    stacked_found = False
    for cnt in contours:
        area = cv2.contourArea(cnt)
        if area > (qr_side * 1.1) ** 2 and area < (qr_side * 3.0) ** 2:
            peri = cv2.arcLength(cnt, True)
            approx = cv2.approxPolyDP(cnt, 0.04 * peri, True)
            # If 4-sided contour enclosing QR center
            if len(approx) == 4 and cv2.isContourConvex(approx):
                dist = cv2.pointPolygonTest(approx, (float(qr_center[0]), float(qr_center[1])), False)
                if dist >= 0:
                    stacked_found = True
                    break
    return stacked_found

def decode_qr(img: np.ndarray) -> Tuple[Optional[str], Optional[np.ndarray], bool, str]:
    """
    Multi-stage QR detector and decoder.
    Returns: (payload, corners, multi_code_flag, details)
    """
    detector = cv2.QRCodeDetector()

    if len(img.shape) == 3:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    else:
        gray = img.copy()

    # Pass 1: Multi-code detection check first
    multi_code_flag = False
    details = ""
    try:
        multi_success, decoded_info, points, _ = detector.detectAndDecodeMulti(img)
        if multi_success and points is not None and len(points) > 1:
            if check_overlapping_regions([pts for pts in points]):
                multi_code_flag = True
                details = "Multiple overlapping QR regions detected in frame."
    except Exception:
        pass

    # Pass 2: Direct detectAndDecode
    payload, corners, _ = detector.detectAndDecode(img)
    if payload:
        if not multi_code_flag and check_nested_contours(gray, corners):
            multi_code_flag = True
            details = "Possible stacked code detected (outer contour enclosing QR)."
        return payload, corners, multi_code_flag, details

    # Pass 3: CLAHE (Contrast Limited Adaptive Histogram Equalization)
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)
    payload, corners, _ = detector.detectAndDecode(enhanced)
    if payload:
        return payload, corners, multi_code_flag, details

    # Pass 4: Adaptive Thresholding
    thresh = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 21, 5
    )
    payload, corners, _ = detector.detectAndDecode(thresh)
    if payload:
        return payload, corners, multi_code_flag, details

    # Pass 5: 2x Upscaling for small QR codes
    h, w = gray.shape[:2]
    upscaled = cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
    payload, corners_up, _ = detector.detectAndDecode(upscaled)
    if payload and corners_up is not None:
        corners = corners_up / 2.0
        return payload, corners, multi_code_flag, details

    # Pass 6: Otsu Thresholding
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    payload, corners, _ = detector.detectAndDecode(otsu)
    if payload:
        return payload, corners, multi_code_flag, details

    return None, None, False, "No valid QR code detected in image."

def capture_and_decode(image_bytes: bytes) -> Dict[str, Any]:
    """
    Full M0 capture and decode pipeline.
    """
    try:
        img = bytes_to_cv2_image(image_bytes)
    except Exception as e:
        return {
            "success": False,
            "error": f"Invalid image format: {e}",
            "payload": None,
            "payload_type": "other",
            "corners": None,
            "quality": assess_image_quality(None, None),
            "multi_code": False,
            "raw_image": image_bytes
        }

    payload, corners, multi_code, multi_details = decode_qr(img)
    quality = assess_image_quality(img, corners)

    if not payload:
        return {
            "success": False,
            "error": "Could not detect or decode QR code.",
            "payload": None,
            "payload_type": "other",
            "corners": None,
            "quality": quality,
            "multi_code": False,
            "raw_image": image_bytes
        }

    ptype, pmeta = parse_payload_type(payload)

    # Convert corners to plain list for JSON serialization if needed
    corners_list = corners.tolist() if corners is not None else None

    return {
        "success": True,
        "error": None,
        "payload": payload,
        "payload_type": ptype,
        "payload_meta": pmeta,
        "corners": corners_list,
        "corners_np": corners,
        "multi_code": multi_code,
        "multi_code_details": multi_details,
        "quality": quality,
        "raw_image": image_bytes
    }
