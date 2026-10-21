"""M0: decoding robustness, payload typing, quality gate, hostile image input."""
import io

import cv2
import numpy as np
import pytest
from PIL import Image

from qrshield.capture import analyze_frame, capture_and_decode, parse_payload_type
from qrshield.capture.quality import assess_image_quality
from tests.conftest import encode, make_qr

URL = "https://pay.citypark.example/m/42?x=1"


def _warp(img, tilt=0.08, rot=12):
    h, w = img.shape[:2]
    big = cv2.copyMakeBorder(img, 120, 120, 120, 120, cv2.BORDER_CONSTANT, value=(170, 175, 180))
    H, W = big.shape[:2]
    src = np.float32([[0, 0], [W, 0], [W, H], [0, H]])
    d = tilt * W
    dst = np.float32([[d, d * .4], [W - d * .5, 0], [W - d * .2, H - d * .3], [0, H]])
    out = cv2.warpPerspective(big, cv2.getPerspectiveTransform(src, dst), (W, H), borderValue=(170, 175, 180))
    m = cv2.getRotationMatrix2D((W / 2, H / 2), rot, 1.0)
    return cv2.warpAffine(out, m, (W, H), borderValue=(170, 175, 180))


def test_clean_code_decodes_with_corners():
    r = capture_and_decode(encode(make_qr(URL)))
    assert r["success"] and r["payload"] == URL and r["payload_type"] == "url"
    assert np.asarray(r["corners"]).shape == (4, 2)


@pytest.mark.parametrize("variant", ["rotated_perspective", "noisy_jpeg", "blurred", "inverted", "small", "low_contrast"])
def test_realistic_variants_decode(variant):
    img = make_qr(URL, box=9)
    if variant == "rotated_perspective":
        img = _warp(img)
    elif variant == "noisy_jpeg":
        rng = np.random.default_rng(1)
        img = np.clip(img.astype(np.float32) + rng.normal(0, 14, img.shape), 0, 255).astype(np.uint8)
    elif variant == "blurred":
        img = cv2.GaussianBlur(img, (0, 0), 1.6)
    elif variant == "inverted":
        img = 255 - img
    elif variant == "small":
        img = cv2.resize(img, None, fx=0.45, fy=0.45, interpolation=cv2.INTER_AREA)
    elif variant == "low_contrast":
        img = (60 + img.astype(np.float32) * 0.45).astype(np.uint8)
    r = capture_and_decode(encode(img, ".jpg", 80))
    assert r["success"], variant
    assert r["payload"] == URL


def test_no_code_gives_helpful_error_not_exception():
    blank = np.full((400, 400, 3), 200, np.uint8)
    r = capture_and_decode(encode(blank))
    assert r["success"] is False and "QR" in r["error"]


def test_corrupt_bytes_and_empty_input():
    for junk in (b"", b"CORRUPT_HEADER_NOT_A_VALID_IMAGE_BYTES_12345", b"\x89PNG\r\n\x1a\n" + b"\x00" * 50):
        r = capture_and_decode(junk)
        assert r["success"] is False and r["error"]


def test_decompression_bomb_is_refused_before_decoding():
    buf = io.BytesIO()
    Image.new("L", (9000, 9000), 255).save(buf, format="PNG")          # 81 MP of white compresses tiny
    r = capture_and_decode(buf.getvalue())
    assert r["success"] is False and "safety limit" in r["error"]


def test_oversized_upload_refused():
    r = capture_and_decode(b"\x00" * (9 * 1024 * 1024))
    assert r["success"] is False and "limit" in r["error"]


def test_small_code_pasted_over_a_larger_one_is_flagged_as_stacked():
    """The original's corner finder patterns stay visible around the sticker: extra finders = a hidden code."""
    a = make_qr("https://a.example/original", box=10)
    b = make_qr("https://b.example/sticker", box=10)
    canvas = np.full((a.shape[0] + 160, a.shape[1] + 160, 3), 255, np.uint8)
    canvas[80:80 + a.shape[0], 80:80 + a.shape[1]] = a
    s = int(a.shape[0] * 0.36)
    off = 80 + (a.shape[0] - s) // 2
    canvas[off:off + s, off:off + s] = cv2.resize(b, (s, s), interpolation=cv2.INTER_NEAREST)
    res = analyze_frame(canvas)
    assert res.primary is not None and res.primary.text == "https://b.example/sticker"
    assert res.stacked and "finder" in res.stacked_details


def test_single_code_and_separate_side_by_side_codes_are_not_stacked():
    for payload in ("https://spit.ac.in/departments/comps", "upi://pay?pa=a@ybl&pn=Shop", "WIFI:S:x;T:WPA;P:y;;", "https://pay.citypark.example/m/42?x=" + "q" * 60):
        assert not analyze_frame(make_qr(payload, box=9)).stacked, payload
    a, b = make_qr("https://a.example/one", box=8), make_qr("https://b.example/two", box=8)
    both = np.full((a.shape[0] + 60, a.shape[1] * 2 + 140, 3), 255, np.uint8)
    both[30:30 + a.shape[0], 30:30 + a.shape[1]] = a
    both[30:30 + b.shape[0], a.shape[1] + 110:a.shape[1] + 110 + b.shape[1]] = b
    res = analyze_frame(both)
    assert len(res.codes) == 2 and not res.stacked, "a poster with two separate, readable codes is ambiguous, not tampered"


# ---------------------------------------------------------------- payload types
@pytest.mark.parametrize("payload,expected", [
    ("https://example.com/a?b=c", "url"),
    ("http://[x", "url"),
    ("upi://pay?pa=a@ybl&pn=X", "upi"),
    ("WIFI:S:Cafe;T:WPA;P:secret;;", "wifi"),
    ("tel:+912212345678", "tel"),
    ("smsto:12345:STOP", "sms"),
    ("mailto:a@b.example?subject=hi", "mailto"),
    ("geo:19.07,72.87", "geo"),
    ("bitcoin:bc1qxyz", "crypto"),
    ("BEGIN:VCARD\nFN:X", "vcard"),
    ("javascript:alert(1)", "risky_scheme"),
    ("data:text/html,<script>1</script>", "risky_scheme"),
    ("intent://scan/#Intent;scheme=zxing;end", "risky_scheme"),
    ("file:///etc/passwd", "risky_scheme"),
    ("evil-bank.com/login", "url"),
    ("just some words", "text"),
    ("", "text"),
])
def test_payload_types(payload, expected):
    assert parse_payload_type(payload)[0] == expected


def test_wifi_open_network_and_sms_body_parsed():
    t, meta = parse_payload_type("WIFI:S:FreeCafe;T:nopass;;")
    assert t == "wifi" and meta["auth"] == "nopass" and meta["ssid"] == "FreeCafe"
    t, meta = parse_payload_type("sms:+9199?body=WIN%20PRIZE")
    assert t == "sms" and meta["body"] == "WIN PRIZE"


# ---------------------------------------------------------------- quality gate
def test_quality_gate_flags_blur_and_small():
    sharp = make_qr(URL, box=10)
    ok = assess_image_quality(sharp, np.array([[40, 40], [sharp.shape[1] - 40, 40], [sharp.shape[1] - 40, sharp.shape[0] - 40], [40, sharp.shape[0] - 40]], np.float32))
    assert ok["status"] == "ok" and not ok["hints"]
    blurry = cv2.GaussianBlur(sharp, (0, 0), 5)
    bad = assess_image_quality(blurry, np.array([[40, 40], [sharp.shape[1] - 40, 40], [sharp.shape[1] - 40, sharp.shape[0] - 40], [40, sharp.shape[0] - 40]], np.float32))
    assert bad["status"] == "low_quality" and any("blurry" in h for h in bad["hints"])
    tiny = assess_image_quality(sharp, np.array([[10, 10], [60, 10], [60, 60], [10, 60]], np.float32))
    assert tiny["is_too_small"] and any("closer" in h for h in tiny["hints"])


def test_white_poster_is_not_glare():
    poster = np.full((600, 800, 3), 255, np.uint8)
    qr = make_qr(URL, box=8)
    poster[100:100 + qr.shape[0], 100:100 + qr.shape[1]] = qr
    res = analyze_frame(poster)
    q = assess_image_quality(poster, res.primary.corners)
    assert not q["is_glare"], "a white page must not be mistaken for a reflection on the code"
