"""M2: rectification geometry, feature sanity, analyze() contract and held-out behaviour of the trained model."""
import cv2
import numpy as np
import pytest

from qrshield.capture.decode import analyze_frame
from qrshield.cv_layer import analyze
from qrshield.cv_layer.features import FEATURE_ORDER
from qrshield.cv_layer.measure import measure
from qrshield.cv_layer.rectify import CORE, DIST, M, Q, S, rectify, ring
from qrshield.cv_layer.simulate import render_scene
from tests.conftest import encode, make_qr


def test_canvas_geometry_is_consistent():
    assert S == 384 and Q == 128 and M == 128
    assert CORE.sum() > 0.9 * (Q - 4) ** 2 and not CORE[0, 0]
    assert ring(4, 16).sum() > 0 and not (ring(4, 16) & CORE).any()
    assert DIST[S // 2, S // 2] < 0 and DIST[0, 0] > 0


def test_rectification_maps_the_code_to_the_centre():
    img = make_qr("https://example.com/geometry-check", box=8)
    canvas = cv2.copyMakeBorder(img, 260, 260, 260, 260, cv2.BORDER_CONSTANT, value=(255, 255, 255))   # same white as the quiet zone
    frame = analyze_frame(canvas)
    rect, coverage = rectify(canvas, frame.primary.corners)
    assert rect.shape == (S, S, 3) and coverage > 0.99
    centre = cv2.cvtColor(rect, cv2.COLOR_BGR2GRAY)[M:M + Q, M:M + Q]
    assert centre.std() > 60, "the QR modules should fill the central square"
    ring_px = cv2.cvtColor(rect, cv2.COLOR_BGR2GRAY)[ring(8, 60)]
    assert ring_px.std() < 8, "a plain surround must stay flat after rectification"


def test_features_are_complete_and_finite():
    sc = render_scene(4242, label=1, surface="wood", style="smaller", session=1)
    m = measure(sc.image)
    assert m["ok"] and set(m["features"]) == set(FEATURE_ORDER)
    assert np.isfinite(m["vector"]).all() and m["vector"].shape == (len(FEATURE_ORDER),)


def test_analyze_contract_and_overlay():
    sc = render_scene(4243, label=1, surface="metal", style="offset_rotated", session=2)
    r = analyze(encode(sc.image, ".jpg"))
    assert {"score", "status", "signals", "heatmap_png_b64", "details"} <= set(r)
    assert r["status"] in ("ok", "inconclusive") and 0.0 <= r["score"] <= 1.0
    assert r["heatmap_png_b64"].startswith("data:image/png;base64,")
    assert all({"name", "text", "direction"} <= set(s) for s in r["signals"])


def test_no_code_blur_and_garbage_are_low_quality_not_errors():
    assert analyze(b"")["status"] == "low_quality"
    assert analyze(b"not an image")["status"] == "low_quality"
    blank = np.full((400, 400, 3), 190, np.uint8)
    assert analyze(blank)["status"] == "low_quality"
    sc = render_scene(4244, label=1, surface="wood", style="smaller", session=3)
    mushy = cv2.GaussianBlur(sc.image, (0, 0), 14)
    r = analyze(mushy)
    assert r["status"] == "low_quality" and r["score"] == 0.0, "an unreadable photo must not produce a verdict"


def test_second_photo_with_a_different_code_is_flagged():
    a = render_scene(4245, label=0, surface="matte_paper", style="printed_direct", session=4, payload="https://a.example/one")
    b = render_scene(4246, label=0, surface="matte_paper", style="printed_direct", session=4, payload="https://b.example/two")
    r = analyze(a.image, b.image)
    assert any(s["name"] == "payload_mismatch_multi_view" for s in r["signals"]) and r["score"] >= 0.7


def test_two_views_of_the_same_scene_are_accepted():
    v0 = render_scene(4247, label=1, surface="metal", style="smaller", session=5, view=0)
    v1 = render_scene(4247, label=1, surface="metal", style="smaller", session=5, view=1)
    assert v0.label == v1.label
    r = analyze(v0.image, v1.image)
    assert r["details"].get("views") == 2


def test_stacked_overlapping_codes_raise_the_score():
    a, b = make_qr("https://a.example/one", box=10), make_qr("https://b.example/two", box=10)
    canvas = np.full((a.shape[0] + 200, a.shape[1] + 200, 3), 235, np.uint8)
    canvas[40:40 + a.shape[0], 40:40 + a.shape[1]] = a
    s = int(b.shape[0] * 0.85)
    canvas[100:100 + s, 100:100 + s] = cv2.resize(b, (s, s), interpolation=cv2.INTER_NEAREST)
    r = analyze(canvas)
    if r["status"] != "low_quality":
        assert r["score"] >= 0.6 or any(s["name"] == "stacked_code_pattern" for s in r["signals"])


# ---------------------------------------------------------------- held-out behaviour of the shipped model
@pytest.mark.slow
def test_model_separates_unseen_sessions():
    """Fresh simulated sessions (never in training): AUC well above chance, easy tamper styles caught."""
    from sklearn.metrics import roc_auc_score
    rows = []
    for i in range(70):
        label = i % 2
        style = ["smaller", "offset_rotated", "wrinkled"][i % 3] if label else None
        sc = render_scene(8_500_000 + i, label=label, surface=["wood", "metal", "matte_paper", "plastic"][i % 4],
                          style=style, session=500 + i % 5)
        r = analyze(sc.image)
        if r["status"] != "low_quality":
            rows.append((label, r["score"], style))
    y = np.array([r[0] for r in rows]); p = np.array([r[1] for r in rows])
    assert len(rows) >= 50
    assert roc_auc_score(y, p) > 0.80
    easy = [s for lab, s, st in rows if lab == 1]
    assert np.mean([s >= 0.5 for s in easy]) > 0.6
