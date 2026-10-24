"""Camera-degradation perturbations and calibration metrics used by the robustness evaluation."""
import numpy as np
import pytest

from qrshield.calibration import reliability_bins
from qrshield.cv_layer import analyze, perturb
from qrshield.cv_layer.simulate import render_scene


@pytest.fixture(scope="module")
def photo():
    return render_scene(4246, label=1, surface="wood", style="offset_rotated", session=5).image


@pytest.mark.parametrize("name", sorted(perturb.PERTURBATIONS))
def test_every_perturbation_keeps_shape_and_dtype_and_is_deterministic(photo, name):
    a = perturb.apply(name, photo, 2, seed=7)
    assert a.shape == photo.shape and a.dtype == np.uint8
    assert np.array_equal(a, perturb.apply(name, photo, 2, seed=7)), "same seed must give the same degraded photo"
    assert not np.array_equal(a, photo), "a degradation that changes nothing proves nothing"


def test_severity_is_monotonic_for_blur_and_noise(photo):
    for name in ("gaussian_blur", "sensor_noise", "low_light"):
        err = [float(np.abs(perturb.apply(name, photo, s, seed=1).astype(float) - photo).mean()) for s in perturb.SEVERITIES]
        assert err[0] < err[1] < err[2], name


def test_invalid_severity_is_rejected(photo):
    with pytest.raises(ValueError):
        perturb.apply("jpeg", photo, 4)


def test_analyze_survives_every_degradation_without_raising(photo):
    for name in perturb.PERTURBATIONS:
        r = analyze(perturb.apply(name, photo, 3, seed=3))
        assert r["status"] in ("ok", "inconclusive", "low_quality") and 0.0 <= r["score"] <= 1.0


def test_reliability_bins_perfectly_calibrated_and_overconfident():
    rng = np.random.default_rng(0)
    p = rng.uniform(0, 1, 20000)
    y = (rng.uniform(0, 1, 20000) < p).astype(int)
    assert reliability_bins(y, p)["ece"] < 0.02
    over = reliability_bins(y, np.where(p > 0.5, 0.99, 0.01))
    assert over["ece"] > 0.15 and over["mce"] >= over["ece"]
    assert sum(b["n"] for b in over["bins"]) == 20000


def test_reliability_bins_edge_cases():
    assert reliability_bins([1, 0], [1.0, 0.0])["ece"] == 0.0 and reliability_bins([1, 0], [1.0, 0.0])["brier"] == 0.0
    assert reliability_bins([1], [7.0])["bins"][0]["hi"] == 1.0, "scores are clipped into [0, 1]"
    with pytest.raises(ValueError):
        reliability_bins([], [])
    with pytest.raises(ValueError):
        reliability_bins([1, 0], [0.5])
