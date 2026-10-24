"""Drift monitoring for the link model: PSI maths, the reference cache and the admin endpoint."""
import json

import numpy as np
import pytest

from qrshield import monitoring


def test_psi_is_zero_for_identical_samples_and_grows_with_shift():
    rng = np.random.default_rng(1)
    ref = rng.beta(1.2, 8, 5000)
    assert monitoring.psi(ref, ref) == pytest.approx(0.0, abs=1e-9)
    same = monitoring.psi(ref, rng.beta(1.2, 8, 5000))
    mild = monitoring.psi(ref, rng.beta(1.8, 8, 5000))
    wild = monitoring.psi(ref, rng.beta(8, 1.5, 5000))
    assert same < monitoring.STABLE_BELOW < mild < wild
    assert wild > monitoring.SHIFT_FROM


def test_psi_survives_empty_bins_and_out_of_range_scores():
    assert np.isfinite(monitoring.psi([0.0] * 50, [1.0] * 50))
    assert monitoring.histogram([-3.0, 7.0]) == [0.5] + [0.0] * 8 + [0.5]
    assert monitoring.histogram([]) == [0.0] * monitoring.BINS
    assert sum(monitoring.histogram(np.random.default_rng(0).uniform(0, 1, 999))) == pytest.approx(1.0)


def test_status_thresholds():
    assert [monitoring.status_for(v) for v in (0.0, 0.099, 0.10, 0.249, 0.25, 3.0)] == [
        "stable", "stable", "moderate_shift", "moderate_shift", "significant_shift", "significant_shift"]


def test_health_needs_enough_samples_then_reports_drift():
    ref = list(np.random.default_rng(2).beta(1.2, 8, 600))
    few = monitoring.health([0.9] * 5, ref)
    assert few["status"] == "insufficient_data" and few["psi"] is None
    drifted = monitoring.health([0.9] * 80, ref)
    assert drifted["status"] == "significant_shift" and drifted["recent"]["flagged_share"] == 1.0 and drifted["mean_shift"] > 0.5
    calm = monitoring.health(list(np.random.default_rng(3).beta(1.2, 8, 300)), ref)
    assert calm["status"] == "stable"


def test_reference_is_computed_once_per_model_version(tmp_path, monkeypatch):
    monkeypatch.setenv("QRSHIELD_ONLINE_CHECKS", "0")
    monkeypatch.setattr(monitoring, "REFERENCE_SAMPLE", 12)
    bench = tmp_path / "b.csv"
    bench.write_text("url,label,source\n" + "".join(f"site{i}.example.com/,0,x\n" for i in range(30)) + "evil.xyz/login,1,x\n", encoding="utf-8")
    first = monitoring.reference_scores(tmp_path, bench)
    assert len(first) == 12 and all(0.0 <= s <= 1.0 for s in first)
    cache = tmp_path / "monitoring_reference.json"
    assert json.loads(cache.read_text())["version"]
    bench.unlink()                                             # a cache hit must not need the benchmark any more
    assert monitoring.reference_scores(tmp_path, bench) == first


def test_admin_model_health_endpoint(client, monkeypatch):
    monkeypatch.setattr(monitoring, "reference_scores", lambda home, benchmark=None: list(np.random.default_rng(4).beta(1.2, 8, 200)))
    assert client.get("/api/admin/model-health").status_code == 401
    h = client.get("/api/admin/model-health", headers=client.admin).json()
    assert h["status"] == "insufficient_data" and h["reference"]["n"] == 200
    reg = client.app_ref.state.registry
    for i in range(40):
        reg.log_scan(scan_id=f"s{i}", payload_hash="h", payload_type="url", verdict="BLOCK", risk=0.9,
                     url_risk=0.95, tamper_risk=0.0, sig_status="none", elapsed_ms=1.0)
    reg.log_scan(scan_id="upi", payload_hash="h", payload_type="upi", verdict="SAFE", risk=0.1,
                 url_risk=0.0, tamper_risk=0.0, sig_status="none", elapsed_ms=1.0)
    h = client.get("/api/admin/model-health", headers=client.admin).json()
    assert h["n_recent"] == 40, "only web-link scans feed the link-model monitor"
    assert h["status"] == "significant_shift" and h["psi"] > monitoring.SHIFT_FROM
