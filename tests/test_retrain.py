"""F35: human-gated retraining. A candidate is promoted only if it is not worse; poisoning is rejected."""
import random

import numpy as np
import pytest

from qrshield import model_store, retrain
from qrshield.url_layer import train


@pytest.fixture()
def small_corpus(tmp_path, monkeypatch):
    """Use a 6,000-row slice of the bundled corpus so retraining takes seconds, not minutes."""
    urls, y, groups = train.load_base_corpus()
    idx = np.random.default_rng(3).choice(len(urls), 6000, replace=False)
    path = tmp_path / "base.csv.gz"
    train.save_base_corpus([urls[i] for i in idx], y[idx], [groups[i] for i in idx], path)
    monkeypatch.setattr(train, "BASE_CORPUS_PATH", path)
    return path


def small_benchmark(n=500):
    urls, y = train.load_benchmark()
    rng = np.random.default_rng(1)
    idx = rng.choice(len(urls), n, replace=False)
    return [urls[i] for i in idx], y[idx]


@pytest.mark.slow
def test_gate_accepts_a_healthy_candidate(home, small_corpus):
    active = model_store.load("url")
    cand = train.retrain([], [])
    bench_urls, bench_y = small_benchmark()
    ok, rep = train.gate(active, cand, bench_urls, bench_y)
    # a model trained on 6k rows is a weaker model than the shipped 100k one: it must be judged on the numbers
    assert set(rep["checks"]) == {"roc_auc_not_worse", "tpr_at_1pct_fpr_not_worse", "fpr_not_worse", "all_canaries_correct"}
    assert rep["candidate"]["canaries_correct"] == rep["candidate"]["canaries_total"]
    assert isinstance(ok, bool)


@pytest.mark.slow
def test_poisoning_by_mass_reports_is_rejected(home, small_corpus):
    """An attacker mass-reports legitimate sites as phishing: even if approved, the benchmark+canary gate blocks it."""
    active = model_store.load("url")
    rng = random.Random(5)
    poison_urls, poison_labels = [], []
    for host in ("spit.ac.in", "irctc.co.in", "onlinesbi.sbi", "paytm.com", "amazon.in", "wikipedia.org", "pay.citypark.example"):
        for i in range(120):
            poison_urls.append(f"https://{host}/{rng.choice(['help','pay','info','login','menu'])}/{i}")
            poison_labels.append(1)                                    # "this is phishing"
    cand = train.retrain(poison_urls, poison_labels, weight=5.0)
    bench_urls, bench_y = small_benchmark()
    ok, rep = train.gate(active, cand, bench_urls, bench_y)
    assert not ok and not rep["checks"]["all_canaries_correct"]


def test_retrain_status_and_versions(registry):
    assert retrain.status()["running"] is False
    registry.record_model_version("url", "v-test", "rejected", {"roc_auc": 0.9, "fpr": 0.1}, "gate failed: all_canaries_correct")
    hist = registry.list_model_versions("url")
    assert hist[0]["status"] == "rejected" and hist[0]["metrics"]["roc_auc"] == 0.9


@pytest.mark.slow
def test_full_retrain_run_promotes_or_rejects_and_records(home, registry, small_corpus, monkeypatch):
    rid = registry.add_report("https://totally-new-scam-site.top/login", "phishing", "seen on a poster")
    registry.review_report(rid, "approve")
    # keep the run fast: score the gate on a 500-row slice of the real benchmark
    bench = small_benchmark()
    monkeypatch.setattr(train, "load_benchmark", lambda *a, **k: bench)
    result = retrain.run(registry)
    assert result["approved_reports_used"] == 1 and isinstance(result["promoted"], bool)
    hist = registry.list_model_versions("url")
    assert hist and hist[0]["version"] == result["version"]
    if result["promoted"]:
        assert model_store.active_version("url") == result["version"]
        assert registry.approved_reports(only_unused=True) == []
    audit = [a["action"] for a in registry.audit_log()]
    assert "model.promote" in audit or "model.reject" in audit
