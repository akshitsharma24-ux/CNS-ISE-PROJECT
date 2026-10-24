"""
Model-health monitoring for the link model (M1): has the traffic it sees drifted away from what it was validated on?

A model that scored 0.94 AUC on a benchmark says nothing about next month's QR codes. This module compares the
distribution of recent link-risk scores (from the anonymised scan telemetry) with a reference distribution - the
same model scoring the benign links of the fixed benchmark - using the Population Stability Index:

    PSI = sum_i (cur_i - ref_i) * ln(cur_i / ref_i)         over 10 equal-width score bins

Conventional reading: < 0.10 stable, 0.10-0.25 moderate shift, >= 0.25 significant shift. A shift means either
real data drift (new kinds of links, new URL shorteners) or a wave of risky links; both deserve a human look and,
if the cause is drift, a retrain through the gated pipeline in retrain.py. No payloads or images are used - only
scores that are already logged.
"""
from __future__ import annotations

import csv
import json
import random
from pathlib import Path
from typing import Any, Dict, List, Sequence

import numpy as np

from qrshield import config, model_store

BINS = 10
MIN_SAMPLES = 30                  # below this a PSI is noise
REFERENCE_SAMPLE = 600
STABLE_BELOW, SHIFT_FROM = 0.10, 0.25
_EPS = 1e-4


def histogram(scores: Sequence[float], bins: int = BINS) -> List[float]:
    """Share of scores in each equal-width bin on [0, 1] (sums to 1; empty input gives all zeros)."""
    s = np.clip(np.asarray(list(scores), dtype=float), 0.0, 1.0)
    if s.size == 0:
        return [0.0] * bins
    counts = np.bincount(np.minimum((s * bins).astype(int), bins - 1), minlength=bins)
    return (counts / s.size).tolist()


def psi(reference: Sequence[float], current: Sequence[float]) -> float:
    """Population Stability Index of two score samples (bins smoothed so an empty bin cannot blow up the log)."""
    ref = np.maximum(np.asarray(histogram(reference)), _EPS)
    cur = np.maximum(np.asarray(histogram(current)), _EPS)
    return float(np.sum((cur - ref) * np.log(cur / ref)))


def status_for(value: float) -> str:
    return "stable" if value < STABLE_BELOW else "moderate_shift" if value < SHIFT_FROM else "significant_shift"


def reference_scores(home: Path, benchmark: Path | None = None) -> List[float]:
    """Link-risk scores of the active model on the benign benchmark links; computed once per model version and cached."""
    from qrshield.url_layer import analyze

    version = model_store.active_version("url") or "none"
    cache = Path(home) / "monitoring_reference.json"
    try:
        cached = json.loads(cache.read_text(encoding="utf-8"))
        if cached.get("version") == version and cached.get("sample") == REFERENCE_SAMPLE:
            return cached["scores"]
    except (OSError, ValueError):
        pass
    path = benchmark or (config.REPO_ROOT / "data" / "benchmark" / "url_benchmark.csv")
    with open(path, encoding="utf-8", newline="") as fh:
        urls = [r["url"] for r in csv.DictReader(fh) if r.get("label") == "0"]
    random.Random(7).shuffle(urls)
    scores = [float(analyze("https://" + u)["score"]) for u in urls[:REFERENCE_SAMPLE]]
    try:
        cache.write_text(json.dumps({"version": version, "sample": REFERENCE_SAMPLE, "scores": scores}), encoding="utf-8")
    except OSError:
        pass
    return scores


def health(recent_url_scores: Sequence[float], reference: Sequence[float]) -> Dict[str, Any]:
    """Drift report for the link model. `recent_url_scores` are the logged risks of recent scans of web links."""
    n = len(recent_url_scores)
    out: Dict[str, Any] = {
        "model": model_store.active_version("url"), "n_recent": n, "min_samples": MIN_SAMPLES, "bins": BINS,
        "reference": {"n": len(reference), "description": "active model on the benign benchmark links",
                      "histogram": [round(x, 4) for x in histogram(reference)], "mean": round(float(np.mean(reference)), 4) if len(reference) else None},
    }
    if n < MIN_SAMPLES:
        out.update(status="insufficient_data", psi=None, recent={"histogram": [round(x, 4) for x in histogram(recent_url_scores)], "mean": None},
                   message=f"Need at least {MIN_SAMPLES} scanned web links to judge drift ({n} so far).")
        return out
    value = psi(reference, recent_url_scores)
    mean_recent, mean_ref = float(np.mean(recent_url_scores)), float(np.mean(reference))
    flagged = float(np.mean(np.asarray(recent_url_scores) >= 0.5))
    status = status_for(value)
    out.update(
        status=status, psi=round(value, 4),
        recent={"histogram": [round(x, 4) for x in histogram(recent_url_scores)], "mean": round(mean_recent, 4), "flagged_share": round(flagged, 4)},
        mean_shift=round(mean_recent - mean_ref, 4),
        message={"stable": "Recent link scores look like the benchmark the model was validated on.",
                 "moderate_shift": "Recent link scores are drifting from the benchmark. Review recent reports and consider a gated retrain.",
                 "significant_shift": "Recent link scores differ markedly from the benchmark: either a wave of risky links or data drift. Review reports, then retrain through the gate if it is drift."}[status])
    return out
