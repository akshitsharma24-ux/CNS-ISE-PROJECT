"""
Robustness and calibration of the sticker model under camera degradations.

    python -m qrshield robustness [--n 40]

Renders held-out simulated scenes (seeds and sessions the model was never trained on), degrades each photo with
every perturbation in qrshield.cv_layer.perturb at three severities, and runs the REAL `cv_layer.analyze` on it.
Per condition it records how often the layer abstains (asks for a retake), detects attacks and false-alarms on
genuine codes, plus ROC-AUC. On the clean photos it also measures calibration (ECE / Brier / reliability table).
Output: docs/results/cv_robustness.json (rendered into docs/evaluation.md by scripts.make_eval_report).

Honest scope: scenes are simulated, so this measures sensitivity to *modelled* degradations, not field accuracy.
"""
from __future__ import annotations

import argparse
import datetime
import json
import time
from typing import Any, Dict, List

import cv2
import numpy as np
from sklearn.metrics import roc_auc_score

from qrshield import config
from qrshield.calibration import reliability_bins
from qrshield.cv_layer import analyze, perturb
from qrshield.cv_layer.simulate import BENIGN_STYLES, SURFACES, TAMPER_STYLES, render_scene

SEED0 = 9_100_000            # disjoint from the training seeds
SESSION0 = 500
THRESHOLD = 0.5


def build_scenes(n_per_class: int) -> List[Dict[str, Any]]:
    rng = np.random.default_rng(2027)
    scenes = []
    for label in (0, 1):
        styles = TAMPER_STYLES if label else BENIGN_STYLES
        for i in range(n_per_class):
            sc = render_scene(SEED0 + label * 10_000 + i, label=label, surface=str(rng.choice(SURFACES)),
                              style=str(rng.choice(styles)), session=SESSION0 + int(rng.integers(8)))
            scenes.append({"label": label, "image": sc.image, "seed": SEED0 + i})
    return scenes


def run_condition(scenes: List[Dict[str, Any]], name: str, severity: int) -> Dict[str, Any]:
    y, p, abstained = [], [], 0
    for s in scenes:
        img = s["image"] if name == "clean" else perturb.apply(name, s["image"], severity, s["seed"])
        r = analyze(img)
        if r["status"] == "low_quality":
            abstained += 1
            continue
        y.append(s["label"])
        p.append(r["score"])
    y, p = np.asarray(y), np.asarray(p)
    pos, neg = y == 1, y == 0
    return {
        "n": len(scenes), "n_scored": int(len(y)), "abstain_rate": round(abstained / len(scenes), 4),
        "recall": round(float((p[pos] >= THRESHOLD).mean()), 4) if pos.any() else None,
        "false_positive_rate": round(float((p[neg] >= THRESHOLD).mean()), 4) if neg.any() else None,
        "roc_auc": round(float(roc_auc_score(y, p)), 4) if pos.any() and neg.any() else None,
        "_y": y.tolist(), "_p": p.tolist(),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=40, help="scenes per class (default 40 -> 80 photos x 28 conditions)")
    args = ap.parse_args()

    t0 = time.time()
    scenes = build_scenes(args.n)
    print(f"rendered {len(scenes)} held-out scenes in {time.time() - t0:.0f}s")

    clean = run_condition(scenes, "clean", 0)
    calibration = reliability_bins(clean["_y"], clean["_p"], n_bins=10)
    conditions: Dict[str, Dict[str, Any]] = {}
    for name in perturb.PERTURBATIONS:
        conditions[name] = {}
        for sev in perturb.SEVERITIES:
            conditions[name][str(sev)] = run_condition(scenes, name, sev)
            c = conditions[name][str(sev)]
            print(f"  {name:14s} sev {sev}: AUC {c['roc_auc']}  recall {c['recall']}  FPR {c['false_positive_rate']}  abstain {c['abstain_rate']}")

    for c in [clean] + [v for d in conditions.values() for v in d.values()]:
        c.pop("_y"), c.pop("_p")
    out = {
        "generated_at": datetime.date.today().isoformat(), "data_is_simulated": True, "threshold": THRESHOLD,
        "n_scenes": len(scenes), "n_per_class": args.n, "severity_scale": {"1": "mild", "2": "moderate", "3": "severe"},
        "clean": clean, "calibration_clean": calibration, "conditions": conditions,
        "worst_case": min(((n, s, v["roc_auc"]) for n, d in conditions.items() for s, v in d.items() if v["roc_auc"] is not None),
                          key=lambda t: t[2]),
    }
    path = config.REPO_ROOT / "docs" / "results" / "cv_robustness.json"
    path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path} in {time.time() - t0:.0f}s; clean AUC {clean['roc_auc']}, ECE {calibration['ece']}, Brier {calibration['brier']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
