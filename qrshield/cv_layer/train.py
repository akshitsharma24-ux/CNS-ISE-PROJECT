"""
M2 training and evaluation (F18, F19).

    python -m qrshield.cv_layer.train                          # simulated photos only
    python -m qrshield.cv_layer.train --real data/cv_images    # + the team's real photos (metadata.csv)

Evaluation protocol (no random splits - they would let the model memorise a surface or a camera):
  * leave-one-SURFACE-out : every number per surface is on a material the model never saw
  * group-k-fold by SESSION : unseen lighting / camera / surface instance
Calibration is cross-fitted on out-of-fold predictions. Results are written to docs/results/cv_metrics.json.

Honesty note: with simulated data these numbers measure the algorithm against *modelled* physics.
They are not a claim about real-world accuracy - add real photos and re-run to get that.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import cv2
import joblib
import lightgbm as lgb
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupKFold, LeaveOneGroupOut
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from qrshield import config, model_store
from qrshield.cv_layer.features import FEATURE_ORDER
from qrshield.cv_layer.measure import measure
from qrshield.cv_layer.simulate import SURFACES, render_scene

SEED = 7
MODEL_PATH = config.BUNDLED_MODELS_DIR / "cv_model.joblib"
CACHE_DIR = config.DATA_DIR / "cv_cache"
INCONCLUSIVE_BAND = (0.38, 0.62)
LGB_PARAMS: Dict[str, Any] = dict(
    objective="binary", learning_rate=0.05, num_leaves=15, min_data_in_leaf=40, feature_fraction=0.8,
    bagging_fraction=0.8, bagging_freq=1, lambda_l2=3.0, verbose=-1, seed=SEED, deterministic=True,
    force_row_wise=True, num_threads=4,
)
ROUNDS = 260

GROUPS = {
    "edges": [n for n in FEATURE_ORDER if n.startswith(("edge_", "ring_"))],
    "shadow": ["shadow_max", "shadow_mean", "shadow_asym"],
    "colour": ["de_inner_outer", "dL_inner_outer", "db_inner_outer", "dsat_inner_outer"],
    "texture": ["noise_ratio", "noise_diff", "lbp_chi2", "lap_ratio"],
    "specular": ["hl_inner", "hl_outer", "hl_diff"],
    "peeking_code": ["surround_dark_frac", "n_module_blobs", "blob_area_frac", "qz_dark_frac", "qz_std_rel"],
    "frames": ["n_enclosing_rects", "enclosing_margin", "double_border"],
}


# --------------------------------------------------------------------------- data generation
def _gen_session(args: Tuple[str, int, int, int]) -> List[Dict[str, Any]]:
    surface, session, n, seed0 = args
    rows = []
    for i in range(n):
        label = (i + session) % 2
        sc = render_scene(seed0 + i, label=label, surface=surface, session=session)
        m = measure(sc.image)
        row = {**sc.meta, "source": "sim", "decode_ok": m.get("reason") != "no_code", "measured": bool(m["ok"]),
               "reason": m.get("reason", "")}
        if m["ok"]:
            row["vector"] = m["vector"].tolist()
        rows.append(row)
    return rows


def generate_sim(sessions: int, per_session: int, workers: int, log=print) -> List[Dict[str, Any]]:
    tasks = [(s, k, per_session, 1_000_000 * (SURFACES.index(s) + 1) + 1000 * k) for s in SURFACES for k in range(sessions)]
    log(f"rendering {len(tasks) * per_session:,} simulated photos on {workers} workers ...")
    t0 = time.time()
    with ProcessPoolExecutor(max_workers=workers) as ex:
        out = [r for rows in ex.map(_gen_session, tasks) for r in rows]
    log(f"  done in {time.time() - t0:.0f}s")
    return out


def load_real(real_dir: Path, log=print) -> List[Dict[str, Any]]:
    """Read data/cv_images/metadata.csv (schema in scripts/collect_cv_dataset.md) and measure every photo."""
    rows = []
    meta_path = real_dir / "metadata.csv"
    if not meta_path.exists():
        return rows
    with open(meta_path, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            path = real_dir / r["image_id"]
            if not path.exists():
                continue
            img = cv2.imdecode(np.fromfile(str(path), np.uint8), cv2.IMREAD_COLOR)
            if img is None:
                continue
            from qrshield.capture.decode import normalize_resolution
            m = measure(normalize_resolution(img))
            row = {"source": "real", "label": int(r["class_label"]), "surface": r.get("surface", "real"),
                   "session": r.get("session_id", "real-0"), "style": r.get("tamper_style", "none"),
                   "sticker_material": r.get("sticker_material", ""), "decode_ok": m.get("reason") != "no_code",
                   "measured": bool(m["ok"]), "reason": m.get("reason", "")}
            if m["ok"]:
                row["vector"] = m["vector"].tolist()
            rows.append(row)
    log(f"loaded {sum(1 for r in rows if r['measured'])}/{len(rows)} real photos from {real_dir}")
    return rows


# --------------------------------------------------------------------------- modelling
def _fit_lgb(X: np.ndarray, y: np.ndarray, w: Optional[np.ndarray] = None) -> lgb.Booster:
    names = FEATURE_ORDER if X.shape[1] == len(FEATURE_ORDER) else [f"f{i}" for i in range(X.shape[1])]
    return lgb.train(LGB_PARAMS, lgb.Dataset(X, y, weight=w, feature_name=names), num_boost_round=ROUNDS)


def _oof(X, y, groups, splitter, w=None) -> np.ndarray:
    p = np.zeros(len(y))
    for tr, te in splitter.split(X, y, groups):
        p[te] = _fit_lgb(X[tr], y[tr], None if w is None else w[tr]).predict(X[te])
    return p


def _crossfit_calibrate(p: np.ndarray, y: np.ndarray, sessions: np.ndarray) -> np.ndarray:
    """Calibrate OOF scores without calibrating on the data we then evaluate: two disjoint session halves."""
    uniq = np.unique(sessions)
    rng = np.random.default_rng(SEED)
    rng.shuffle(uniq)
    half = np.isin(sessions, uniq[: len(uniq) // 2])
    out = np.zeros_like(p)
    for a, b in ((half, ~half), (~half, half)):
        out[b] = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1).fit(p[a], y[a]).predict(p[b])
    return out


def _m(y: np.ndarray, p: np.ndarray, thr: float = 0.5) -> Dict[str, Any]:
    pred = p >= thr
    pos, neg = (y == 1), (y == 0)
    out: Dict[str, Any] = {"n": int(len(y)), "recall": round(float(pred[pos].mean()), 4) if pos.any() else None,
                           "false_positive_rate": round(float(pred[neg].mean()), 4) if neg.any() else None,
                           "accuracy": round(float((pred == pos).mean()), 4)}
    if pos.any() and neg.any():
        out["roc_auc"] = round(float(roc_auc_score(y, p)), 4)
    return out


def _bin(values: np.ndarray, edges: List[float], names: List[str]) -> np.ndarray:
    return np.asarray([names[int(np.searchsorted(edges, v))] for v in values])


def evaluate(X: np.ndarray, y: np.ndarray, meta: List[Dict[str, Any]], log=print) -> Dict[str, Any]:
    surfaces = np.asarray([m["surface"] for m in meta])
    sessions = np.asarray([m["session"] for m in meta])
    styles = np.asarray([m["style"] for m in meta])
    rep: Dict[str, Any] = {}

    log("leave-one-surface-out ...")
    p_loso = _oof(X, y, surfaces, LeaveOneGroupOut())
    p_loso_c = _crossfit_calibrate(p_loso, y, sessions)
    rep["leave_one_surface_out"] = _m(y, p_loso_c)
    log("group-k-fold by session ...")
    gkf = GroupKFold(n_splits=5)
    p_sess = _oof(X, y, sessions, gkf)
    p_sess_c = _crossfit_calibrate(p_sess, y, sessions)
    rep["group_5fold_by_session"] = _m(y, p_sess_c)

    p = p_loso_c
    rep["per_surface_unseen"] = {s: _m(y[surfaces == s], p[surfaces == s]) for s in sorted(set(surfaces))}
    rep["per_style"] = {s: {"n": int((styles == s).sum()), **{k: v for k, v in _m(y[styles == s], p[styles == s]).items()
                                                                if k in ("recall", "false_positive_rate")}} for s in sorted(set(styles))}
    band = (p >= INCONCLUSIVE_BAND[0]) & (p <= INCONCLUSIVE_BAND[1])
    rep["inconclusive_band"] = {"band": list(INCONCLUSIVE_BAND), "fraction_of_photos": round(float(band.mean()), 4),
                                "accuracy_outside_band": round(float(((p >= 0.5) == (y == 1))[~band].mean()), 4),
                                "accuracy_inside_band": round(float(((p >= 0.5) == (y == 1))[band].mean()), 4) if band.any() else None}

    rep["threshold_table"] = [
        {"threshold": t, **{k: v for k, v in _m(y, p, t).items() if k in ("recall", "false_positive_rate", "accuracy")}}
        for t in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9)]

    cond = {}
    for key, edges, names in (("blur_sigma", [0.5, 1.2], ["<0.5", "0.5-1.2", ">1.2"]), ("qr_px", [250, 400], ["<250", "250-400", ">400"]),
                              ("exposure", [0.8, 1.05], ["dark<0.8", "mid", "bright>1.05"]), ("tilt", [3, 8], ["low", "mid", "high"])):
        if key in meta[0]:
            vals = np.asarray([m[key] for m in meta], dtype=float)
            b = _bin(vals, edges, names)
            cond[key] = {n: _m(y[b == n], p[b == n]) for n in names if (b == n).any()}
    rep["per_condition"] = cond

    log("ablation ...")
    idx = {n: i for i, n in enumerate(FEATURE_ORDER)}
    all_cols = list(range(len(FEATURE_ORDER)))
    ab = {"all_features": rep["leave_one_surface_out"].get("roc_auc")}
    for g, names in GROUPS.items():
        cols = [idx[n] for n in names]
        rest = [c for c in all_cols if c not in cols]
        only = _oof(X[:, cols], y, surfaces, LeaveOneGroupOut())
        without = _oof(X[:, rest], y, surfaces, LeaveOneGroupOut())
        ab[g] = {"only_auc": round(float(roc_auc_score(y, only)), 4), "without_auc": round(float(roc_auc_score(y, without)), 4)}
    rep["feature_group_ablation_loso_auc"] = ab

    log("baselines ...")
    base = {}
    for name, mk in (("logistic_regression", lambda: make_pipeline(StandardScaler(), LogisticRegression(max_iter=600))),
                     ("random_forest", lambda: RandomForestClassifier(n_estimators=200, min_samples_leaf=3, n_jobs=4, random_state=SEED))):
        pp = np.zeros(len(y))
        for tr, te in LeaveOneGroupOut().split(X, y, surfaces):
            pp[te] = mk().fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
        base[name] = round(float(roc_auc_score(y, pp)), 4)
    base["lightgbm"] = rep["leave_one_surface_out"].get("roc_auc")
    rep["baselines_loso_auc"] = base
    return rep


def _two_views(args: Tuple[str, int, int]) -> Dict[str, Any]:
    surface, session, seed = args
    label = seed % 2
    rows = {}
    for view in (0, 1):
        sc = render_scene(seed, label=label, surface=surface, session=session, view=view)
        m = measure(sc.image)
        rows[view] = m if m["ok"] else None
        if view == 0:
            meta = sc.meta
    if rows[0] is None or rows[1] is None:
        return {"ok": False}
    return {"ok": True, "label": label, "style": meta["style"], "surface": surface,
            "v0": rows[0]["vector"].tolist(), "v1": rows[1]["vector"].tolist(),
            "m0": {"rect": rows[0]["rect"], "geom": rows[0]["geom"]}, "m1": {"rect": rows[1]["rect"], "geom": rows[1]["geom"]}}


def evaluate_second_photo(art: Dict[str, Any], n_per_surface: int = 60, workers: int = 8, log=print) -> Dict[str, Any]:
    """Photograph the SAME scene twice (unseen sessions) and compare single photo / two photos / two + cue."""
    from qrshield.cv_layer import model as CM
    from qrshield.cv_layer.second_photo import differential_cue

    tasks = [(s, 100 + (i % 4), 9_000_000 + 100 * SURFACES.index(s) + i) for s in SURFACES for i in range(n_per_surface)]
    log(f"second-photo evaluation: {len(tasks)} scenes x 2 views ...")
    with ProcessPoolExecutor(max_workers=workers) as ex:
        rows = [r for r in ex.map(_two_views, tasks) if r["ok"]]
    y = np.asarray([r["label"] for r in rows])
    p1 = CM.predict(art, np.asarray([r["v0"] for r in rows]))
    p2 = CM.predict(art, np.asarray([r["v1"] for r in rows]))
    cues = np.asarray([differential_cue({"geom": r["m0"]["geom"], "rect": r["m0"]["rect"]},
                                        {"geom": r["m1"]["geom"], "rect": r["m1"]["rect"]})["cue"] for r in rows])
    out: Dict[str, Any] = {"n_scenes": len(rows), "single_photo": _m(y, p1), "second_photo_alone": _m(y, p2)}
    avg = (p1 + p2) / 2
    out["two_photos_average"] = _m(y, avg)
    best_w, best_auc = 0.0, roc_auc_score(y, avg)
    for w in (0.05, 0.12, 0.25):
        auc = roc_auc_score(y, np.clip(avg + w * cues, 0, 1))
        out[f"two_photos_plus_cue_w{w}"] = _m(y, np.clip(avg + w * cues, 0, 1))
        if auc > best_auc + 0.002:
            best_w, best_auc = w, auc
    out["chosen_cue_weight"] = best_w
    final = np.clip(avg + best_w * cues, 0, 1)
    band = (p1 >= INCONCLUSIVE_BAND[0]) & (p1 <= INCONCLUSIVE_BAND[1])
    out["borderline_subset"] = {
        "n": int(band.sum()),
        "accuracy_single_photo": round(float(((p1 >= 0.5) == (y == 1))[band].mean()), 4) if band.any() else None,
        "accuracy_two_photos": round(float(((final >= 0.5) == (y == 1))[band].mean()), 4) if band.any() else None}
    out["cue_mean_tampered_vs_genuine"] = [round(float(cues[y == 1].mean()), 4), round(float(cues[y == 0].mean()), 4)]
    return out


def fit_final(X: np.ndarray, y: np.ndarray, p_oof: np.ndarray, weights: Optional[np.ndarray] = None) -> Dict[str, Any]:
    booster = _fit_lgb(X, y, weights)
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1).fit(p_oof, y)
    return {"kind": "cv", "feature_order": list(FEATURE_ORDER), "booster_str": booster.model_to_string(), "calibrator": iso,
            "params": dict(LGB_PARAMS), "rounds": ROUNDS, "trained_at": int(time.time())}


def run(sessions: int = 12, per_session: int = 50, workers: Optional[int] = None, real_dir: Optional[Path] = None,
        results_path: Optional[Path] = None, log=print) -> Dict[str, Any]:
    workers = workers or max(1, min(16, (os.cpu_count() or 4) - 2))
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache = CACHE_DIR / f"sim_{sessions}x{per_session}.json"
    if cache.exists():
        rows = json.loads(cache.read_text())
        log(f"using cached simulation {cache.name} ({len(rows):,} rows)")
    else:
        rows = generate_sim(sessions, per_session, workers, log)
        cache.write_text(json.dumps(rows))

    n_total = len(rows)
    decode_rate = float(np.mean([r["decode_ok"] for r in rows]))
    sim_rows = [r for r in rows if r["measured"]]
    real_rows = [r for r in (load_real(real_dir, log) if real_dir else []) if r["measured"]]
    all_rows = sim_rows + real_rows
    X = np.asarray([r["vector"] for r in all_rows], dtype=np.float32)
    y = np.asarray([r["label"] for r in all_rows])
    log(f"{len(all_rows):,} usable photos ({len(real_rows)} real); label balance {y.mean():.2f}")

    report: Dict[str, Any] = {"generated_at": time.strftime("%Y-%m-%d"), "n_simulated_photos": n_total,
                              "n_usable": len(all_rows), "n_real_photos": len(real_rows), "n_features": len(FEATURE_ORDER),
                              "decode_success_rate": round(decode_rate, 4),
                              "measurement_failures": {k: int(sum(1 for r in rows if r["reason"] == k)) for k in ("no_code", "low_quality", "partial_view")},
                              "data_is_simulated": True}
    for key, edges, names in (("blur", [0.5, 1.2], ["<0.5", "0.5-1.2", ">1.2"]), ("qr_px", [250, 400], ["<250", "250-400", ">400"])):
        b = _bin(np.asarray([r[key] for r in rows], float), edges, names)
        report[f"decode_rate_by_{key}"] = {n: round(float(np.mean([r["decode_ok"] for r, bb in zip(rows, b) if bb == n])), 4) for n in names}

    report.update(evaluate(X, y, all_rows, log))
    if real_rows:
        ridx = np.asarray([r["source"] == "real" for r in all_rows])
        log("real-photo evaluation (trained on sim + other real sessions) ...")
        sess = np.asarray([r["session"] for r in all_rows])
        w = np.where(ridx, 3.0, 1.0)
        p = np.zeros(len(y))
        for tr, te in GroupKFold(n_splits=min(5, len(set(sess[ridx])))).split(X, y, sess):
            p[te] = _fit_lgb(X[tr], y[tr], w[tr]).predict(X[te])
        report["real_photos_grouped_cv"] = _m(y[ridx], _crossfit_calibrate(p[ridx], y[ridx], sess[ridx]))

    raw_oof = _oof(X, y, np.asarray([r["surface"] for r in all_rows]), LeaveOneGroupOut())
    w_all = np.asarray([3.0 if r["source"] == "real" else 1.0 for r in all_rows])
    art = fit_final(X, y, raw_oof, w_all)
    art["version"] = "v1-bundled"
    art["metrics"] = {"leave_one_surface_out": report["leave_one_surface_out"], "n_real": len(real_rows)}
    art["data"] = {"simulated": len(sim_rows), "real": len(real_rows)}
    report["second_photo"] = evaluate_second_photo(art, workers=workers, log=log)
    art["second_photo_cue_weight"] = report["second_photo"]["chosen_cue_weight"]
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(art, MODEL_PATH, compress=3)
    model_store.reset_cache()

    from qrshield.cv_layer import model as CM
    t0 = time.perf_counter()
    for _ in range(200):
        CM.predict(art, X[:1])
    report["model_latency_ms"] = round((time.perf_counter() - t0) / 200 * 1000, 2)
    results_path = results_path or (config.REPO_ROOT / "docs" / "results" / "cv_metrics.json")
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log(f"wrote {results_path}")
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sessions", type=int, default=12)
    ap.add_argument("--per-session", type=int, default=50)
    ap.add_argument("--workers", type=int, default=None)
    ap.add_argument("--real", type=Path, default=None, help="folder with metadata.csv + photos")
    a = ap.parse_args()
    rep = run(a.sessions, a.per_session, a.workers, a.real)
    print(json.dumps({k: rep[k] for k in ("decode_success_rate", "leave_one_surface_out", "group_5fold_by_session", "per_style",
                                           "inconclusive_band", "baselines_loso_auc")}, indent=2))
