"""
M1 training, evaluation and retraining (F12, F13, F35).

    python -m qrshield.url_layer.train            # needs `make data` (data/url/*.parquet)

Everything reported in docs/evaluation.md for the URL layer is produced here: a domain-disjoint
test split, an external corpus never trained on, recent 2026 phishing feeds, popular-domain false
positives, baselines, per-component scores and a feature-group ablation that exposes leakage.
"""
from __future__ import annotations

import csv
import gzip
import json
import time
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import lightgbm as lgb
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score, roc_curve
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from qrshield import config, model_store
from qrshield.url_layer import model as M
from qrshield.url_layer.features import FEATURE_ORDER, extract_features, ngram_text

SEED = 42
BASE_CORPUS_ROWS = 100_000
LGB_PARAMS: Dict[str, Any] = dict(
    objective="binary", learning_rate=0.05, num_leaves=31, min_data_in_leaf=60, feature_fraction=0.8,
    bagging_fraction=0.8, bagging_freq=1, lambda_l2=5.0, verbose=-1, seed=SEED, deterministic=True,
    force_row_wise=True, num_threads=4,
)
BASE_CORPUS_PATH = config.BUNDLED_MODELS_DIR / "url_base_corpus.csv.gz"
MODEL_PATH = config.BUNDLED_MODELS_DIR / "url_model.joblib"
BENCHMARK_PATH = config.DATA_DIR / "benchmark" / "url_benchmark.csv"

# Fixed sanity set: a retrained model that gets any of these wrong is rejected by the gate, which
# also blunts data-poisoning through mass-reported "good" or "bad" links.
CANARIES: List[Tuple[str, int]] = [
    ("https://spit.ac.in/departments/computer-engineering/faculty", 0),
    ("https://pay.citypark.example/m/42", 0),
    ("https://www.irctc.co.in/nget/train-search", 0),
    ("https://onlinesbi.sbi/retail/login.htm", 0),
    ("https://www.amazon.in/gp/help/customer/display.html", 0),
    ("https://en.wikipedia.org/wiki/QR_code", 0),
    ("https://paytm.com/recharge/prepaid-mobile-payment", 0),
    ("https://secure-phonepe-refund.xyz/claim-cashback?amt=2000", 1),
    ("https://paytm-kyc-update.top/wallet/kyc-verification.php", 1),
    ("http://sbi-reward-claim.online/redeem-points/otp.html", 1),
    ("https://mumbai-challan-pay.click/e-challan/settle?id=MH02", 1),
    ("http://hdfcbank-security-alert.club/otp-update", 1),
]


# --------------------------------------------------------------------------- featurisation
def featurize(urls: Sequence[str]) -> np.ndarray:
    return np.asarray([extract_features(u).vector for u in urls], dtype=np.float32)


def texts_of(urls: Sequence[str]) -> List[str]:
    return [ngram_text(u) for u in urls]


def group_hash(groups: Sequence[str]) -> np.ndarray:
    return np.asarray([zlib.crc32(str(g).encode("utf-8")) for g in groups], dtype=np.uint32)


def split_by_group(groups: np.ndarray, fractions: Dict[str, float], seed: int = SEED) -> Dict[str, np.ndarray]:
    """Row masks such that no group (registered domain) ever spans two splits."""
    uniq = np.unique(groups)
    rng = np.random.default_rng(seed)
    rng.shuffle(uniq)
    out: Dict[str, np.ndarray] = {}
    start = 0
    names = list(fractions)
    for i, name in enumerate(names):
        stop = len(uniq) if i == len(names) - 1 else start + int(round(len(uniq) * fractions[name]))
        out[name] = np.isin(groups, uniq[start:stop])
        start = stop
    return out


# --------------------------------------------------------------------------- metrics
def metrics_at(y: np.ndarray, p: np.ndarray, thr: float = 0.5) -> Dict[str, Any]:
    y = np.asarray(y)
    pred = (p >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    out: Dict[str, Any] = {
        "n": int(len(y)), "threshold": thr, "accuracy": round((tp + tn) / max(len(y), 1), 4),
        "precision": round(tp / max(tp + fp, 1), 4), "recall": round(tp / max(tp + fn, 1), 4),
        "fpr": round(fp / max(fp + tn, 1), 4), "confusion": [[tn, fp], [fn, tp]],
    }
    pr, rc = out["precision"], out["recall"]
    out["f1"] = round(2 * pr * rc / max(pr + rc, 1e-9), 4)
    if len(np.unique(y)) == 2:
        out["roc_auc"] = round(float(roc_auc_score(y, p)), 4)
        out["pr_auc"] = round(float(average_precision_score(y, p)), 4)
        out["brier"] = round(float(brier_score_loss(y, p)), 4)
        fpr, tpr, _ = roc_curve(y, p)
        out["tpr_at_1pct_fpr"] = round(float(np.interp(0.01, fpr, tpr)), 4)
    return out


# --------------------------------------------------------------------------- model fitting
def fit(urls: Sequence[str], X: np.ndarray, y: np.ndarray, groups: np.ndarray,
        weights: Optional[np.ndarray] = None, rounds: int = 1000) -> Dict[str, Any]:
    """Train both models on a domain-disjoint train split, early-stop on val, calibrate on cal."""
    urls = np.asarray(urls, dtype=object)
    sp = split_by_group(groups, {"train": 0.76, "val": 0.12, "cal": 0.12})
    w = weights if weights is not None else np.ones(len(y), dtype=np.float32)

    dtrain = lgb.Dataset(X[sp["train"]], y[sp["train"]], weight=w[sp["train"]], feature_name=FEATURE_ORDER)
    dval = lgb.Dataset(X[sp["val"]], y[sp["val"]], weight=w[sp["val"]], reference=dtrain)
    booster = lgb.train(LGB_PARAMS, dtrain, num_boost_round=rounds, valid_sets=[dval],
                        callbacks=[lgb.early_stopping(50, verbose=False)])

    counts = M._HV.transform(texts_of(urls[sp["train"]]))
    tfidf = TfidfTransformer(sublinear_tf=True).fit(counts)
    lr = LogisticRegression(max_iter=300, C=2.0, solver="liblinear", random_state=SEED)
    lr.fit(tfidf.transform(counts), y[sp["train"]], sample_weight=w[sp["train"]])

    art: Dict[str, Any] = {
        "kind": "url", "feature_order": list(FEATURE_ORDER), "booster_str": booster.model_to_string(),
        "ngram": {"idf": tfidf.idf_.astype(np.float32), "coef": lr.coef_[0].astype(np.float32),
                  "intercept": float(lr.intercept_[0])},
        "best_iteration": int(booster.best_iteration), "params": dict(LGB_PARAMS),
        "n_train": int(sp["train"].sum()), "trained_at": int(time.time()),
    }
    cal = sp["cal"]
    p_lgb, p_ng = M.raw_scores(art, X[cal], texts_of(urls[cal]))
    art["calibrator"] = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit((p_lgb + p_ng) / 2, y[cal])
    return art


def predict(art: Dict[str, Any], urls: Sequence[str], X: Optional[np.ndarray] = None) -> np.ndarray:
    return M.predict_proba(art, X if X is not None else featurize(urls), texts_of(urls))


# --------------------------------------------------------------------------- base corpus (retraining)
def save_base_corpus(urls: Sequence[str], y: np.ndarray, groups: Sequence[str], path: Path = BASE_CORPUS_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "label", "group"])
        for u, l, g in zip(urls, y, groups):
            w.writerow([u, int(l), g])


def load_base_corpus(path: Path = BASE_CORPUS_PATH) -> Tuple[List[str], np.ndarray, List[str]]:
    urls, labels, groups = [], [], []
    with gzip.open(path, "rt", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            urls.append(row["url"]); labels.append(int(row["label"])); groups.append(row["group"])
    return urls, np.asarray(labels), groups


# --------------------------------------------------------------------------- benchmark gate
def load_benchmark(path: Path = BENCHMARK_PATH) -> Tuple[List[str], np.ndarray]:
    urls, labels = [], []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            urls.append(row["url"]); labels.append(int(row["label"]))
    return urls, np.asarray(labels)


def benchmark_scores(art: Dict[str, Any], urls: Sequence[str], y: np.ndarray) -> Dict[str, Any]:
    m = metrics_at(y, predict(art, urls))
    can_p = predict(art, [u for u, _ in CANARIES])
    can_y = np.asarray([l for _, l in CANARIES])
    m["canaries_correct"] = int(((can_p >= 0.5).astype(int) == can_y).sum())
    m["canaries_total"] = len(CANARIES)
    return m


def gate(active: Dict[str, Any], candidate: Dict[str, Any], urls: Sequence[str], y: np.ndarray) -> Tuple[bool, Dict[str, Any]]:
    """Promote only if the candidate is not worse than the active model on the fixed benchmark."""
    a, c = benchmark_scores(active, urls, y), benchmark_scores(candidate, urls, y)
    checks = {
        "roc_auc_not_worse": c["roc_auc"] >= a["roc_auc"] - 0.005,
        "tpr_at_1pct_fpr_not_worse": c["tpr_at_1pct_fpr"] >= a["tpr_at_1pct_fpr"] - 0.02,
        "fpr_not_worse": c["fpr"] <= a["fpr"] + 0.01,
        "all_canaries_correct": c["canaries_correct"] == c["canaries_total"],
    }
    return all(checks.values()), {"active": a, "candidate": c, "checks": checks}


def _base_features(urls: Sequence[str]) -> np.ndarray:
    """Feature matrix of the bundled base corpus, cached in the runtime home (first retrain is slower)."""
    stat = BASE_CORPUS_PATH.stat()
    cache = config.home_dir() / "cache" / f"url_base_{stat.st_size}_{int(stat.st_mtime)}_{len(FEATURE_ORDER)}.npy"
    if cache.exists():
        return np.load(cache)
    X = featurize(urls)
    cache.parent.mkdir(parents=True, exist_ok=True)
    np.save(cache, X)
    return X


def retrain(extra_urls: Sequence[str] = (), extra_labels: Sequence[int] = (), weight: float = 3.0) -> Dict[str, Any]:
    """Train a candidate on the bundled base corpus plus human-approved report rows."""
    urls, y, groups = load_base_corpus()
    X = _base_features(urls)
    urls = list(urls)
    gh = group_hash(groups)
    w = np.ones(len(y), dtype=np.float32)
    if len(extra_urls):
        X = np.vstack([X, featurize(extra_urls)])
        urls += list(extra_urls)
        y = np.concatenate([y, np.asarray(extra_labels)])
        gh = np.concatenate([gh, group_hash([f"report-{i}" for i in range(len(extra_urls))])])
        w = np.concatenate([w, np.full(len(extra_urls), weight, dtype=np.float32)])
    return fit(urls, X, y, gh, w)


# --------------------------------------------------------------------------- full pipeline
def _quick_auc(X_tr, y_tr, X_te, y_te, cols: List[int]) -> float:
    m = lgb.train(LGB_PARAMS, lgb.Dataset(X_tr[:, cols], y_tr), num_boost_round=200)
    return round(float(roc_auc_score(y_te, m.predict(X_te[:, cols]))), 4)


def run(data_dir: Path = config.DATA_DIR / "url", results_path: Optional[Path] = None, log=print) -> Dict[str, Any]:
    import joblib
    import pandas as pd

    pool = pd.read_parquet(data_dir / "train_pool.parquet")
    external = pd.read_parquet(data_dir / "external.parquet")
    recent = pd.read_parquet(data_dir / "recent_phishing.parquet")
    popular = pd.read_parquet(data_dir / "popular_benign.parquet")

    log("featurizing pool ...")
    urls_pool = pool["url"].to_numpy()
    X_pool, y_pool = featurize(urls_pool), pool["label"].to_numpy()
    g_pool = pool["group"].to_numpy()
    is_synth = pool["source"].str.startswith("synthetic").to_numpy()

    sp = split_by_group(g_pool, {"test": 0.15, "rest": 0.85})
    real_test = sp["test"] & ~is_synth
    log(f"pool rows={len(pool):,}  domain-disjoint test={real_test.sum():,}")

    rng = np.random.default_rng(SEED)
    idx = np.flatnonzero(sp["rest"])
    take = [rng.choice(idx[y_pool[idx] == l], size=min(BASE_CORPUS_ROWS // 2, int((y_pool[idx] == l).sum())), replace=False)
            for l in (0, 1)]
    base_idx = rng.permutation(np.concatenate(take))
    save_base_corpus(urls_pool[base_idx], y_pool[base_idx], g_pool[base_idx])

    log(f"training on {len(base_idx):,} rows ...")
    art = fit(urls_pool[base_idx], X_pool[base_idx], y_pool[base_idx], group_hash(g_pool[base_idx]))
    art["version"] = "v1-bundled"

    report: Dict[str, Any] = {"generated_at": time.strftime("%Y-%m-%d"), "n_train_rows": int(len(base_idx)),
                              "n_structured_features": len(FEATURE_ORDER), "ngram_features": M.NGRAM_FEATURES,
                              "lightgbm_best_iteration": art["best_iteration"]}

    X_ext, y_ext = featurize(external["url"]), external["label"].to_numpy()
    p_test = predict(art, urls_pool[real_test], X_pool[real_test])
    p_ext = predict(art, external["url"], X_ext)
    report["domain_disjoint_test"] = metrics_at(y_pool[real_test], p_test)
    report["domain_disjoint_test_at_0.30"] = metrics_at(y_pool[real_test], p_test, 0.30)
    report["domain_disjoint_test_at_0.65"] = metrics_at(y_pool[real_test], p_test, 0.65)
    report["external_pirocheto"] = metrics_at(y_ext, p_ext)
    report["external_pirocheto_at_0.30"] = metrics_at(y_ext, p_ext, 0.30)
    report["external_pirocheto_at_0.65"] = metrics_at(y_ext, p_ext, 0.65)

    report["threshold_table"] = [
        {"threshold": t,
         "domain_disjoint": {k: v for k, v in metrics_at(y_pool[real_test], p_test, t).items() if k in ("recall", "fpr")},
         "external": {k: v for k, v in metrics_at(y_ext, p_ext, t).items() if k in ("recall", "fpr")}}
        for t in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9)]

    p_rec = predict(art, recent["url"])
    report["recent_phishing_recall"] = {"n": int(len(p_rec)), **{f"recall_at_{t}": round(float((p_rec >= t).mean()), 4) for t in (0.30, 0.50, 0.65)}}
    p_pop = predict(art, popular["url"])
    report["popular_top20k_false_positive_rate_model_only"] = {
        "n": int(len(p_pop)), **{f"fpr_at_{t}": round(float((p_pop >= t).mean()), 4) for t in (0.30, 0.50, 0.65)}}

    # DEPLOYED behaviour: the analyzer (model + brand rules + trusted-domain caps), on the decision scale used by the engine
    from qrshield.url_layer import analyze
    from qrshield.url_layer.brands import KNOWN_GOOD
    log("deployed analyzer on samples ...")

    def deployed(urls) -> np.ndarray:
        return np.asarray([analyze("https://" + u, offline=True)["score"] for u in urls])

    ext_b = external[external.label == 0]["url"].sample(2500, random_state=1).tolist()
    ext_p = external[external.label == 1]["url"].sample(2500, random_state=1).tolist()
    rec_p = recent["url"].sample(2500, random_state=1).tolist()
    pop_rows = popular[~popular["group"].isin(KNOWN_GOOD)]["url"].sample(2500, random_state=1).tolist()
    s_b, s_p, s_r, s_pop = deployed(ext_b), deployed(ext_p), deployed(rec_p), deployed(pop_rows)

    def rates(s, thr):
        return round(float((s >= thr).mean()), 4)

    report["deployed_analyzer"] = {
        "note": "decision-scale risk after rules; SUSPICIOUS starts at ~0.30 fused, BLOCK-eligible from ~0.68 (see config.URL_P_*)",
        "samples": {"external_benign": len(ext_b), "external_phishing": len(ext_p), "recent_phishing": len(rec_p), "popular_not_in_known_good": len(pop_rows)},
        "not_safe_rate_at_0.30": {"external_benign (false alarms)": rates(s_b, .30), "external_phishing (recall)": rates(s_p, .30),
                                  "recent_phishing (recall)": rates(s_r, .30), "popular_domains_outside_allowlist (false alarms)": rates(s_pop, .30)},
        "block_eligible_rate_at_0.65": {"external_benign (false blocks)": rates(s_b, .65), "external_phishing (recall)": rates(s_p, .65),
                                        "recent_phishing (recall)": rates(s_r, .65), "popular_domains_outside_allowlist (false blocks)": rates(s_pop, .65)},
    }

    # per-component scores
    rt_urls = urls_pool[real_test]
    comps = {}
    for name, (u, X, y) in {"domain_disjoint_test": (rt_urls, X_pool[real_test], y_pool[real_test]),
                            "external_pirocheto": (external["url"].to_numpy(), X_ext, y_ext)}.items():
        pl, pn = M.raw_scores(art, X, texts_of(u))
        comps[name] = {"structured_lightgbm_auc": round(float(roc_auc_score(y, pl)), 4),
                       "char_ngram_auc": round(float(roc_auc_score(y, pn)), 4),
                       "blend_calibrated_auc": round(float(roc_auc_score(y, predict(art, u, X))), 4)}
    report["components"] = comps

    log("baselines ...")
    Xb, yb = X_pool[base_idx], y_pool[base_idx]
    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=500, random_state=SEED)).fit(Xb, yb)
    rf = RandomForestClassifier(n_estimators=200, min_samples_leaf=3, n_jobs=4, random_state=SEED).fit(Xb, yb)
    base = {}
    for name, model in (("logistic_regression_structured", lr), ("random_forest_structured", rf)):
        base[name] = {"domain_disjoint_roc_auc": round(float(roc_auc_score(y_pool[real_test], model.predict_proba(X_pool[real_test])[:, 1])), 4),
                      "external_roc_auc": round(float(roc_auc_score(y_ext, model.predict_proba(X_ext)[:, 1])), 4)}
    report["baselines"] = base

    log("ablation ...")
    groups_of = {"host_structure": FEATURE_ORDER[:23], "brand": FEATURE_ORDER[23:31], "path_query": FEATURE_ORDER[31:]}
    cols = {n: [FEATURE_ORDER.index(f) for f in fs] for n, fs in groups_of.items()}
    ab = {}
    for name, cs in {"all_structured": list(range(len(FEATURE_ORDER))), "host_only (structure+brand)": cols["host_structure"] + cols["brand"],
                     "path_query_only": cols["path_query"], "brand_only": cols["brand"],
                     "without_brand": cols["host_structure"] + cols["path_query"]}.items():
        ab[name] = {"domain_disjoint_roc_auc": _quick_auc(Xb, yb, X_pool[real_test], y_pool[real_test], cs),
                    "external_roc_auc": _quick_auc(Xb, yb, X_ext, y_ext, cs)}
    report["feature_group_ablation"] = ab

    sample = list(pool["url"].sample(300, random_state=1))
    t0 = time.perf_counter()
    for u in sample:
        predict(art, [u])
    report["latency_ms_per_url"] = round((time.perf_counter() - t0) / len(sample) * 1000, 2)

    contrib = np.abs(lgb.Booster(model_str=art["booster_str"]).predict(X_pool[real_test][:3000], pred_contrib=True)[:, :-1]).mean(axis=0)
    report["top_structured_features_mean_abs_shap"] = [(FEATURE_ORDER[i], round(float(contrib[i]), 3)) for i in np.argsort(contrib)[::-1][:12]]

    art["metrics"] = {k: report[k] for k in ("domain_disjoint_test", "external_pirocheto")}
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(art, MODEL_PATH, compress=3)
    model_store.reset_cache()

    BENCHMARK_PATH.parent.mkdir(parents=True, exist_ok=True)
    bench = []
    for df, n, src in ((external[external.label == 0], 600, "pirocheto_benign"), (external[external.label == 1], 600, "pirocheto_phish"),
                       (recent, 600, "recent_phish"), (popular, 300, "tranco_popular")):
        part = df.sample(n=min(n, len(df)), random_state=SEED)
        bench += [(u, int(l), src) for u, l in zip(part["url"], part["label"])]
    with open(BENCHMARK_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["url", "label", "source"]); w.writerows(bench)
    report["benchmark_rows"] = len(bench)
    report["benchmark_active_model"] = benchmark_scores(art, [b[0] for b in bench], np.asarray([b[1] for b in bench]))

    results_path = results_path or (config.REPO_ROOT / "docs" / "results" / "url_metrics.json")
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log(f"wrote {results_path}")
    return report


if __name__ == "__main__":
    rep = run()
    print(json.dumps({k: rep[k] for k in ("domain_disjoint_test", "external_pirocheto", "components", "recent_phishing_recall",
                                           "popular_top20k_false_positive_rate_model_only", "feature_group_ablation", "latency_ms_per_url")}, indent=2))
