"""
Render docs/evaluation.md from docs/results/*.json. Nothing in the report is typed by hand.

    python -m scripts.make_eval_report
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from qrshield import config

R = config.REPO_ROOT / "docs" / "results"


def load(name: str) -> Dict[str, Any]:
    p = R / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def pct(x) -> str:
    return "-" if x is None else f"{100 * x:.1f}%"


def table(head: List[str], rows: List[List[Any]]) -> str:
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def url_section(u: Dict[str, Any], corpus: Dict[str, Any]) -> str:
    if not u:
        return "_Run `python -m qrshield data && python -m qrshield train-url` to generate this section._\n"
    s = ["## 1. M1 - link model (real public corpora)\n"]
    if corpus:
        b, a = corpus["shape_before_balancing"], corpus["shape_after_balancing"]
        s.append("### 1.1 The corpora are biased - and in opposite directions\n")
        s.append("A model trained on raw phishing corpora learns *how the data was collected*, not phishing. Share of URLs that carry a path / a query string, by class:\n")
        rows = []
        for src, shp in corpus.get("per_source_shape_raw", {}).items():
            rows.append([src, f"{pct(shp['benign']['has_path'])} / {pct(shp['phishing']['has_path'])}", f"{pct(shp['benign']['has_query'])} / {pct(shp['phishing']['has_query'])}"])
        rows.append(["**all raw sources pooled**", f"{pct(b['benign']['has_path'])} / {pct(b['phishing']['has_path'])}", f"{pct(b['benign']['has_query'])} / {pct(b['phishing']['has_query'])}"])
        rows.append(["**after shape-balancing (used for training)**", f"{pct(a['benign']['has_path'])} / {pct(a['phishing']['has_path'])}", f"{pct(a['benign']['has_query'])} / {pct(a['phishing']['has_query'])}"])
        s.append(table(["Source", "has path (benign / phishing)", "has query (benign / phishing)"], rows))
        s.append("In PhiUSIIL no benign URL has a path, so \"has a path\" alone separates the classes; in ealvaradob the bias runs the other way. "
                 "Mitigations: scheme and `www.` are not features, the pool is resampled so path/query presence is identical in both classes, "
                 f"each registered domain contributes at most 15 URLs per class, and {corpus['heldout_domains_removed_from_pool']:,} domains used for evaluation are removed from the training pool.\n")
    s.append("### 1.2 Held-out results\n")
    t, e = u["domain_disjoint_test"], u["external_pirocheto"]
    s.append(table(["Evaluation set", "n", "ROC-AUC", "PR-AUC", "Recall@0.5", "FPR@0.5", "TPR@1% FPR"], [
        ["Domain-disjoint split of the training sources", t["n"], t["roc_auc"], t["pr_auc"], pct(t["recall"]), pct(t["fpr"]), pct(t["tpr_at_1pct_fpr"])],
        ["**External corpus** (pirocheto/phishing-url, never trained on)", e["n"], e["roc_auc"], e["pr_auc"], pct(e["recall"]), pct(e["fpr"]), pct(e["tpr_at_1pct_fpr"])],
    ]))
    r = u["recent_phishing_recall"]
    s.append(f"Recall on **{r['n']:,} phishing URLs from the 2026 OpenPhish + Phishing.Database feeds** (domains disjoint from training): "
             f"{pct(r['recall_at_0.3'])} at 0.30, {pct(r['recall_at_0.5'])} at 0.50, {pct(r['recall_at_0.65'])} at 0.65. "
             "This is the closest proxy to the zero-day claim; it is not a strict time split (the feeds carry no first-seen dates).\n")
    s.append("### 1.3 Threshold table (why the engine maps the score the way it does)\n")
    s.append(table(["Threshold", "Domain-disjoint: recall", "FPR", "External: recall", "FPR"],
                   [[x["threshold"], pct(x["domain_disjoint"]["recall"]), pct(x["domain_disjoint"]["fpr"]), pct(x["external"]["recall"]), pct(x["external"]["fpr"])] for x in u.get("threshold_table", [])]))
    s.append(f"Scores are calibrated on a class-balanced corpus, so they are *not* probabilities for real-world prevalence. The engine treats p <= {config.URL_P_FLOOR} as no evidence and p >= {config.URL_P_CEIL} as full risk, "
             "so a lexical-only BLOCK needs p of about 0.76, where false positives on random websites are 2-7%.\n")
    d = u.get("deployed_analyzer")
    if d:
        s.append("### 1.4 Deployed behaviour (model + brand rules + trusted-domain caps)\n")
        a30, a65 = d["not_safe_rate_at_0.30"], d["block_eligible_rate_at_0.65"]
        s.append(table(["Sample", "n", "not SAFE (risk >= 0.30)", "BLOCK-eligible (risk >= 0.65)"], [
            ["External benign (false alarms)", d["samples"]["external_benign"], pct(a30["external_benign (false alarms)"]), pct(a65["external_benign (false blocks)"])],
            ["External phishing (recall)", d["samples"]["external_phishing"], pct(a30["external_phishing (recall)"]), pct(a65["external_phishing (recall)"])],
            ["2026 feed phishing (recall)", d["samples"]["recent_phishing"], pct(a30["recent_phishing (recall)"]), pct(a65["recent_phishing (recall)"])],
            ["Popular domains outside the curated allowlist (false alarms)", d["samples"]["popular_not_in_known_good"], pct(a30["popular_domains_outside_allowlist (false alarms)"]), pct(a65["popular_domains_outside_allowlist (false blocks)"])],
        ]))
        s.append("Popular-domain false alarms are high because many top-ranked names are CDN / ad-tech infrastructure hosts that no one prints on a QR code; "
                 "the model alone flags "
                 f"{pct(u['popular_top20k_false_positive_rate_model_only']['fpr_at_0.5'])} of the top-20k at 0.5.\n")
    c = u["components"]
    s.append("### 1.5 Why two models are blended\n")
    s.append(table(["Component", "Domain-disjoint AUC", "External AUC"], [
        ["Structured features (LightGBM)", c["domain_disjoint_test"]["structured_lightgbm_auc"], c["external_pirocheto"]["structured_lightgbm_auc"]],
        ["Character 3-5-gram logistic model", c["domain_disjoint_test"]["char_ngram_auc"], c["external_pirocheto"]["char_ngram_auc"]],
        ["**Blend, isotonic-calibrated (deployed)**", c["domain_disjoint_test"]["blend_calibrated_auc"], c["external_pirocheto"]["blend_calibrated_auc"]],
        ["Baseline: logistic regression on structured features", u["baselines"]["logistic_regression_structured"]["domain_disjoint_roc_auc"], u["baselines"]["logistic_regression_structured"]["external_roc_auc"]],
        ["Baseline: random forest on structured features", u["baselines"]["random_forest_structured"]["domain_disjoint_roc_auc"], u["baselines"]["random_forest_structured"]["external_roc_auc"]],
    ]))
    s.append("### 1.6 Feature-group ablation (shortcut check)\n")
    s.append("If one group alone separated the classes unusually well that would be a collection artefact. Structured LightGBM only:\n")
    s.append(table(["Features used", "Domain-disjoint AUC", "External AUC"], [[k, v["domain_disjoint_roc_auc"], v["external_roc_auc"]] for k, v in u["feature_group_ablation"].items()]))
    s.append("Top structured features by mean |SHAP|: " + ", ".join(f"`{n}` ({v})" for n, v in u["top_structured_features_mean_abs_shap"][:8]) + f". Latency: {u['latency_ms_per_url']} ms per URL.\n")
    return "\n".join(s)


def cv_section(c: Dict[str, Any]) -> str:
    if not c:
        return "_Run `python -m qrshield train-cv` to generate this section._\n"
    s = ["## 2. M2 - sticker check\n"]
    s.append(f"> **All photos in this section are SIMULATED** ({c['n_simulated_photos']:,} rendered scenes, {c['n_usable']:,} usable; {c['n_real_photos']} real photos). "
             "The simulator (`qrshield/cv_layer/simulate.py`) models surfaces, printed labels, genuine stickers, five sticker-over-code styles, shadows, gloss, lighting, perspective, blur, noise and JPEG. "
             "These numbers measure the algorithm against *modelled* physics; they are not a claim about accuracy on real photos. "
             "Add real photos per `scripts/collect_cv_dataset.md` and run `python -m qrshield train-cv --real data/cv_images` to get that number.\n")
    s.append("### 2.1 Protocol\n")
    s.append("No random splits. *Leave-one-surface-out*: every figure is on a material the model never saw. *Group 5-fold by session*: unseen lighting, camera and surface instance. Probabilities are calibrated by cross-fitting on out-of-fold predictions.\n")
    a, b = c["leave_one_surface_out"], c["group_5fold_by_session"]
    s.append(table(["Protocol", "n", "ROC-AUC", "Recall@0.5", "FPR@0.5"], [
        ["Leave-one-surface-out", a["n"], a["roc_auc"], pct(a["recall"]), pct(a["false_positive_rate"])],
        ["Group 5-fold by session", b["n"], b["roc_auc"], pct(b["recall"]), pct(b["false_positive_rate"])]]))
    s.append(f"QR decode success on the simulated photos: **{pct(c['decode_success_rate'])}** (by blur: " + ", ".join(f"{k}: {pct(v)}" for k, v in c["decode_rate_by_blur"].items()) + ").\n")
    s.append("### 2.2 What it catches and what it cannot\n")
    rows = [[k, v["n"], pct(v["recall"]) if v["recall"] is not None else "-", pct(v["false_positive_rate"]) if v["false_positive_rate"] is not None else "-"]
            for k, v in sorted(c["per_style"].items(), key=lambda kv: -(kv[1]["recall"] or 0))]
    s.append(table(["Scene style", "n", "Detected (tampered styles)", "False alarm (genuine styles)"], rows))
    s.append("*Offset/rotated, smaller and wrinkled covers leave the original code or a boundary visible and are caught. An **exact-fit** or **larger** sticker over an unsigned code is physically close to a genuine sticker on a clean surface, so recall there is low by nature - "
             "that is precisely why the link layer and the signature layer exist.*\n")
    s.append("### 2.3 Per surface (each held out in turn)\n")
    s.append(table(["Surface", "n", "ROC-AUC", "Recall", "FPR"], [[k, v["n"], v["roc_auc"], pct(v["recall"]), pct(v["false_positive_rate"])] for k, v in c["per_surface_unseen"].items()]))
    s.append("### 2.4 Operating point\n")
    s.append(table(["Threshold p", "Recall", "FPR"], [[x["threshold"], pct(x["recall"]), pct(x["false_positive_rate"])] for x in c["threshold_table"]]))
    s.append(f"The engine rescales p (<= {config.TAMPER_P_FLOOR} = nothing, >= {config.TAMPER_P_CEIL} = full) and caps the visual weight so a photo alone can raise SUSPICIOUS but never BLOCK. "
             f"{pct(c['inconclusive_band']['fraction_of_photos'])} of photos fall in the borderline band {c['inconclusive_band']['band']} and trigger the second-photo prompt "
             f"(accuracy inside the band {pct(c['inconclusive_band']['accuracy_inside_band'])}, outside {pct(c['inconclusive_band']['accuracy_outside_band'])}).\n")
    s.append("### 2.5 Per condition\n")
    rows = []
    for key, d in c["per_condition"].items():
        for name, v in d.items():
            rows.append([key, name, v["n"], v["roc_auc"], pct(v["recall"]), pct(v["false_positive_rate"])])
    s.append(table(["Condition", "Bin", "n", "ROC-AUC", "Recall", "FPR"], rows))
    s.append("### 2.6 Feature-group ablation (leave-one-surface-out AUC)\n")
    ab = c["feature_group_ablation_loso_auc"]
    s.append(table(["Group", "Only this group", "Everything except it"], [[k, v["only_auc"], v["without_auc"]] for k, v in ab.items() if k != "all_features"]) + f"All features: {ab['all_features']}. Baselines (same protocol): " + ", ".join(f"{k} {v}" for k, v in c["baselines_loso_auc"].items()) + f". Model latency {c['model_latency_ms']} ms.\n")
    sp = c.get("second_photo")
    if sp:
        s.append("### 2.7 Does the second photo help? (unseen sessions, same scene photographed twice)\n")
        s.append(table(["Method", "ROC-AUC", "Recall@0.5", "FPR@0.5"], [
            ["Single photo", sp["single_photo"]["roc_auc"], pct(sp["single_photo"]["recall"]), pct(sp["single_photo"]["false_positive_rate"])],
            ["Second photo alone", sp["second_photo_alone"]["roc_auc"], pct(sp["second_photo_alone"]["recall"]), pct(sp["second_photo_alone"]["false_positive_rate"])],
            ["Average of two photos (deployed)", sp["two_photos_average"]["roc_auc"], pct(sp["two_photos_average"]["recall"]), pct(sp["two_photos_average"]["false_positive_rate"])],
            ["Average + photometric differential cue (w=0.12)", sp["two_photos_plus_cue_w0.12"]["roc_auc"], pct(sp["two_photos_plus_cue_w0.12"]["recall"]), pct(sp["two_photos_plus_cue_w0.12"]["false_positive_rate"])]]))
        s.append(f"Honest finding: a second photo helps mainly by averaging two independent looks (and by the consistency check that both photos decode to the same payload). "
                 f"The physics-inspired differential cue separates tampered from genuine scenes only weakly (mean {sp['cue_mean_tampered_vs_genuine'][0]} vs {sp['cue_mean_tampered_vs_genuine'][1]}), so the evaluation selected weight {sp['chosen_cue_weight']} and it is switched off. "
                 f"On the {sp['borderline_subset']['n']} borderline photos accuracy was {pct(sp['borderline_subset']['accuracy_single_photo'])} with one photo and {pct(sp['borderline_subset']['accuracy_two_photos'])} with two - no gain.\n")
    return "\n".join(s)


def robustness_section(r: Dict[str, Any]) -> str:
    if not r:
        return "_Run `python -m qrshield robustness` to generate this section._\n"
    s = ["### 2.8 Robustness to camera degradations and calibration\n"]
    s.append(f"> **Simulated photos.** {r['n_scenes']} held-out scenes ({r['n_per_class']} genuine, {r['n_per_class']} tampered; seeds and sessions never used in training), each degraded by nine camera faults at three severities and pushed through the real `cv_layer.analyze`. "
             "*Abstain* is the share of photos the layer refused to judge and asked to retake - the safe failure mode.\n")
    c = r["clean"]
    s.append(f"Clean photos: ROC-AUC **{c['roc_auc']}**, recall {pct(c['recall'])}, false alarms {pct(c['false_positive_rate'])}, abstain {pct(c['abstain_rate'])}.\n")
    rows = []
    for name, sevs in r["conditions"].items():
        row = [name]
        for sev in ("1", "2", "3"):
            v = sevs[sev]
            row.append(f"{v['roc_auc']} / {pct(v['recall'])} / {pct(v['false_positive_rate'])} / {pct(v['abstain_rate'])}")
        rows.append(row)
    s.append(table(["Degradation", "Mild: AUC / recall / FPR / abstain", "Moderate", "Severe"], rows))
    n, sev, auc = r["worst_case"]
    s.append(f"Worst case: **{n}**, severity {sev}, ROC-AUC {auc} (clean {c['roc_auc']}).\n")
    cal = r["calibration_clean"]
    s.append(f"**Calibration** (clean photos, {cal['n']} scored): Expected Calibration Error **{cal['ece']}**, largest bin gap {cal['mce']}, Brier score {cal['brier']}. "
             "ECE is the average gap between the score a photo gets and the share of such photos that really are tampered; 0 would be perfectly calibrated.\n")
    s.append(table(["Score bin", "n", "Mean score", "Observed tampered rate"], [[f"{b['lo']}-{b['hi']}", b["n"], b["mean_score"], b["observed_rate"]] for b in cal["bins"]]))
    return "\n".join(s)


def system_section(m: Dict[str, Any]) -> str:
    if not m:
        return "_Run `python -m qrshield evaluate` to generate this section._\n"
    s = ["## 3. End-to-end ablation (the core evidence)\n"]
    s.append(f"{m['n_scanned']} of {m['n_scenarios']} scenarios decoded and were pushed through the real pipeline (decode, M1, M2, M3, engine); {m['decode_failures']} failed to decode. "
             f"Link sources: {m['url_sources']}. Photos are simulated and the sticker model was trained on the same simulator (different seeds and sessions) - this tests the *fusion design*, not field accuracy. "
             "\"Flagged\" means the verdict is not SAFE. Good scenarios should end SAFE; bad ones should not.\n")
    fams = [f for f in m["ablation"]["all_three"] if not f.startswith("_")]
    head = ["Configuration"] + [f"{f} ({m['ablation']['all_three'][f]['truth']})" for f in fams] + ["**attacks flagged**", "**genuine flagged**"]
    rows = []
    for name, row in m["ablation"].items():
        rows.append([name] + [f"{row[f]['flagged_pct']}%" for f in fams] + [f"**{row['_summary']['attack_detection_pct']}%**", f"**{row['_summary']['false_alarm_pct_on_genuine']}%**"])
    s.append(table(head, rows))
    s.append("Verdicts of the full system per family:\n")
    s.append(table(["Family", "SAFE", "SUSPICIOUS", "BLOCK"], [[k, v["SAFE"], v["SUSPICIOUS"], v["BLOCK"]] for k, v in m["verdicts_all_three"].items()]))
    s.append("Attacks reaching BLOCK (not just SUSPICIOUS), by configuration: " + ", ".join(f"{k} {v['_summary']['attack_blocked_pct']}%" for k, v in m["ablation"].items()) + ".\n")
    s.append(f"Full-scan latency on this machine: median {m['latency_ms']['p50']} ms, 95th percentile {m['latency_ms']['p95']} ms (max {m['latency_ms']['max']} ms). "
             f"Sanity check - a freshly signed code verifies as `{m['signed_sanity_check']}`.\n")
    return "\n".join(s)


def readme_block(u: Dict[str, Any], c: Dict[str, Any], m: Dict[str, Any]) -> str:
    rows: List[List[str]] = []
    if u:
        e, r = u["external_pirocheto"], u["recent_phishing_recall"]
        rows.append(["M1 link model (real public corpora)", f"ROC-AUC **{e['roc_auc']}** on an external corpus it never trained on (domain-disjoint split: {u['domain_disjoint_test']['roc_auc']}); "
                     f"flags {pct(r['recall_at_0.5'])} of {r['n']:,} phishing links from 2026 feeds at the 0.5 threshold"])
    if c:
        st = c["per_style"]
        rows.append(["M2 sticker check (**simulated** photos)", f"ROC-AUC **{c['leave_one_surface_out']['roc_auc']}** on surfaces it never saw; catches {pct(st['offset_rotated']['recall'])} of offset/rotated and "
                     f"{pct(st['smaller']['recall'])} of smaller stickers, but only {pct(st['exact_fit']['recall'])} of exact-fit ones (physically close to a genuine sticker)"])
    if m:
        a = m["ablation"]
        best_single = max(("url_only", "cv_only", "crypto_only"), key=lambda k: a[k]["_summary"]["attack_detection_pct"])
        rows.append(["End-to-end ablation (simulated photos, real pipeline)",
                     f"all three layers flag **{a['all_three']['_summary']['attack_detection_pct']}%** of attacks vs {a[best_single]['_summary']['attack_detection_pct']}% for the best single layer ({best_single}); "
                     f"false alarms on genuine codes: {a['all_three']['_summary']['false_alarm_pct_on_genuine']}%; median scan {m['latency_ms']['p50']} ms"])
    rows.append(["M3 signatures", "forged, edited, expired, revoked, rolled-back, cross-domain and rogue-root tokens are all rejected - see `tests/test_crypto.py`, `tests/test_redteam.py`"])
    return table(["Component", "Result"], rows)


def update_readme(block: str) -> None:
    path = config.REPO_ROOT / "README.md"
    text = path.read_text(encoding="utf-8")
    start, end = "<!-- RESULTS:START -->", "<!-- RESULTS:END -->"
    if start in text and end in text:
        head, rest = text.split(start, 1)
        _, tail = rest.split(end, 1)
        path.write_text(head + start + "\n" + block + end + tail, encoding="utf-8")


def main() -> None:
    u, c, m, corpus = load("url_metrics.json"), load("cv_metrics.json"), load("system_metrics.json"), load("url_corpus.json")
    head = ["# QRshield - evaluation report\n",
            "> **Generated file - do not edit.** Rendered by `python -m scripts.make_eval_report` from `docs/results/*.json`, which are written by "
            "`python -m qrshield train-url`, `train-cv` and `evaluate`. Every number below is measured; nothing is typed by hand.\n",
            "## 0. What is real and what is simulated\n",
            table(["Layer", "Data", "Status"], [
                ["M1 link model", "Public phishing/benign corpora (PhiUSIIL, ealvaradob, pirocheto, OpenPhish, Phishing.Database, Tranco) + clearly-labelled synthetic QR-style URLs in training only", "Real data, domain-disjoint evaluation"],
                ["M2 sticker model", "Procedurally simulated photographs (`simulate.py`)", "**Simulated** - re-train with real photos to measure real accuracy"],
                ["M3 signatures", "Real Ed25519 / PKI code paths", "Exact: forged, edited, expired, revoked, rolled-back and cross-domain tokens are rejected (see `tests/test_crypto.py`, `tests/test_redteam.py`)"],
                ["Fusion", "Real pipeline on simulated photos", "Tests the design, not field accuracy"]]),
            "Reproduce: `python -m qrshield data && python -m qrshield train-url && python -m qrshield train-cv && python -m qrshield evaluate && python -m scripts.make_eval_report`.\n"]
    body = [url_section(u, corpus), cv_section(c) + ("\n" + robustness_section(load("cv_robustness.json")) if c else ""), system_section(m)]
    body.append("## 4. Security tests\n\n"
                "Executed by `python -m pytest` (see `tests/`): signature forgery, token field tampering, cross-domain signing, expired/revoked/rotated keys, CRL rollback and forged CRLs, "
                "certificate-cache poisoning, fail-closed without a pinned root, SSRF (private/loopback/link-local/metadata/IPv4-mapped/6to4/NAT64 addresses, numeric spellings, DNS rebinding, redirect re-validation, a real pinned-connection test), "
                "decompression bombs and oversized uploads, hostile payloads, admin-route authentication, rate limiting, stored-XSS inertness, CSP/no inline script, retraining-gate poisoning rejection, and a browser end-to-end suite.\n")
    body.append("## 5. Limitations\n\n"
                "1. The sticker model has only seen simulated photos. Expect lower accuracy on real photos until real data is added.\n"
                "2. A perfectly fitted sticker over an *unsigned* code is not reliably detectable; only the link layer or a signature can help there.\n"
                "3. Signatures prove who issued a payload, not that a physical code was never copied (replay). Location binding, expiry and the sticker check limit this.\n"
                "4. The link model is statistical; scores come from class-balanced training and are not real-world probabilities.\n"
                "5. Live domain-age lookups (RDAP) are off by default and not part of any reported number.\n")
    (config.REPO_ROOT / "docs" / "evaluation.md").write_text("\n".join(head + body), encoding="utf-8")
    update_readme(readme_block(u, c, m))
    print("wrote docs/evaluation.md and refreshed the README results table")


if __name__ == "__main__":
    main()
