# QRshield - evaluation report

> **Generated file - do not edit.** Rendered by `python -m scripts.make_eval_report` from `docs/results/*.json`, which are written by `python -m qrshield train-url`, `train-cv` and `evaluate`. Every number below is measured; nothing is typed by hand.

## 0. What is real and what is simulated

| Layer | Data | Status |
|---|---|---|
| M1 link model | Public phishing/benign corpora (PhiUSIIL, ealvaradob, pirocheto, OpenPhish, Phishing.Database, Tranco) + clearly-labelled synthetic QR-style URLs in training only | Real data, domain-disjoint evaluation |
| M2 sticker model | Procedurally simulated photographs (`simulate.py`) | **Simulated** - re-train with real photos to measure real accuracy |
| M3 signatures | Real Ed25519 / PKI code paths | Exact: forged, edited, expired, revoked, rolled-back and cross-domain tokens are rejected (see `tests/test_crypto.py`, `tests/test_redteam.py`) |
| Fusion | Real pipeline on simulated photos | Tests the design, not field accuracy |

Reproduce: `python -m qrshield data && python -m qrshield train-url && python -m qrshield train-cv && python -m qrshield evaluate && python -m scripts.make_eval_report`.

## 1. M1 - link model (real public corpora)

### 1.1 The corpora are biased - and in opposite directions

A model trained on raw phishing corpora learns *how the data was collected*, not phishing. Share of URLs that carry a path / a query string, by class:

| Source | has path (benign / phishing) | has query (benign / phishing) |
|---|---|---|
| ealvaradob | 87.6% / 44.9% | 12.0% / 11.5% |
| phiusiil | 0.0% / 27.1% | 0.0% / 6.1% |
| **all raw sources pooled** | 66.9% / 41.2% | 9.1% / 10.3% |
| **after shape-balancing (used for training)** | 44.1% / 44.1% | 6.9% / 6.9% |

In PhiUSIIL no benign URL has a path, so "has a path" alone separates the classes; in ealvaradob the bias runs the other way. Mitigations: scheme and `www.` are not features, the pool is resampled so path/query presence is identical in both classes, each registered domain contributes at most 15 URLs per class, and 36,366 domains used for evaluation are removed from the training pool.

### 1.2 Held-out results

| Evaluation set | n | ROC-AUC | PR-AUC | Recall@0.5 | FPR@0.5 | TPR@1% FPR |
|---|---|---|---|---|---|---|
| Domain-disjoint split of the training sources | 18193 | 0.9425 | 0.9476 | 81.0% | 7.4% | 65.4% |
| **External corpus** (pirocheto/phishing-url, never trained on) | 11237 | 0.9434 | 0.9405 | 87.1% | 14.8% | 54.8% |

Recall on **20,277 phishing URLs from the 2026 OpenPhish + Phishing.Database feeds** (domains disjoint from training): 97.0% at 0.30, 90.5% at 0.50, 88.2% at 0.65. This is the closest proxy to the zero-day claim; it is not a strict time split (the feeds carry no first-seen dates).

### 1.3 Threshold table (why the engine maps the score the way it does)

| Threshold | Domain-disjoint: recall | FPR | External: recall | FPR |
|---|---|---|---|---|
| 0.3 | 91.1% | 23.8% | 95.0% | 28.8% |
| 0.4 | 85.7% | 13.4% | 91.9% | 20.7% |
| 0.5 | 81.0% | 7.4% | 87.1% | 14.8% |
| 0.6 | 78.5% | 5.4% | 84.7% | 12.6% |
| 0.7 | 74.2% | 3.2% | 80.5% | 8.8% |
| 0.8 | 71.9% | 2.3% | 77.8% | 6.7% |
| 0.9 | 64.9% | 0.9% | 66.8% | 2.7% |

Scores are calibrated on a class-balanced corpus, so they are *not* probabilities for real-world prevalence. The engine treats p <= 0.45 as no evidence and p >= 0.9 as full risk, so a lexical-only BLOCK needs p of about 0.76, where false positives on random websites are 2-7%.

### 1.4 Deployed behaviour (model + brand rules + trusted-domain caps)

| Sample | n | not SAFE (risk >= 0.30) | BLOCK-eligible (risk >= 0.65) |
|---|---|---|---|
| External benign (false alarms) | 2500 | 12.7% | 7.7% |
| External phishing (recall) | 2500 | 84.8% | 77.4% |
| 2026 feed phishing (recall) | 2500 | 88.2% | 82.3% |
| Popular domains outside the curated allowlist (false alarms) | 2500 | 25.3% | 16.4% |

Popular-domain false alarms are high because many top-ranked names are CDN / ad-tech infrastructure hosts that no one prints on a QR code; the model alone flags 27.2% of the top-20k at 0.5.

### 1.5 Why two models are blended

| Component | Domain-disjoint AUC | External AUC |
|---|---|---|
| Structured features (LightGBM) | 0.898 | 0.8891 |
| Character 3-5-gram logistic model | 0.9379 | 0.9269 |
| **Blend, isotonic-calibrated (deployed)** | 0.9425 | 0.9434 |
| Baseline: logistic regression on structured features | 0.8311 | 0.804 |
| Baseline: random forest on structured features | 0.8866 | 0.8892 |

### 1.6 Feature-group ablation (shortcut check)

If one group alone separated the classes unusually well that would be a collection artefact. Structured LightGBM only:

| Features used | Domain-disjoint AUC | External AUC |
|---|---|---|
| all_structured | 0.8952 | 0.8894 |
| host_only (structure+brand) | 0.7984 | 0.7281 |
| path_query_only | 0.7915 | 0.8371 |
| brand_only | 0.6159 | 0.5166 |
| without_brand | 0.8941 | 0.9025 |

Top structured features by mean |SHAP|: `tld_abused` (0.577), `subdomain_depth` (0.452), `path_depth` (0.37), `path_entropy` (0.328), `path_len` (0.32), `tld_len` (0.317), `host_digits` (0.238), `long_token_len` (0.214). Latency: 3.86 ms per URL.

## 2. M2 - sticker check

> **All photos in this section are SIMULATED** (4,800 rendered scenes, 4,706 usable; 0 real photos). The simulator (`qrshield/cv_layer/simulate.py`) models surfaces, printed labels, genuine stickers, five sticker-over-code styles, shadows, gloss, lighting, perspective, blur, noise and JPEG. These numbers measure the algorithm against *modelled* physics; they are not a claim about accuracy on real photos. Add real photos per `scripts/collect_cv_dataset.md` and run `python -m qrshield train-cv --real data/cv_images` to get that number.

### 2.1 Protocol

No random splits. *Leave-one-surface-out*: every figure is on a material the model never saw. *Group 5-fold by session*: unseen lighting, camera and surface instance. Probabilities are calibrated by cross-fitting on out-of-fold predictions.

| Protocol | n | ROC-AUC | Recall@0.5 | FPR@0.5 |
|---|---|---|---|---|
| Leave-one-surface-out | 4706 | 0.8805 | 74.2% | 11.4% |
| Group 5-fold by session | 4706 | 0.9021 | 71.2% | 9.1% |

QR decode success on the simulated photos: **99.7%** (by blur: <0.5: 99.8%, 0.5-1.2: 99.7%, >1.2: 99.5%).

### 2.2 What it catches and what it cannot

| Scene style | n | Detected (tampered styles) | False alarm (genuine styles) |
|---|---|---|---|
| offset_rotated | 539 | 99.1% | - |
| smaller | 551 | 97.8% | - |
| wrinkled | 340 | 76.8% | - |
| exact_fit | 514 | 47.5% | - |
| larger | 373 | 38.1% | - |
| framed_card | 317 | - | 10.4% |
| genuine_sticker | 641 | - | 18.4% |
| laminated_print | 413 | - | 11.1% |
| printed_direct | 199 | - | 0.0% |
| printed_flat | 819 | - | 9.3% |

*Offset/rotated, smaller and wrinkled covers leave the original code or a boundary visible and are caught. An **exact-fit** or **larger** sticker over an unsigned code is physically close to a genuine sticker on a clean surface, so recall there is low by nature - that is precisely why the link layer and the signature layer exist.*

### 2.3 Per surface (each held out in turn)

| Surface | n | ROC-AUC | Recall | FPR |
|---|---|---|---|---|
| cardboard | 585 | 0.9143 | 73.0% | 3.0% |
| glass | 591 | 0.8545 | 74.9% | 16.0% |
| glossy_poster | 586 | 0.8623 | 81.5% | 23.8% |
| matte_paper | 589 | 0.8981 | 84.1% | 22.0% |
| metal | 595 | 0.8797 | 63.7% | 1.3% |
| painted_wall | 585 | 0.8912 | 73.1% | 13.2% |
| plastic | 583 | 0.9237 | 77.8% | 3.7% |
| wood | 592 | 0.8325 | 66.1% | 8.3% |

### 2.4 Operating point

| Threshold p | Recall | FPR |
|---|---|---|
| 0.3 | 83.6% | 28.2% |
| 0.4 | 76.6% | 15.3% |
| 0.5 | 74.2% | 11.4% |
| 0.6 | 66.9% | 6.1% |
| 0.7 | 61.8% | 3.8% |
| 0.8 | 58.9% | 2.4% |
| 0.9 | 54.0% | 1.6% |

The engine rescales p (<= 0.4 = nothing, >= 0.95 = full) and caps the visual weight so a photo alone can raise SUSPICIOUS but never BLOCK. 10.0% of photos fall in the borderline band [0.38, 0.62] and trigger the second-photo prompt (accuracy inside the band 58.9%, outside 84.0%).

### 2.5 Per condition

| Condition | Bin | n | ROC-AUC | Recall | FPR |
|---|---|---|---|---|---|
| qr_px | <250 | 1231 | 0.8639 | 71.6% | 12.8% |
| qr_px | 250-400 | 1935 | 0.8783 | 73.6% | 9.6% |
| qr_px | >400 | 1540 | 0.8974 | 77.3% | 12.6% |
| exposure | dark<0.8 | 1070 | 0.8754 | 74.0% | 10.7% |
| exposure | mid | 1817 | 0.876 | 73.5% | 14.1% |
| exposure | bright>1.05 | 1819 | 0.8868 | 75.1% | 9.2% |
| tilt | low | 2060 | 0.8829 | 73.5% | 11.3% |
| tilt | mid | 2646 | 0.8789 | 74.8% | 11.5% |

### 2.6 Feature-group ablation (leave-one-surface-out AUC)

| Group | Only this group | Everything except it |
|---|---|---|
| edges | 0.8584 | 0.8507 |
| shadow | 0.7632 | 0.8751 |
| colour | 0.5804 | 0.8823 |
| texture | 0.7091 | 0.8846 |
| specular | 0.608 | 0.8858 |
| peeking_code | 0.7468 | 0.8838 |
| frames | 0.6952 | 0.8834 |
All features: 0.8805. Baselines (same protocol): logistic_regression 0.8038, random_forest 0.8848, lightgbm 0.8805. Model latency 0.28 ms.

### 2.7 Does the second photo help? (unseen sessions, same scene photographed twice)

| Method | ROC-AUC | Recall@0.5 | FPR@0.5 |
|---|---|---|---|
| Single photo | 0.894 | 77.5% | 12.3% |
| Second photo alone | 0.8906 | 74.8% | 12.3% |
| Average of two photos (deployed) | 0.9035 | 73.4% | 9.4% |
| Average + photometric differential cue (w=0.12) | 0.8972 | 76.6% | 12.8% |

Honest finding: a second photo helps mainly by averaging two independent looks (and by the consistency check that both photos decode to the same payload). The physics-inspired differential cue separates tampered from genuine scenes only weakly (mean 0.3864 vs 0.2833), so the evaluation selected weight 0.0 and it is switched off. On the 62 borderline photos accuracy was 66.1% with one photo and 66.1% with two - no gain.

## 3. End-to-end ablation (the core evidence)

306 of 310 scenarios decoded and were pushed through the real pipeline (decode, M1, M2, M3, engine); 4 failed to decode. Link sources: real corpora (pirocheto benign + 2026 phishing feeds) + synthetic local-business. Photos are simulated and the sticker model was trained on the same simulator (different seeds and sessions) - this tests the *fusion design*, not field accuracy. "Flagged" means the verdict is not SAFE. Good scenarios should end SAFE; bad ones should not.

| Configuration | genuine_unsigned (good) | genuine_signed (good) | phishing_url (bad) | sticker_over_unsigned (bad) | sticker_over_signed (bad) | forged_token (bad) | rogue_issuer (bad) | **attacks flagged** | **genuine flagged** |
|---|---|---|---|---|---|---|---|---|---|
| url_only | 3.3% | 0.0% | 93.2% | 5.0% | 0.0% | 0.0% | 0.0% | **28.0%** | **2.0%** |
| cv_only | 5.0% | 10.3% | 6.8% | 53.3% | 60.0% | 0.0% | 10.5% | **30.0%** | **7.1%** |
| crypto_only | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% | 100.0% | **23.2%** | **0.0%** |
| url+cv | 8.3% | 10.3% | 93.2% | 56.7% | 60.0% | 0.0% | 10.5% | **55.6%** | **9.1%** |
| url+crypto | 3.3% | 0.0% | 93.2% | 5.0% | 0.0% | 100.0% | 100.0% | **51.2%** | **2.0%** |
| cv+crypto | 5.0% | 7.7% | 6.8% | 53.3% | 60.0% | 100.0% | 100.0% | **52.2%** | **6.1%** |
| all_three | 8.3% | 7.7% | 93.2% | 56.7% | 60.0% | 100.0% | 100.0% | **77.8%** | **8.1%** |

Verdicts of the full system per family:

| Family | SAFE | SUSPICIOUS | BLOCK |
|---|---|---|---|
| genuine_unsigned | 55 | 4 | 1 |
| genuine_signed | 36 | 3 | 0 |
| phishing_url | 4 | 1 | 54 |
| sticker_over_unsigned | 26 | 33 | 1 |
| sticker_over_signed | 16 | 24 | 0 |
| forged_token | 0 | 0 | 29 |
| rogue_issuer | 0 | 0 | 19 |

Attacks reaching BLOCK (not just SUSPICIOUS), by configuration: url_only 26.1%, cv_only 0.0%, crypto_only 23.2%, url+cv 26.6%, url+crypto 49.3%, cv+crypto 23.2%, all_three 49.8%.

Full-scan latency on this machine: median 97.4 ms, 95th percentile 112.9 ms (max 273.9 ms). Sanity check - a freshly signed code verifies as `valid`.

## 4. Security tests

Executed by `python -m pytest` (see `tests/`): signature forgery, token field tampering, cross-domain signing, expired/revoked/rotated keys, CRL rollback and forged CRLs, certificate-cache poisoning, fail-closed without a pinned root, SSRF (private/loopback/link-local/metadata/IPv4-mapped/6to4/NAT64 addresses, numeric spellings, DNS rebinding, redirect re-validation, a real pinned-connection test), decompression bombs and oversized uploads, hostile payloads, admin-route authentication, rate limiting, stored-XSS inertness, CSP/no inline script, retraining-gate poisoning rejection, and a browser end-to-end suite.

## 5. Limitations

1. The sticker model has only seen simulated photos. Expect lower accuracy on real photos until real data is added.
2. A perfectly fitted sticker over an *unsigned* code is not reliably detectable; only the link layer or a signature can help there.
3. Signatures prove who issued a payload, not that a physical code was never copied (replay). Location binding, expiry and the sticker check limit this.
4. The link model is statistical; scores come from class-balanced training and are not real-world probabilities.
5. Live domain-age lookups (RDAP) are off by default and not part of any reported number.
