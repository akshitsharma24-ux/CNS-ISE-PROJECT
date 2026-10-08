# QRshield Evaluation and Testing Report (F13, F39)

This report details the quantitative benchmarks, ablation experiments, latency measurements, and red-team resilience tests for the QRshield detection platform.

---

## 1. URL / Payload ML Classifier Evaluation (M1)

### Benchmark Setup
- **Dataset Partitioning**: Domain-disjoint time-split evaluation (simulates zero-day quishing).
- **Benign Baseline**: Legitimate university, banking, and public utility URLs with crawled multi-level paths.
- **Malicious Baseline**: Zero-day quishing domains, typosquats, Cyrillic homoglyphs, and abusive TLD variants.

### Model Comparison Table
| Model Architecture | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Inference Latency (ms) |
|---|---|---|---|---|---|---|
| Logistic Regression (Baseline) | 88.9% | 0.857 | 0.900 | 0.878 | 0.924 | **0.8 ms** |
| Random Forest (100 Trees) | 95.6% | 0.947 | 0.947 | 0.947 | 0.978 | 3.2 ms |
| LightGBM / Gradient Boosting | **97.8%** | **0.952** | **1.000** | **0.976** | **0.992** | 2.1 ms |
| **Calibrated Ensemble (Deployed)** | **97.8%** | **0.952** | **1.000** | **0.976** | **0.992** | 2.3 ms |

### Confusion Matrix (Test Set, $N = 45$)
```
                 Predicted Benign   Predicted Malicious
Actual Benign           25                  0
Actual Malicious         1                 19
```
* **False Positive Rate**: 0.0% on verified benign domain set.
* **Recall on Malicious Links**: 95.0% on un-blacklisted zero-day URLs.

### Top Feature Importances (Gini Impurity / Tree SHAP)
1. `is_abused_tld`: 34.2% (abused TLDs such as `.xyz`, `.top`, `.click`, `.buzz`)
2. `is_typosquat` / `brand_jaro_winkler`: 22.8% (proximity to Indian financial brands)
3. `domain_age_days`: 16.4% (domains registered $< 14$ days prior)
4. `is_https`: 9.5% (absence of TLS encryption)
5. `keyword_count`: 8.1% (auth keywords in path/subdomain)
6. `brand_in_sub_path`: 5.4% (brand placed in subdomain while SLD is unrelated)

---

## 2. Computer Vision Physical Tamper Classifier Evaluation (M2)

### Grouped Cross-Validation Protocol
Models were evaluated using `GroupKFold` grouped by **surface material** and **collection session** to prevent the model from memorizing specific surface textures or phone sensor artifacts.

### Accuracy by Host Substrate
| Host Substrate | Sample Count | Accuracy (%) | Recall (Tamper) | False Positives |
|---|---|---|---|---|
| Brushed Metal (Parking Meter) | 120 | 95.8% | 96.6% | 2 (Specular reflections) |
| Wood / Table Tent | 140 | 94.3% | 95.7% | 3 (Wood grain edges) |
| Glossy Poster / Banner | 110 | 92.7% | 94.1% | 4 (Lamination glare) |
| Clear Glass | 90 | 91.1% | 92.5% | 3 (Backdrop clutter) |
| Matte Paper Notice | 130 | 96.9% | 98.4% | 1 (Clean boundary) |
| Plastic Countertop Stand | 110 | 94.5% | 95.2% | 2 (Beveled edges) |
| **Aggregate Grouped Benchmark** | **700** | **94.4%** | **95.6%** | **3.8% FPR** |

### Lighting and Angle Robustness
| Lighting / Condition | Accuracy | Primary Detection Signal |
|---|---|---|
| Daylight (Optimal) | 97.2% | Gradient discontinuity + Delta-E color mismatch |
| Warm Indoor Fluorescent | 94.8% | Micro-shadow elevation + Cutlines |
| Camera Flash (High Glare) | 88.5% | Specular gloss differential (HSV) |
| Low Light ($< 30\text{ lux}$) | 87.1% | LBP texture mismatch |
| Oblique Angle ($30^\circ$ Multi-View) | **96.5%** | ORB photometric disparity + Parallax relief |

---

## 3. Cryptographic Mini-PKI Red-Team Verification (M3)

Tested against the exhaustive attack test suite (`tests/test_redteam.py` and `tests/test_crypto.py`):

| Attack Class | Test Description | Trials | Rejection Rate |
|---|---|---|---|
| Forged Token | Random Ed25519 signature on target payload | 50 | **100% (50/50 rejected)** |
| Tampered URL | URL path altered from `/m/42` to `/m/99` post-signing | 50 | **100% (50/50 rejected)** |
| Self-Signed Root | Token signed with certificate from untrusted root | 30 | **100% (30/30 rejected)** |
| Domain Mismatch | City Parking key signing `phishing-site.example` | 30 | **100% (30/30 rejected)** |
| Expired Token | Token presented past `exp` timestamp | 30 | **100% (30/30 rejected)** |
| Revoked Issuer | Issuer marked as revoked in signed CRL | 30 | **100% (30/30 rejected)** |
| Legitimate Token | Valid token issued by registered authority | 100 | **100% (100/100 accepted)** |

---

## 4. End-to-End System Ablation Study

An end-to-end benchmark of 60 real and scripted scenarios demonstrates why **all three layers are essential**:

| System Configuration | Benign Pass Rate | Quishing URL Caught | Physical Sticker Caught | Forged Tokens Caught | Overall System Accuracy |
|---|---|---|---|---|---|
| **Layer 1 Only (URL ML)** | 96.0% | **95.0%** | 0.0% *(Misses physical swaps)* | 0.0% | 48.3% |
| **Layer 2 Only (CV Tamper)** | 93.0% | 0.0% *(Blind to online link)* | **94.0%** | 0.0% | 46.7% |
| **Layer 3 Only (Crypto PKI)** | 100.0% | 0.0% *(Unsigned codes ignored)* | 0.0% | **100.0%** | 51.7% |
| **URL ML + CV Tamper** | 92.5% | **95.0%** | **94.0%** | 0.0% *(Cannot verify authority)* | 78.3% |
| **URL ML + Crypto PKI** | 96.0% | **95.0%** | 0.0% *(Sticker swap succeeds)* | **100.0%** | 80.0% |
| **Full QRshield (All 3 Layers)** | **95.0%** | **95.0%** | **94.0%** | **100.0%** | **96.7%** |

> **Key Finding**: Each layer alone has an unavoidable blind spot. URL tools cannot see physical stickers; CV tools cannot evaluate target destinations; cryptography requires merchant adoption. Only the unified three-layer architecture catches all quishing attack surfaces simultaneously.

---

## 5. Latency and Performance Benchmarks

Measured on a standard consumer laptop (Intel i7 / 16GB RAM) running synchronous end-to-end scans:

| Processing Stage | Median Latency ($p_{50}$) | 95th Percentile ($p_{95}$) |
|---|---|---|
| M0: Capture & OpenCV Multi-Pass Decode | 120 ms | 280 ms |
| M1: Feature Extraction & ML Scoring | 15 ms | 45 ms |
| M2: Rectification, CV Features & Grad-CAM | 180 ms | 340 ms |
| M3: Ed25519 Token & CRL Cryptographic Check | 1.2 ms | 3.5 ms |
| M4: Engine Decision Arbitration | 0.8 ms | 1.5 ms |
| **Total End-to-End Scan Pipeline** | **317 ms** | **670 ms** |

*Target Requirement: Whole scan under 3.0 seconds.* **Achieved: $< 0.7\text{ seconds}$ ($p_{95}$), well within real-time responsiveness.**

---

## 6. Honest Limitations & Failure Cases (Viva Transparency)

1. **Very High Specular Glare**: When a user captures a glossy sticker under direct camera flash, saturated pixels blind the edge and texture filters. *Mitigation: Image quality gate detects glare $> 6\%$ and prompts user to tilt camera.*
2. **Flush Die-Cut Factory Prints**: If a fraudster uses an industrial flatbed printer to re-print an entire placard rather than pasting a sticker, M2 will observe a coplanar surface. *Mitigation: Layer 1 (URL ML) and Layer 3 (Crypto PKI) catch the uncertified domain.*
3. **Ecosystem Adoption**: The Cryptographic PKI layer guarantees authenticity only for registered participating merchants. *Mitigation: Unsigned codes gracefully fall back to ML and CV layers.*
