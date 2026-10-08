# QRshield Dataset Documentation (F18, F40)

This directory documents the data sources, synthetic generation pipelines, and experimental collection protocols utilized for training and validating the three layers of QRshield.

---

## 1. URL & Payload ML Datasets (M1)

### Public Sources Evaluated & Cited
1. **PhishTank Feed**: Real-time crowd-sourced phishing database ([phishtank.org](https://phishtank.org)).
2. **OpenPhish Community Feed**: Algorithmic zero-day phishing URL detection feed ([openphish.com](https://openphish.com)).
3. **Tranco Top-Sites**: Hardened top 1M ranking list resilient to manipulation ([tranco-list.eu](https://tranco-list.eu)).
4. **UCI PhiUSIIL Phishing Dataset**: High-quality benchmark for machine learning quishing and URL classification.
5. **ISCX-URL-2016**: UNB cybersecurity benchmark dataset for malicious and benign URLs.

### Data Hygiene & Leakage Prevention Strategy
* **Realistic Paths for Benign URLs**: Benign domains from Tranco only supply bare hostnames (e.g., `spit.ac.in`). If compared directly to phishing URLs containing deep paths, models fall into the *leakage trap* (learning "has a path = malicious"). We crawled and curated realistic deep benign paths for all reference domains.
* **Domain-Disjoint Time-Split Validation**: URLs are split strictly so that no registered domain appears simultaneously in the train and test partitions. This strictly evaluates zero-day quishing detection.

---

## 2. Computer Vision Physical Tamper Dataset (M2)

### Protocol
The dataset evaluates physical sticker quishing (e.g. malicious QR codes pasted over municipal parking meters, restaurant table tents, retail UPI standees, and college bulletin boards).

### Summary of Collected Sample Distribution
- **Genuine Baseline**: 400 images across 6 host surfaces (brushed metal, wood, clear glass, plastic acrylic, glossy posters, matte paper). Includes hard negatives (legitimate factory stickers).
- **Tampered Sticker Overlays**: 400 images featuring exact-fit stickers, sub-size stickers with peeking original code modules, skewed overlays, high-gloss stickers on matte surfaces, and hand-cut borders.

### Metadata Schema (`data/cv_images/metadata.csv`)
```csv
image_id,class_label,session_id,surface,sticker_material,phone_model,lighting,angle_deg,tamper_style
IMG_001.png,0,SESSION_01,metal,none,Pixel7,daylight,0,none
IMG_002.png,1,SESSION_01,metal,matte_paper,Pixel7,daylight,0,exact_fit
IMG_003.png,1,SESSION_02,wood,glossy_vinyl,iPhone14,indoor,30,peeking_fragment
```

### Reproducibility
A sample dataset of synthetic and physical benchmark images is stored in `data/cv_images/` for instant local unit test verification and continuous integration runs.
