# CV Physical Tamper Dataset Collection Protocol

## 1. Objective & Target Distribution
To train and evaluate the visual tamper classifier (M2) against real-world physical quishing sticker overlays (replacement stickers on parking meters, table tents, posters, and retail stands).

Target sample size: **800 labeled photos** (400 genuine baseline, 400 tampered sticker overlays).

---

## 2. Experimental Rig & Physical Setup

### Host Surfaces (Minimum 6 diverse substrates)
1. **Rough Wood / Table Tent** (cafe tables, restaurant menus)
2. **Brushed Metal** (parking meters, EV charging kiosks)
3. **Glossy Laminated Poster** (metro stations, event banners)
4. **Matte Paper** (bulletin boards, notice sheets)
5. **Clear Glass / Window** (storefront doors, bus stops)
6. **Textured Plastic / Acrylic** (countertop payment stands)

### Sticker Materials (3 types)
- **Matte Sticker Paper** (inkjet/laser cut)
- **High-Gloss Vinyl Sticker** (die-cut commercial finish)
- **Standard 80 GSM Paper + Double-Sided Adhesive Tape**

### Tamper Overlays (Attack Variants)
- **Exact Fit**: Sticker matches dimensions of original QR code (0mm margin).
- **Sub-Size (Peeking Code)**: Sticker is 3–5mm smaller, leaving fragments of original modules visible.
- **Over-Size**: Sticker overlaps beyond the original quiet zone onto the surrounding substrate.
- **Skewed / Rotated**: Pasted with 2° to 8° angular rotation.
- **Wrinkled / Air Bubbles**: Hand-pasted with slight surface lift.

### Hard Negatives (Crucial for Non-Trivial Evaluation)
- Legitimate factory-printed stickers stuck on clean surfaces (e.g. UPI soundbox stickers).
- Laminated legitimate QR standees.
- **Examiner Defence**: Without hard negatives, the classifier would memorize *sticker = bad*; hard negatives ensure it evaluates *overlay boundary discontinuity and multi-layer relief*.

---

## 3. Metadata CSV Logging Schema (`data/cv_images/metadata.csv`)

| Field | Type | Description | Values / Examples |
|---|---|---|---|
| `image_id` | String | Unique file identifier | `IMG_2026_0102.jpg` |
| `class_label` | Integer | Binary ground truth | `0` = Genuine, `1` = Tampered |
| `session_id` | String | Collection batch ID | `SPIT_LIB_SESSION_01` |
| `surface` | String | Host substrate material | `wood`, `metal`, `glossy_poster`, `glass`, `plastic`, `matte_paper` |
| `sticker_material` | String | Substrate of pasted code | `none`, `matte_paper`, `glossy_vinyl`, `laminated` |
| `phone_model` | String | Capture device | `Pixel 7`, `iPhone 14`, `Samsung S22` |
| `lighting` | String | Ambient lighting condition | `daylight`, `warm_indoor_fluorescent`, `camera_flash`, `dim_low_light` |
| `angle_deg` | Integer | Camera angle relative to normal | `0` (perpendicular), `30` (oblique view) |
| `tamper_style` | String | Physical application style | `none`, `exact_fit`, `peeking_fragment`, `skewed`, `oversized` |

---

## 4. Evaluation & Grouped Cross-Validation Rule
- **Never perform random K-fold splits across the CV dataset.** Random splits cause data leakage by letting the model memorize a specific table grain or phone camera sensor noise.
- **Always use `GroupKFold` grouped by `surface` and `session_id`.** This tests the model's ability to detect physical stickers on completely unseen physical surfaces and lighting setups.
