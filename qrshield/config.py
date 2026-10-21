"""
Central configuration: filesystem layout and tunable thresholds.

Runtime state (registry DB, private keys, admin token, retrained models) lives in a
single "home" directory that is NEVER committed. Override with QRSHIELD_HOME.
Trained model artefacts that ship with the repo live in qrshield/models/.
"""
from __future__ import annotations

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parent
BUNDLED_MODELS_DIR = PACKAGE_DIR / "models"
STATIC_DIR = PACKAGE_DIR / "app" / "static"
DATA_DIR = REPO_ROOT / "data"


def home_dir() -> Path:
    """Runtime state directory (created on demand)."""
    path = Path(os.environ.get("QRSHIELD_HOME", REPO_ROOT / ".qrshield")).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---- upload / abuse limits ---------------------------------------------------
MAX_UPLOAD_BYTES = 8 * 1024 * 1024          # 8 MB per image
MAX_IMAGE_PIXELS = 40_000_000               # reject decompression bombs before decoding
MAX_PAYLOAD_CHARS = 4096                    # longest QR payload we will analyse
MAX_NOTE_CHARS = 500

# ---- URL score -> decision-scale risk (chosen from the threshold table in docs/evaluation.md) ----
# Calibrated phishing probability p is rescaled: p <= URL_P_FLOOR contributes nothing, p >= URL_P_CEIL is
# full risk. With these values a pure-lexical BLOCK needs p ~ 0.76, where false positives on random
# websites are 2-7%, while weaker evidence lands in SUSPICIOUS instead of blocking.
URL_P_FLOOR = 0.45
URL_P_CEIL = 0.90

# ---- tamper score -> decision-scale risk (threshold table in docs/evaluation.md) ----
# Visual evidence below p=0.40 contributes nothing; with TAMPER_WEIGHT it needs p >= ~0.68 to reach SUSPICIOUS,
# where the leave-one-surface-out false-positive rate is ~4-5% (vs ~11% at p = 0.5).
TAMPER_P_FLOOR = 0.40
TAMPER_P_CEIL = 0.95

# ---- engine thresholds (tuned on validation data, see docs/evaluation.md) ----
SAFE_BELOW = 0.30
BLOCK_FROM = 0.65
URL_WEIGHT = 0.95            # a in the noisy-OR fusion
TAMPER_WEIGHT = 0.60         # b: visual evidence alone must never reach BLOCK
TAMPER_WEIGHT_INCONCLUSIVE = 0.35
AGREEMENT_FLOOR = 0.85       # two independent layers agree -> at least this risk
