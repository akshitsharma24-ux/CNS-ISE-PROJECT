"""
The six live-demo scenarios from the master plan (Section 13).

Each scenario is a *simulated photograph* rendered with qrshield.cv_layer.simulate, using real
payloads: signed tokens come from the registry, so scanning them exercises the genuine crypto path.
They exist so the UI can be demonstrated (and regression-tested) without props; the real demo uses
printed codes and a phone camera - see scripts/make_demo_assets.py.
"""
from __future__ import annotations

import threading
from typing import Any, Dict, List

import cv2

from qrshield.cv_layer.simulate import render_scene
from qrshield.registry import Registry

SCENARIOS: List[Dict[str, Any]] = [
    {"id": 1, "title": "Ordinary college QR", "short": "Clean unsigned", "expected": "SAFE",
     "story": "A normal poster QR pointing at the college website. Normal codes must never be blocked.",
     "layers": "all layers low"},
    {"id": 2, "title": "Fresh phishing link", "short": "Phishing zero-day", "expected": "BLOCK",
     "story": "A new PhonePe look-alike domain that appears on no blocklist. A blocklist would pass it; the classifier does not need it to be known.",
     "layers": "M1: typosquat + abused TLD"},
    {"id": 3, "title": "Signed City Parking code", "short": "Signed & certified", "expected": "SAFE",
     "story": "A parking-meter code signed by the registered business. The signature, certificate chain and domain binding all verify.",
     "layers": "M3: valid Ed25519 signature"},
    {"id": 4, "title": "Sticker over the parking code", "short": "Sticker swap", "expected": "SUSPICIOUS",
     "story": "A clean-looking sticker pasted over the real signed code. A URL-only scanner sees nothing wrong; the photo shows the pasted edge.",
     "layers": "M2: sticker edge + hidden code; M3: not certified"},
    {"id": 5, "title": "Forged signed token", "short": "Forged token", "expected": "BLOCK",
     "story": "Someone copied a signed code and edited the path after signing. The signature no longer matches the content.",
     "layers": "M3: signature invalid"},
    {"id": 6, "title": "KYC scam (report it)", "short": "Feedback loop", "expected": "BLOCK",
     "story": "A KYC phishing code to report. Reports go to the admin queue; only approved ones can ever feed retraining.",
     "layers": "M1 + feedback loop"},
]

_CACHE: Dict[tuple, bytes] = {}
_LOCK = threading.Lock()

SIGNED_URL = "https://pay.citypark.example/m/42"


def _signed(registry: Registry) -> str:
    return registry.sign_for_issuer("citypark-01", SIGNED_URL, "andheri-west-meter-04", validity_hours=72,
                                    allow_revoked=True)["signed_url"]


def _spec(n: int, registry: Registry) -> Dict[str, Any]:
    if n == 1:
        return dict(seed=611, label=0, surface="matte_paper", style="printed_flat", payload="https://spit.ac.in/departments/comps")
    if n == 2:
        return dict(seed=612, label=0, surface="glossy_poster", style="printed_flat",
                    payload="https://secure-phonepe-refund.xyz/claim-cashback?amt=2000")
    if n == 3:
        return dict(seed=613, label=0, surface="metal", style="printed_flat", payload=_signed(registry))
    if n == 4:
        return dict(seed=614, label=1, surface="metal", style="smaller", payload="https://citypark.example/m/42",
                    under_payload=_signed(registry))
    if n == 5:
        return dict(seed=615, label=0, surface="wood", style="framed_card", payload=_signed(registry).replace("/m/42", "/m/99"))
    return dict(seed=616, label=0, surface="plastic", style="printed_flat",
                payload="https://paytm-kyc-update.top/wallet/kyc-verification.php")


def scenario_image(registry: Registry, n: int) -> bytes:
    """JPEG bytes of scenario `n` (1-6). Signed scenarios are re-signed at most once per process."""
    if not 1 <= n <= 6:
        raise ValueError("scenario must be 1..6")
    cert = registry.get_certificate("citypark-01") or {}
    key = (n, registry.root_public_key_b64, cert.get("kid"))      # re-render after a key rotation
    with _LOCK:
        if key in _CACHE:
            return _CACHE[key]
    spec = _spec(n, registry)
    scene = render_scene(spec.pop("seed"), session=n, **spec)
    ok, buf = cv2.imencode(".jpg", scene.image, [cv2.IMWRITE_JPEG_QUALITY, 92])
    data = buf.tobytes()
    with _LOCK:
        _CACHE[key] = data
    return data
