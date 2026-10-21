"""Shared fixtures. Every test gets an isolated runtime home, registry and trust store."""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def make_qr(data: str, box: int = 8, border: int = 4) -> np.ndarray:
    """BGR image of a QR code (white background)."""
    import cv2
    import qrcode
    q = qrcode.QRCode(box_size=box, border=border, error_correction=qrcode.constants.ERROR_CORRECT_M)
    q.add_data(data)
    q.make(fit=True)
    return cv2.cvtColor(np.array(q.make_image().convert("RGB")), cv2.COLOR_RGB2BGR)


def encode(img: np.ndarray, ext: str = ".png", quality: int = 92) -> bytes:
    import cv2
    params = [cv2.IMWRITE_JPEG_QUALITY, quality] if ext == ".jpg" else []
    ok, buf = cv2.imencode(ext, img, params)
    assert ok
    return buf.tobytes()


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("QRSHIELD_HOME", str(tmp_path / "qrs_home"))
    monkeypatch.setenv("QRSHIELD_ADMIN_TOKEN", "test-admin-token")
    monkeypatch.setenv("QRSHIELD_ONLINE_CHECKS", "0")          # tests never touch the network
    return tmp_path / "qrs_home"


@pytest.fixture()
def registry(home):
    from qrshield.crypto_layer import TrustStore
    from qrshield.registry import Registry

    reg = Registry(home=home, trust_store=TrustStore())
    reg.ensure_ready(seed_demo=True)
    yield reg
    reg.close()


@pytest.fixture()
def client(home):
    """A TestClient against an isolated app instance (own registry, trust store, rate limiter)."""
    from fastapi.testclient import TestClient
    from qrshield.app.api import create_app
    from qrshield.crypto_layer import TrustStore

    app = create_app(home=home, trust_store=TrustStore())
    with TestClient(app) as c:
        c.admin = {"X-Admin-Token": "test-admin-token"}
        c.app_ref = app
        yield c
