"""
Automated regression tests for the 6 Live Demo Scenarios from Section 13.
Guarantees that all demo scenarios produce the exact expected verdicts.
"""
import pytest
from fastapi.testclient import TestClient
from qrshield.app.api import app
from scripts.retrain import retrain_pipeline

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_scenario_1_clean_college_url(client):
    """Scenario 1: Ordinary unsigned genuine code (college website) -> SAFE (green)."""
    r = client.get("/api/demo/scenario-image/1")
    resp = client.post("/api/scan", files={"image": ("sc1.png", r.content, "image/png")})
    assert resp.status_code == 200
    dec = resp.json()["decision"]
    assert dec["verdict"] == "SAFE"
    assert dec["certified"] is False
    assert dec["risk"] < 0.30

def test_scenario_2_fresh_phishing_url(client):
    """Scenario 2: Fresh zero-day phishing link -> BLOCK (red), M1 fires."""
    r = client.get("/api/demo/scenario-image/2")
    resp = client.post("/api/scan", files={"image": ("sc2.png", r.content, "image/png")})
    assert resp.status_code == 200
    dec = resp.json()["decision"]
    assert dec["verdict"] == "BLOCK"
    assert dec["risk"] >= 0.65

def test_scenario_3_signed_city_parking(client):
    """Scenario 3: Signed City Parking code -> SAFE with Certified badge (green)."""
    r = client.get("/api/demo/scenario-image/3")
    resp = client.post("/api/scan", files={"image": ("sc3.png", r.content, "image/png")})
    assert resp.status_code == 200
    dec = resp.json()["decision"]
    assert dec["verdict"] == "SAFE"
    assert dec["certified"] is True

def test_scenario_4_sticker_swap_tamper(client):
    """Scenario 4: Physical sticker pasted over parking meter -> SUSPICIOUS or BLOCK."""
    r = client.get("/api/demo/scenario-image/4")
    resp = client.post("/api/scan", files={"image": ("sc4.png", r.content, "image/png")})
    assert resp.status_code == 200
    dec = resp.json()["decision"]
    assert dec["verdict"] in ("SUSPICIOUS", "BLOCK")

def test_scenario_5_forged_token_qr(client):
    """Scenario 5: Forged or URL-tampered token QR -> BLOCK (failed crypto)."""
    r = client.get("/api/demo/scenario-image/5")
    resp = client.post("/api/scan", files={"image": ("sc5.png", r.content, "image/png")})
    assert resp.status_code == 200
    dec = resp.json()["decision"]
    assert dec["verdict"] == "BLOCK"

def test_scenario_6_feedback_loop_and_retrain(client):
    """Scenario 6: Feedback report submission, admin review queue, and retrain gate."""
    # Submit feedback report
    r1 = client.post("/api/report", json={
        "payload": "https://paytm-kyc-update.top/wallet/kyc-verification.php",
        "user_label": "phishing",
        "note": "Reported from live test suite"
    })
    assert r1.status_code == 200
    rep_id = r1.json()["report_id"]

    # Review report
    r2 = client.post(f"/api/reports/{rep_id}/review", json={"action": "approve"})
    assert r2.status_code == 200
    assert r2.json()["status"] == "approved"

    # Retrain pipeline quality gate
    passed = retrain_pipeline()
    assert passed is True
