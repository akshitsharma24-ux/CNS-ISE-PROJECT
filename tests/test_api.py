"""The web API: pipeline, demo scenarios, admin protection, abuse limits, security headers."""
import io

import numpy as np
import pytest

from tests.conftest import encode

SCENARIO_EXPECT = {1: {"SAFE"}, 2: {"BLOCK"}, 3: {"SAFE"}, 4: {"SUSPICIOUS", "BLOCK"}, 5: {"BLOCK"}, 6: {"BLOCK"}}


def scan_scenario(client, n):
    img = client.get(f"/api/demo/scenario-image/{n}")
    assert img.status_code == 200 and img.headers["content-type"] == "image/jpeg"
    r = client.post("/api/scan", files={"image": (f"s{n}.jpg", img.content, "image/jpeg")})
    assert r.status_code == 200
    return r.json()


# ---------------------------------------------------------------- health & static
def test_health_reports_models_and_root(client):
    h = client.get("/api/health").json()
    assert h["status"] == "ok" and h["models"]["url"] != "none" and h["models"]["cv"] != "none" and h["root_public_key"]


def test_index_and_assets_served_with_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "QRshield" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
    for path in ("/js/main.js", "/css/app.css", "/img/favicon.svg"):
        assert client.get(path).status_code == 200
    assert client.get("/api/health").headers["cache-control"] == "no-store"


def test_no_inline_scripts_or_styles_in_the_page(client):
    html = client.get("/").text
    assert "<script>" not in html and " style=" not in html and "onclick=" not in html


# ---------------------------------------------------------------- demo scenarios through the real pipeline
@pytest.mark.slow
@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 6])
def test_demo_scenario_verdicts(client, n):
    data = scan_scenario(client, n)
    assert data["success"], data.get("error")
    assert data["decision"]["verdict"] in SCENARIO_EXPECT[n], (n, data["decision"], data["layers"]["cv_layer"]["score"])
    if n == 3:
        assert data["decision"]["certified"] and data["layers"]["crypto_layer"]["status"] == "valid"
    if n == 5:
        assert data["layers"]["crypto_layer"]["status"] == "invalid"
    if n == 4:
        assert data["layers"]["crypto_layer"]["status"] == "none" and data["layers"]["cv_layer"]["score"] > 0.5


@pytest.mark.slow
def test_response_contract(client):
    d = scan_scenario(client, 1)
    assert {"scan_id", "payload", "payload_type", "quality", "decision", "layers", "timings_ms", "elapsed_ms", "models"} <= set(d)
    assert {"verdict", "risk", "certified", "reasons", "breakdown"} <= set(d["decision"])
    assert set(d["layers"]) == {"url_layer", "cv_layer", "crypto_layer"}
    assert set(d["timings_ms"]) >= {"decode", "url", "visual", "crypto", "engine"}


@pytest.mark.slow
def test_scan_explain_returns_the_occlusion_map_only_on_request(client):
    img = client.get("/api/demo/scenario-image/4").content
    plain = client.post("/api/scan", files={"image": ("s4.jpg", img, "image/jpeg")}).json()
    assert "saliency" not in plain["layers"]["cv_layer"]["details"]
    d = client.post("/api/scan?explain=true", files={"image": ("s4.jpg", img, "image/jpeg")}).json()
    sal = d["layers"]["cv_layer"]["details"]["saliency"]
    assert sal["png_b64"].startswith("data:image/png;base64,") and isinstance(sal["hot_spot"], bool)
    assert sal["peak"] > 0.0, "blanking regions of a tampered photo must move the model at least a little"
    assert d["decision"]["verdict"] == plain["decision"]["verdict"]


def test_revocation_changes_the_verdict_live(client):
    assert scan_scenario(client, 3)["decision"]["verdict"] == "SAFE"
    r = client.post("/api/admin/issuers/citypark-01/revoke", json={"reason": "test"}, headers=client.admin)
    assert r.status_code == 200
    after = scan_scenario(client, 3)
    assert after["layers"]["crypto_layer"]["status"] == "revoked" and after["decision"]["verdict"] == "BLOCK"
    assert client.post("/api/admin/issuers/citypark-01/restore", headers=client.admin).status_code == 200
    assert scan_scenario(client, 3)["decision"]["verdict"] == "SAFE"


def test_text_only_check(client):
    r = client.post("/api/check", json={"payload": "https://secure-phonepe-refund.xyz/claim-cashback"}).json()
    assert r["decision"]["verdict"] == "BLOCK" and r["layers"]["cv_layer"]["status"] == "not_applicable" and r["text_only"]
    ok = client.post("/api/check", json={"payload": "https://spit.ac.in/departments/comps"}).json()
    assert ok["decision"]["verdict"] == "SAFE"


def test_signed_link_through_text_check_is_certified(client):
    signed = client.post("/api/admin/sign", headers=client.admin,
                         json={"issuer_id": "citypark-01", "url": "https://pay.citypark.example/m/7", "location_id": "m7", "validity_hours": 5}).json()
    assert signed["self_check"] == "valid" and signed["qr_png_base64"].startswith("data:image/png;base64,")
    d = client.post("/api/check", json={"payload": signed["signed_url"]}).json()
    assert d["decision"]["certified"] and d["layers"]["crypto_layer"]["issuer"]["location_id"] == "m7"
    # edit one character of the path: forged
    forged = signed["signed_url"].replace("/m/7", "/m/8")
    assert client.post("/api/check", json={"payload": forged}).json()["decision"]["verdict"] == "BLOCK"


def test_scan_of_generated_signed_qr_image(client):
    s = client.post("/api/admin/sign", headers=client.admin, json={"issuer_id": "spit-admit", "url": "https://spit.ac.in/admissions", "validity_hours": 0}).json()
    import base64
    png = base64.b64decode(s["qr_png_base64"].split(",", 1)[1])
    d = client.post("/api/scan", files={"image": ("q.png", png, "image/png")}).json()
    assert d["success"] and d["decision"]["certified"]


# ---------------------------------------------------------------- failure handling
def test_image_without_a_code_is_a_clean_failure(client):
    blank = encode(np.full((300, 300, 3), 180, np.uint8))
    r = client.post("/api/scan", files={"image": ("b.png", blank, "image/png")})
    assert r.status_code == 200 and r.json()["success"] is False and r.json()["error"]


def test_garbage_and_empty_uploads(client):
    assert client.post("/api/scan", files={"image": ("x.png", b"not an image", "image/png")}).json()["success"] is False
    assert client.post("/api/scan", files={"image": ("x.png", b"", "image/png")}).status_code == 400
    assert client.post("/api/scan").status_code == 422


def test_oversized_upload_is_rejected_early(client):
    r = client.post("/api/scan", files={"image": ("big.jpg", b"\xff\xd8" + b"\x00" * (9 * 1024 * 1024), "image/jpeg")})
    assert r.status_code == 413


def test_decompression_bomb_over_http(client):
    from PIL import Image
    buf = io.BytesIO()
    Image.new("L", (9000, 9000), 255).save(buf, format="PNG")
    r = client.post("/api/scan", files={"image": ("bomb.png", buf.getvalue(), "image/png")})
    assert r.status_code == 200 and r.json()["success"] is False


@pytest.mark.parametrize("payload", ["http://[x", "http://", "javascript:alert(1)", "\u0000\u0001", "A" * 4000, "http://a b.c/\n\r",
                                     "<script>alert(1)</script>", "upi://pay", "WIFI:;;", "' OR 1=1 --"])
def test_hostile_payloads_never_cause_a_500(client, payload):
    r = client.post("/api/check", json={"payload": payload})
    assert r.status_code in (200, 422)
    if r.status_code == 200:
        assert r.json()["decision"]["verdict"] in ("SAFE", "SUSPICIOUS", "BLOCK")


@pytest.mark.slow
def test_a_crashing_layer_degrades_conservatively_instead_of_failing(client, monkeypatch):
    import qrshield.app.api as api_mod

    def boom(*a, **k):
        raise RuntimeError("simulated layer crash")

    img = client.get("/api/demo/scenario-image/1").content
    monkeypatch.setattr(api_mod, "analyze_cv", boom)
    d = client.post("/api/scan", files={"image": ("s.jpg", img, "image/jpeg")}).json()
    assert d["success"] and d["layers"]["cv_layer"]["status"] == "low_quality" and d["decision"]["verdict"] == "SAFE"
    monkeypatch.setattr(api_mod, "analyze_url", boom)
    d = client.post("/api/scan", files={"image": ("s.jpg", img, "image/jpeg")}).json()
    assert d["success"] and d["decision"]["verdict"] != "SAFE" and any(
        s["name"] == "layer_failed" for s in d["layers"]["url_layer"]["signals"]), "a crashed link analysis must not read as safe"
    signed = client.post("/api/admin/sign", headers=client.admin,
                         json={"issuer_id": "citypark-01", "url": "https://pay.citypark.example/m/9", "validity_hours": 1}).json()["signed_url"]
    monkeypatch.setattr(api_mod, "verify_crypto", boom)
    d = client.post("/api/check", json={"payload": signed}).json()
    assert d["decision"]["verdict"] == "BLOCK" and not d["decision"]["certified"], "a crashed verifier must never certify"


def test_request_validation(client):
    assert client.post("/api/check", json={"payload": ""}).status_code == 422
    assert client.post("/api/check", json={"payload": "x" * 5000}).status_code == 422
    assert client.post("/api/report", json={"payload": "https://x.example", "user_label": "spam"}).status_code == 422


# ---------------------------------------------------------------- reporting & admin protection
def test_report_flow_with_admin_review(client):
    r = client.post("/api/report", json={"payload": "https://paytm-kyc-update.top/x", "user_label": "phishing",
                                         "note": "<img src=x onerror=alert(1)>", "verdict": "SAFE"})
    assert r.status_code == 200
    rid = r.json()["report_id"]
    pending = client.get("/api/admin/reports?status=pending", headers=client.admin).json()
    assert pending[0]["report_id"] == rid and pending[0]["note"] == "<img src=x onerror=alert(1)>"   # stored verbatim, rendered as text by the UI
    assert client.post(f"/api/admin/reports/{rid}/review", json={"action": "approve"}, headers=client.admin).json()["status"] == "approved"
    assert client.get("/api/admin/reports?status=approved", headers=client.admin).json()[0]["report_id"] == rid


ADMIN_ROUTES = [
    ("get", "/api/admin/session"), ("get", "/api/admin/overview"), ("get", "/api/admin/reports"), ("get", "/api/admin/models"),
    ("get", "/api/admin/audit"), ("post", "/api/admin/retrain"), ("post", "/api/admin/demo/reset"),
    ("post", "/api/admin/issuers/citypark-01/revoke"), ("post", "/api/admin/issuers/citypark-01/restore"),
    ("post", "/api/admin/issuers/citypark-01/rotate"),
]


@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
def test_admin_routes_require_the_token(client, method, path):
    r = getattr(client, method)(path)
    assert r.status_code == 401
    wrong = getattr(client, method)(path, headers={"X-Admin-Token": "nope"})
    assert wrong.status_code == 401


def test_register_and_sign_require_admin_and_validate(client):
    body = {"issuer_id": "evil-corp", "name": "Evil Corp", "domain": "sbi.co.in"}
    assert client.post("/api/admin/issuers", json=body).status_code == 401
    ok = client.post("/api/admin/issuers", json=body, headers=client.admin)
    assert ok.status_code == 200                           # an admin may register; the point is that nobody else can
    assert client.post("/api/admin/issuers", json={**body, "issuer_id": "bad-tld", "domain": "com"}, headers=client.admin).status_code == 400
    assert client.post("/api/admin/issuers", json=body, headers=client.admin).status_code == 409
    assert client.post("/api/admin/sign", json={"issuer_id": "nobody", "url": "https://x.example/a"}, headers=client.admin).status_code == 404


def test_public_registry_endpoints_expose_no_secrets(client):
    blob = client.get("/api/registry/issuers").text + client.get("/api/registry/crl").text + client.get("/api/registry/root").text \
        + client.get("/api/registry/issuers/citypark-01/cert").text + client.get("/api/health").text
    assert "private" not in blob.lower() and "admin" not in blob.lower().replace("administr", "")
    assert client.get("/api/registry/issuers/ghost/cert").status_code == 404


def test_rate_limits(client):
    codes = [client.post("/api/report", json={"payload": "https://x.example/a", "user_label": "benign"}).status_code for _ in range(14)]
    assert codes[:12] == [200] * 12 and 429 in codes[12:]
    r = client.post("/api/report", json={"payload": "https://x.example/a", "user_label": "benign"})
    assert r.status_code == 429 and "Retry-After" in r.headers


def test_models_endpoint_and_stats(client):
    m = client.get("/api/admin/models", headers=client.admin).json()
    assert m["active"]["url"] != "none" and "history" in m and m["retrain"]["running"] is False
    client.post("/api/check", json={"payload": "https://spit.ac.in/"})
    st = client.get("/api/admin/overview", headers=client.admin).json()["stats"]
    assert "scans_total" in st


def test_results_endpoint_serves_generated_metrics_only(client):
    r = client.get("/api/results")
    assert r.status_code == 200 and isinstance(r.json(), dict)
