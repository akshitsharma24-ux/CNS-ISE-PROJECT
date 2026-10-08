"""
QRshield Main Application and FastAPI Endpoints (M5).
Provides:
  - POST /api/scan (Image upload, M0 decode, parallel layer checks, M4 fusion)
  - POST /api/report (Quishing & false positive feedback reporting)
  - GET /api/reports (Admin review queue)
  - POST /api/reports/{id}/review (Admin approve/reject)
  - POST /api/generate-signed-qr (Issuer portal generation tool)
  - Static frontend delivery
"""
import os
import io
import time
import uuid
import hashlib
import cv2
import numpy as np
from typing import Optional, List
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import qrcode
from PIL import Image


from qrshield.capture import capture_and_decode
from qrshield.url_layer import analyze as analyze_url
from qrshield.cv_layer import analyze as analyze_cv
from qrshield.crypto_layer import verify as verify_crypto, sign_url_token, load_private_key_b64
from qrshield.engine import decide
from qrshield.registry.api import registry_router
from qrshield.registry.admin import (
    sync_all_certificates_to_verifier,
    SessionLocal,
    IssuerRecord,
    ScanReport
)

app = FastAPI(
    title="QRshield: Quishing & Tamper Detection Platform",
    description="Three-layer detector: URL ML + CV Physical Tamper + Ed25519 Signed QR",
    version="1.0.0"
)

# Enable CORS for cross-device mobile testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include registry router
app.include_router(registry_router)

# Mount static directory for single-page app
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR, exist_ok=True)

@app.on_event("startup")
def startup_event():
    """Initializes database and caches certificates on application boot."""
    sync_all_certificates_to_verifier()

@app.post("/api/scan")
async def api_scan(
    image: UploadFile = File(...),
    image2: Optional[UploadFile] = File(None)
):
    """
    Main Scan Pipeline:
    1. M0: Decodes QR, assesses blur/glare/quality, detects stacked codes.
    2. Runs M1 (URL ML), M2 (CV Tamper), M3 (Crypto) in coordinated pipeline.
    3. M4: Fuses all signals with rule-first noisy-OR aggregation.
    """
    start_time = time.time()
    img_bytes = await image.read()
    if not img_bytes:
        raise HTTPException(status_code=400, detail="Empty image uploaded")

    img2_bytes = None
    if image2 is not None:
        img2_bytes = await image2.read()

    # Step 1: M0 Capture & Decode
    m0_res = capture_and_decode(img_bytes)
    if not m0_res["success"]:
        return JSONResponse(status_code=200, content={
            "success": False,
            "error": m0_res["error"],
            "quality": m0_res["quality"],
            "elapsed_ms": round((time.time() - start_time) * 1000, 1)
        })

    payload = m0_res["payload"]
    payload_type = m0_res["payload_type"]

    # Step 2: Layer Analysis
    # M1 URL / Payload ML
    url_res = analyze_url(payload, offline=True)

    # M2 Visual Tamper Detection (pass image bytes & optional second angle)
    cv_res = analyze_cv(img_bytes, img2=img2_bytes)

    # If multi-code stacked sticker flagged by M0, inject into CV signals
    if m0_res.get("multi_code"):
        cv_res["score"] = max(cv_res["score"], 0.88)
        cv_res["signals"].append({
            "name": "stacked_code_pattern",
            "value": True,
            "text": m0_res.get("multi_code_details", "Multiple overlapping QR modules detected.")
        })

    # M3 Crypto Layer Verification
    sig_res = verify_crypto(payload)

    # Step 3: M4 Aggregation Engine
    decision = decide(url_res, cv_res, sig_res)

    scan_id = str(uuid.uuid4())
    total_time = round((time.time() - start_time) * 1000, 1)

    return {
        "success": True,
        "scan_id": scan_id,
        "payload": payload,
        "payload_type": payload_type,
        "quality": m0_res["quality"],
        "decision": decision,
        "layers": {
            "url_layer": {
                "score": url_res["score"],
                "signals": url_res["signals"],
                "type": url_res["payload_type"]
            },
            "cv_layer": {
                "score": cv_res["score"],
                "status": cv_res["status"],
                "signals": cv_res["signals"],
                "heatmap_png_b64": cv_res.get("heatmap_png_b64")
            },
            "crypto_layer": {
                "status": sig_res["status"],
                "issuer": sig_res["issuer"]
            }
        },
        "elapsed_ms": total_time
    }

class ReportSubmission(BaseModel):
    scan_id: Optional[str] = None
    payload: str
    user_label: str  # 'phishing' | 'benign' | 'tampered'
    note: Optional[str] = ""

@app.post("/api/report")
def api_submit_report(rep: ReportSubmission):
    """
    Submits feedback report (F34) into SQLite review queue.
    Hashes payload with SHA-256 for privacy compliance.
    """
    db = SessionLocal()
    try:
        payload_hash = hashlib.sha256(rep.payload.encode("utf-8")).hexdigest()
        report_id = str(uuid.uuid4())
        rec = ScanReport(
            report_id=report_id,
            payload_hash=payload_hash,
            url=rep.payload,
            user_label=rep.user_label,
            note=rep.note,
            status="pending"
        )
        db.add(rec)
        db.commit()
        return {"success": True, "report_id": report_id, "message": "Feedback submitted for admin review."}
    finally:
        db.close()

@app.get("/api/reports")
def api_list_reports():
    """Admin endpoint to retrieve reported cases (F34)."""
    db = SessionLocal()
    try:
        rows = db.query(ScanReport).order_by(ScanReport.created_at.desc()).all()
        return [{
            "report_id": r.report_id,
            "url": r.url,
            "user_label": r.user_label,
            "note": r.note,
            "created_at": r.created_at,
            "status": r.status
        } for r in rows]
    finally:
        db.close()

class ReviewAction(BaseModel):
    action: str  # 'approve' | 'reject'

@app.post("/api/reports/{report_id}/review")
def api_review_report(report_id: str, action: ReviewAction):
    """Admin human-gate action approving or rejecting reported URL (F35)."""
    db = SessionLocal()
    try:
        rec = db.query(ScanReport).filter_by(report_id=report_id).first()
        if not rec:
            raise HTTPException(status_code=404, detail="Report not found")
        rec.status = "approved" if action.action == "approve" else "rejected"
        db.commit()
        return {"success": True, "status": rec.status}
    finally:
        db.close()

class GenerateQRRequest(BaseModel):
    url: str
    issuer_id: str
    issuer_private_key_b64: str
    location_id: Optional[str] = "counter-01"
    validity_hours: Optional[int] = 24

@app.post("/api/generate-signed-qr")
def api_generate_signed_qr(req: GenerateQRRequest):
    """
    Issuer Portal API (F27): Signs a business URL with Ed25519
    and returns a downloadable QR PNG image base64.
    """
    try:
        priv_key = load_private_key_b64(req.issuer_private_key_b64)
        now = int(time.time())
        exp = now + (req.validity_hours * 3600)

        signed_url, token = sign_url_token(
            url=req.url,
            private_key=priv_key,
            issuer_id=req.issuer_id,
            key_id="key-1",
            location_id=req.location_id,
            iat=now,
            exp=exp
        )

        # Generate QR PNG with Error Correction Level M
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4
        )
        qr.add_data(signed_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_bytes = buf.getvalue()

        import base64
        b64_qr = base64.b64encode(png_bytes).decode("ascii")

        return {
            "success": True,
            "signed_url": signed_url,
            "token": token,
            "qr_png_base64": f"data:image/png;base64,{b64_qr}"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/demo/scenario-image/{num}")
def api_demo_scenario_image(num: int):
    """Generates synthetic and realistic images for the 6 demo scenarios in Section 13."""
    from scripts.seed_registry import CITYPARK_PRIV_B64
    from qrshield.crypto_layer.token import sign_url_token

    def _render_qr(data: str) -> np.ndarray:
        qr = qrcode.QRCode(box_size=8, border=4)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        return cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)

    def _create_canvas(qr_bgr, bg_color=255):
        h, w = qr_bgr.shape[:2]
        pad = max(60, int(w * 0.25))
        canvas = np.ones((h + pad * 2, w + pad * 2, 3), dtype=np.uint8) * bg_color
        canvas[pad:pad+h, pad:pad+w] = qr_bgr
        return canvas, pad, pad, h, w

    if num == 1:
        # Scenario 1: Clean Unsigned College Website
        qr_bgr = _render_qr("https://spit.ac.in/departments/comps")
        canvas, _, _, _, _ = _create_canvas(qr_bgr, 255)
    elif num == 2:
        # Scenario 2: Fresh Phishing-Style QR (Lookalike Brand)
        qr_bgr = _render_qr("https://secure-phonepe-refund.xyz/claim-cashback?amt=2000")
        canvas, _, _, _, _ = _create_canvas(qr_bgr, 255)
    elif num == 3:
        # Scenario 3: Signed City Parking Code (Valid Ed25519)
        priv = load_private_key_b64(CITYPARK_PRIV_B64)
        now = int(time.time())
        signed_url, _ = sign_url_token(
            url="https://pay.citypark.example/m/42",
            private_key=priv,
            issuer_id="citypark-01",
            key_id="key-1",
            location_id="andheri-counter-04",
            iat=now,
            exp=now + 86400
        )
        qr_bgr = _render_qr(signed_url)
        canvas, _, _, _, _ = _create_canvas(qr_bgr, 255)
    elif num == 4:
        # Scenario 4: Physical Sticker Swap (Clean URL pasted over Parking Meter)
        qr_bgr = _render_qr("https://citypark.example/m/42")
        # Wooden/metallic backing surface
        canvas, pad_x, pad_y, h, w = _create_canvas(qr_bgr, 180)
        # Draw physical sticker backing with distinct paper color and shadow
        cv2.rectangle(canvas, (pad_x - 14, pad_y - 14), (pad_x + w + 16, pad_y + h + 16), (70, 70, 70), -1)  # micro-shadow
        cv2.rectangle(canvas, (pad_x - 12, pad_y - 12), (pad_x + w + 12, pad_y + h + 12), (255, 255, 240), -1)  # sticker paper
        canvas[pad_y:pad_y+h, pad_x:pad_x+w] = qr_bgr
    elif num == 5:
        # Scenario 5: Forged-token QR (URL edited or invalid signature)
        priv = load_private_key_b64(CITYPARK_PRIV_B64)
        now = int(time.time())
        signed_url, _ = sign_url_token(
            url="https://pay.citypark.example/m/42",
            private_key=priv,
            issuer_id="citypark-01",
            key_id="key-1",
            iat=now,
            exp=now + 86400
        )
        # Attacker tampered URL from /m/42 to /m/99
        tampered_url = signed_url.replace("/m/42", "/m/99")
        qr_bgr = _render_qr(tampered_url)
        canvas, _, _, _, _ = _create_canvas(qr_bgr, 255)
    else:
        # Scenario 6: Sample for feedback reporting
        qr_bgr = _render_qr("https://paytm-kyc-update.top/wallet/kyc-verification.php")
        canvas, _, _, _, _ = _create_canvas(qr_bgr, 255)

    _, encoded = cv2.imencode(".png", canvas)
    return Response(content=encoded.tobytes(), media_type="image/png")


# Mount static files for the single page web application
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")

