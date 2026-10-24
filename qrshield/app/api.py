"""
QRshield web API and single-page app (M5).

    uvicorn qrshield.app.api:app            # `app` is created lazily on first access
    create_app(home=...)                    # isolated instance (used by the tests)

Public routes   : /api/health, /api/scan, /api/check, /api/report, /api/registry/{root,crl,issuers,...},
                  /api/demo/*
Admin routes    : /api/admin/*   (header X-Admin-Token)
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Literal, Optional

import numpy as np
import qrcode
from fastapi import APIRouter, Depends, FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

import qrshield
from qrshield import config, model_store, monitoring, retrain
from qrshield.app import demo
from qrshield.app.security import RateLimiter, SecurityHeaders, limit, read_upload, require_admin
from qrshield.capture import capture_and_decode
from qrshield.crypto_layer import TrustStore, verify as verify_crypto
from qrshield.cv_layer import analyze as analyze_cv
from qrshield.engine import decide
from qrshield.registry import Registry, RegistryError
from qrshield.url_layer import analyze as analyze_url


def _py(obj: Any) -> Any:
    """Recursively convert numpy scalars/arrays so the response is plain JSON."""
    if isinstance(obj, dict):
        return {str(k): _py(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_py(v) for v in obj]
    if isinstance(obj, np.generic):
        return obj.item()
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj


# ----------------------------------------------------------------------------- request models
class CheckRequest(BaseModel):
    payload: str = Field(min_length=1, max_length=config.MAX_PAYLOAD_CHARS)


class ReportRequest(BaseModel):
    scan_id: Optional[str] = Field(None, max_length=64)
    payload: str = Field(min_length=1, max_length=config.MAX_PAYLOAD_CHARS)
    user_label: Literal["phishing", "benign", "tampered"]
    note: str = Field("", max_length=config.MAX_NOTE_CHARS)
    verdict: Optional[Literal["SAFE", "SUSPICIOUS", "BLOCK"]] = None


class ReviewRequest(BaseModel):
    action: Literal["approve", "reject"]


class RevokeRequest(BaseModel):
    reason: str = Field("key compromised", max_length=200)


class IssuerRequest(BaseModel):
    issuer_id: str = Field(min_length=2, max_length=63)
    name: str = Field(min_length=2, max_length=128)
    domain: str = Field(min_length=3, max_length=253)
    public_key_b64: Optional[str] = Field(None, max_length=64, description="Omit to let the registry generate and hold the key (demo custody)")


class SignRequest(BaseModel):
    issuer_id: str = Field(min_length=2, max_length=63)
    url: str = Field(min_length=8, max_length=1500)
    location_id: str = Field("counter-01", min_length=1, max_length=48)
    validity_hours: int = Field(48, ge=0, le=43800, description="0 = never expires")


class VerifyRequest(BaseModel):
    payload: str = Field(min_length=1, max_length=config.MAX_PAYLOAD_CHARS)


# ----------------------------------------------------------------------------- helpers
def _qr_png_data_uri(text: str, box: int = 10) -> str:
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=box, border=4)
    qr.add_data(text)
    qr.make(fit=True)
    buf = io.BytesIO()
    qr.make_image(fill_color="black", back_color="white").save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


log = logging.getLogger("qrshield")


def _timed(timings: Dict[str, float], name: str, fn, *args, **kwargs):
    t = time.perf_counter()
    out = fn(*args, **kwargs)
    timings[name] = round((time.perf_counter() - t) * 1000, 1)
    return out


def _guarded(timings: Dict[str, float], name: str, fn, fallback, *args, **kwargs):
    """Run one layer; if it ever crashes, degrade *conservatively* instead of failing the whole scan."""
    try:
        return _timed(timings, name, fn, *args, **kwargs)
    except Exception:
        log.exception("layer %s failed", name)
        timings[name] = -1.0
        return fallback


def _layers(url_res, cv_res, sig_res) -> Dict[str, Any]:
    return {
        "url_layer": {"score": url_res["score"], "type": url_res["payload_type"], "signals": url_res["signals"],
                      "details": url_res.get("details", {})},
        "cv_layer": {"score": cv_res["score"], "status": cv_res["status"], "signals": cv_res["signals"],
                     "heatmap_png_b64": cv_res.get("heatmap_png_b64"), "details": cv_res.get("details", {})},
        "crypto_layer": {"status": sig_res["status"], "issuer": sig_res.get("issuer"), "detail": sig_res.get("detail", "")},
    }


def run_scan(registry: Registry, img_bytes: bytes, img2_bytes: Optional[bytes], explain: bool = False) -> Dict[str, Any]:
    """The full pipeline: M0 decode -> M1/M2/M3 -> M4 fusion."""
    timings: Dict[str, float] = {}
    t0 = time.perf_counter()
    m0 = _timed(timings, "decode", capture_and_decode, img_bytes)
    if not m0["success"]:
        return {"success": False, "error": m0["error"], "quality": m0["quality"],
                "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1)}
    payload = m0["payload"]
    url_res = _guarded(timings, "url", analyze_url, {
        "score": 0.55, "payload_type": m0["payload_type"] if m0["payload_type"] in ("url", "upi") else "other",
        "signals": [{"name": "layer_failed", "value": None, "direction": "risk",
                     "text": "The link could not be analysed, so it is treated with caution."}], "details": {}}, payload)
    cv_res = _guarded(timings, "visual", analyze_cv, {
        "score": 0.0, "status": "low_quality", "heatmap_png_b64": None, "details": {},
        "signals": [{"name": "layer_failed", "value": None, "direction": "info", "text": "The visual check failed on this photo."}]},
        m0["image"], img2_bytes, m0["corners_np"], explain)
    if m0["multi_code"] and not any(s["name"] == "stacked_code_pattern" for s in cv_res["signals"]):
        cv_res["signals"].insert(0, {"name": "stacked_code_pattern", "value": True, "direction": "risk",
                                     "text": m0.get("multi_code_details") or "Two QR patterns overlap in the frame."})
        cv_res["score"] = max(cv_res["score"], 0.88)
    sig_res = _guarded(timings, "crypto", verify_crypto, {
        "status": "invalid" if "qrs=" in payload else "none", "issuer": None, "detail": "verification error - treated as failed"},
        payload, registry.store)
    decision = _timed(timings, "engine", decide, url_res, cv_res, sig_res)

    scan_id = str(uuid.uuid4())
    total = round((time.perf_counter() - t0) * 1000, 1)
    try:
        registry.log_scan(scan_id=scan_id, payload_hash=hashlib.sha256(payload.encode()).hexdigest(),
                          payload_type=url_res["payload_type"], verdict=decision["verdict"], risk=decision["risk"],
                          url_risk=url_res["score"], tamper_risk=cv_res["score"], sig_status=sig_res["status"], elapsed_ms=total)
    except Exception:
        pass                                              # telemetry must never break a scan
    return _py({
        "success": True, "scan_id": scan_id, "payload": payload, "payload_type": m0["payload_type"],
        "quality": m0["quality"], "codes_in_frame": m0["codes"], "decision": decision,
        "layers": _layers(url_res, cv_res, sig_res), "timings_ms": timings, "elapsed_ms": total,
        "models": {"url": model_store.active_version("url"), "cv": model_store.active_version("cv")},
    })


def run_check(registry: Registry, payload: str) -> Dict[str, Any]:
    """Text-only check (no photo): M1 + M3 + M4. The visual layer reports 'not_applicable'."""
    timings: Dict[str, float] = {}
    t0 = time.perf_counter()
    url_res = _guarded(timings, "url", analyze_url, {
        "score": 0.55, "payload_type": "other", "details": {},
        "signals": [{"name": "layer_failed", "value": None, "direction": "risk", "text": "The link could not be analysed, so it is treated with caution."}]}, payload)
    cv_res = {"score": 0.0, "status": "not_applicable", "signals": [], "heatmap_png_b64": None, "details": {}}
    sig_res = _guarded(timings, "crypto", verify_crypto, {
        "status": "invalid" if "qrs=" in payload else "none", "issuer": None, "detail": "verification error - treated as failed"},
        payload, registry.store)
    decision = _timed(timings, "engine", decide, url_res, cv_res, sig_res)
    from qrshield.capture.payload_types import parse_payload_type
    return _py({
        "success": True, "scan_id": str(uuid.uuid4()), "payload": payload, "payload_type": parse_payload_type(payload)[0],
        "quality": None, "codes_in_frame": [], "decision": decision, "layers": _layers(url_res, cv_res, sig_res),
        "timings_ms": timings, "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1), "text_only": True,
        "models": {"url": model_store.active_version("url"), "cv": model_store.active_version("cv")},
    })


# ----------------------------------------------------------------------------- app factory
def create_app(home: Optional[Path] = None, seed_demo: bool = True, trust_store: Optional[TrustStore] = None) -> FastAPI:
    registry = Registry(home=home, trust_store=trust_store)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        registry.ensure_ready(seed_demo=seed_demo)
        if not os.environ.get("QRSHIELD_ADMIN_TOKEN"):
            print(f"\n  QRshield admin token (Issuer Portal / Admin Queue): {registry.admin_token()}\n"
                  f"  (also stored in {registry.home / 'admin_token'})\n", flush=True)
        yield
        registry.close()

    app = FastAPI(title="QRshield", version=qrshield.__version__, lifespan=lifespan,
                  description="Scan, verify, then decide: URL ML + visual tamper detection + Ed25519 signed QR codes.")
    app.state.registry = registry
    app.state.limiter = RateLimiter()
    app.add_middleware(SecurityHeaders)

    @app.exception_handler(RegistryError)
    async def _registry_error(_: Request, exc: RegistryError):
        return JSONResponse(status_code=exc.status, content={"detail": str(exc)})

    api = APIRouter(prefix="/api")

    # ------------------------------------------------------------------ public
    @api.get("/health")
    def health():
        crl = registry.current_crl()
        return {"status": "ok", "version": qrshield.__version__,
                "models": {"url": model_store.active_version("url"), "cv": model_store.active_version("cv")},
                "root_public_key": registry.root_public_key_b64, "crl_version": crl["version"],
                "secure_context_hint": "Phone cameras need HTTPS; run `python -m qrshield serve --https`."}

    @api.post("/scan", dependencies=[limit("scan", 40)])
    async def scan(image: UploadFile = File(...), image2: Optional[UploadFile] = File(None),
                   explain: bool = Query(False, description="also compute the occlusion-sensitivity map (slower)")):
        data = await read_upload(image)
        if not data:
            raise HTTPException(status_code=400, detail="Empty image upload.")
        data2 = await read_upload(image2)
        return await run_in_threadpool(run_scan, registry, data, data2 or None, explain)

    @api.post("/check", dependencies=[limit("check", 120)])
    async def check(req: CheckRequest):
        return await run_in_threadpool(run_check, registry, req.payload.strip())

    @api.post("/report", dependencies=[limit("report", 12)])
    def report(req: ReportRequest):
        rid = registry.add_report(req.payload, req.user_label, req.note, req.verdict)
        return {"success": True, "report_id": rid, "message": "Thanks - your report is queued for human review."}

    @api.get("/results")
    def results():
        """Measured evaluation results (generated by `make evaluate`; nothing here is hand-written)."""
        out: Dict[str, Any] = {}
        for key, name in (("url", "url_metrics.json"), ("cv", "cv_metrics.json"), ("system", "system_metrics.json")):
            path = config.REPO_ROOT / "docs" / "results" / name
            if path.exists():
                out[key] = json.loads(path.read_text(encoding="utf-8"))
        return out

    @api.get("/registry/root")
    def registry_root():
        return {"public_key": registry.root_public_key_b64, "algorithm": "Ed25519",
                "note": "In a real deployment this key is pinned inside the app, not fetched."}

    @api.get("/registry/crl")
    def registry_crl():
        return registry.current_crl()

    @api.get("/registry/issuers")
    def registry_issuers():
        return [{k: i[k] for k in ("issuer_id", "name", "domain", "key_id", "is_revoked", "cert_valid_to")} for i in registry.list_issuers()]

    @api.get("/registry/issuers/{issuer_id}/cert")
    def registry_cert(issuer_id: str):
        cert = registry.get_certificate(issuer_id)
        if not cert:
            raise HTTPException(status_code=404, detail="Issuer not found")
        return cert

    @api.post("/registry/verify", dependencies=[limit("verify", 120)])
    def registry_verify(req: VerifyRequest):
        return verify_crypto(req.payload, registry.store)

    @api.get("/demo/scenarios")
    def demo_scenarios():
        return demo.SCENARIOS

    @api.get("/demo/scenario-image/{n}", dependencies=[limit("demo", 60)])
    async def demo_image(n: int):
        if not 1 <= n <= 6:
            raise HTTPException(status_code=404, detail="Scenario must be 1-6")
        data = await run_in_threadpool(demo.scenario_image, registry, n)
        return Response(content=data, media_type="image/jpeg", headers={"Cache-Control": "no-store"})

    @api.get("/demo/render-qr", dependencies=[limit("demo", 60)])
    def demo_render_qr(text: str = Query(min_length=1, max_length=config.MAX_PAYLOAD_CHARS)):
        data_uri = _qr_png_data_uri(text.strip(), box=8)
        return Response(content=base64.b64decode(data_uri.split(",", 1)[1]), media_type="image/png")

    # ------------------------------------------------------------------ admin
    admin = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])

    @admin.get("/session")
    def admin_session():
        return {"ok": True}

    @admin.get("/overview")
    def admin_overview():
        return {"stats": registry.stats(), "issuers": registry.list_issuers(), "crl": registry.current_crl(),
                "models": {"url": model_store.active_version("url"), "cv": model_store.active_version("cv")}}

    @admin.post("/issuers")
    def admin_register(req: IssuerRequest):
        cert = registry.register_issuer(req.issuer_id, req.name, req.domain, req.public_key_b64)
        return {"success": True, "certificate": cert}

    @admin.post("/issuers/{issuer_id}/revoke")
    def admin_revoke(issuer_id: str, req: RevokeRequest):
        crl = registry.revoke_issuer(issuer_id, req.reason)
        return {"success": True, "crl_version": crl["version"], "message": f"'{issuer_id}' revoked."}

    @admin.post("/issuers/{issuer_id}/restore")
    def admin_restore(issuer_id: str):
        crl = registry.restore_issuer(issuer_id)
        return {"success": True, "crl_version": crl["version"], "message": f"'{issuer_id}' restored."}

    @admin.post("/issuers/{issuer_id}/rotate")
    def admin_rotate(issuer_id: str):
        res = registry.rotate_issuer_key(issuer_id)
        return {"success": True, "crl_version": res["crl_version"], "certificate": res["certificate"]}

    @admin.post("/sign")
    def admin_sign(req: SignRequest):
        res = registry.sign_for_issuer(req.issuer_id, req.url, req.location_id, req.validity_hours)
        verdict = verify_crypto(res["signed_url"], registry.store)
        return {"success": True, "signed_url": res["signed_url"], "token": res["token"],
                "qr_png_base64": _qr_png_data_uri(res["signed_url"]), "self_check": verdict["status"],
                "payload_bytes": len(res["signed_url"].encode())}

    @admin.get("/reports")
    def admin_reports(status: Optional[Literal["pending", "approved", "rejected"]] = None):
        return registry.list_reports(status)

    @admin.post("/reports/{report_id}/review")
    def admin_review(report_id: str, req: ReviewRequest):
        return {"success": True, "status": registry.review_report(report_id, req.action)}

    @admin.get("/models")
    def admin_models():
        return {"active": {"url": model_store.active_version("url"), "cv": model_store.active_version("cv")},
                "history": registry.list_model_versions(), "retrain": retrain.status()}

    @admin.get("/model-health")
    async def admin_model_health():
        """Drift of recent link-risk scores against the benchmark reference (Population Stability Index)."""
        def _health():
            return monitoring.health(registry.recent_url_scores(), monitoring.reference_scores(registry.home))
        return await run_in_threadpool(_health)

    @admin.post("/retrain")
    def admin_retrain():
        started = retrain.run_in_background(registry)
        return {"success": True, "started": started, "message": "Retraining started." if started else "A retrain is already running."}

    @admin.get("/audit")
    def admin_audit():
        return registry.audit_log()

    @admin.post("/demo/reset")
    def admin_demo_reset():
        registry.reset_demo()
        return {"success": True, "crl_version": registry.current_crl()["version"]}

    api.include_router(admin)
    app.include_router(api)

    app.mount("/", StaticFiles(directory=str(config.STATIC_DIR), html=True), name="static")
    return app


def __getattr__(name: str):                      # `uvicorn qrshield.app.api:app` creates the app lazily
    if name == "app":
        global _APP
        try:
            return _APP
        except NameError:
            _APP = create_app()
            return _APP
    raise AttributeError(name)
