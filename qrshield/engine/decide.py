"""
M4: aggregation and scoring engine (F30).

Rule first, score second:

  1. Cryptographic facts decide before any score is computed.
       valid                                -> SAFE + "certified" (downgraded to SUSPICIOUS if the
                                               sign physically looks pasted over)
       invalid / unknown_issuer / revoked /
       domain_mismatch                      -> BLOCK  (claiming authenticity it cannot prove is worse
                                               than being unsigned)
       expired                              -> at least SUSPICIOUS
  2. Unsigned codes (the common case) are fused with noisy-OR:
       risk = 1 - (1 - a*url_risk) * (1 - b*tamper_risk)
     The tamper probability is first rescaled (p <= 0.40 counts as nothing, p >= 0.95 as full risk) and
     visual evidence is deliberately capped (b < 0.65) so a photo alone can never BLOCK: it can only raise
     SUSPICIOUS. Two independent layers agreeing (url>0.5 and tamper>0.5) floors the risk at 0.85.
  3. Hard overrides: blocklist hit or dangerous scheme -> BLOCK; stacked codes, UPI payee mismatch and
     inconsistent two-photo decodes -> at least SUSPICIOUS.
"""
from __future__ import annotations

from typing import Any, Dict, List

from qrshield import config
from qrshield.engine.reasons import generate_reasons


def _names(res: Dict[str, Any]) -> set:
    return {s.get("name") for s in res.get("signals", []) if s.get("direction", "risk") == "risk"}


def _shape(p: float, floor: float, ceil: float) -> float:
    return min(max((p - floor) / (ceil - floor), 0.0), 1.0)


def _verdict_for(risk: float) -> str:
    if risk < config.SAFE_BELOW:
        return "SAFE"
    return "SUSPICIOUS" if risk < config.BLOCK_FROM else "BLOCK"


def _finish(verdict, risk, certified, url_res, cv_res, sig_res, overrides, breakdown):
    return {
        "verdict": verdict, "risk": round(float(min(max(risk, 0.0), 1.0)), 4), "certified": certified,
        "reasons": generate_reasons(url_res, cv_res, sig_res, verdict, certified, overrides),
        "breakdown": {**breakdown, "overrides": overrides},
    }


def decide(url_res: Dict[str, Any], cv_res: Dict[str, Any], sig_res: Dict[str, Any]) -> Dict[str, Any]:
    sig = sig_res.get("status", "none")
    url_risk = float(url_res.get("score", 0.0))
    cv_status = cv_res.get("status", "ok")
    tamper_p = 0.0 if cv_status == "low_quality" else float(cv_res.get("score", 0.0))     # calibrated probability
    tamper = _shape(tamper_p, config.TAMPER_P_FLOOR, config.TAMPER_P_CEIL)                # decision-scale risk

    breakdown: Dict[str, Any] = {"url_risk": round(url_risk, 4), "tamper_probability": round(tamper_p, 4),
                                 "tamper_risk": round(tamper, 4), "signature": sig, "cv_status": cv_status}
    overrides: List[str] = []

    # ---- 1. cryptographic hard facts ------------------------------------------------------
    if sig == "valid":
        if tamper_p >= 0.70:
            overrides.append("certified_but_physically_tampered")
            return _finish("SUSPICIOUS", max(0.55, tamper_p * 0.8), True, url_res, cv_res, sig_res, overrides, breakdown)
        return _finish("SAFE", max(0.02, tamper_p * 0.15), True, url_res, cv_res, sig_res, overrides, breakdown)

    if sig in ("invalid", "unknown_issuer", "revoked", "domain_mismatch"):
        overrides.append(f"signature_{sig}")
        return _finish("BLOCK", 0.95, False, url_res, cv_res, sig_res, overrides, breakdown)

    # ---- 2. noisy-OR fusion for unsigned codes ---------------------------------------------
    a = config.URL_WEIGHT
    b = {"ok": config.TAMPER_WEIGHT, "inconclusive": config.TAMPER_WEIGHT_INCONCLUSIVE, "low_quality": 0.0}.get(cv_status, config.TAMPER_WEIGHT)
    fused = 1.0 - (1.0 - a * url_risk) * (1.0 - b * tamper)
    if url_risk > 0.5 and tamper > 0.5 and cv_status != "low_quality":
        fused = max(fused, config.AGREEMENT_FLOOR)
        overrides.append("two_layers_agree")
    breakdown.update(a=a, b=b, fused=round(fused, 4))

    if sig == "expired":
        fused = max(fused, 0.60)
        overrides.append("signature_expired")
    risk = min(max(fused, 0.0), 1.0)

    # ---- 3. hard overrides ---------------------------------------------------------------------
    url_names, cv_names = _names(url_res), _names(cv_res)
    floor = 0.0
    verdict = _verdict_for(risk)
    if "blocklist_match" in url_names:
        overrides.append("blocklist_hit")
        return _finish("BLOCK", 1.0, False, url_res, cv_res, sig_res, overrides, breakdown)
    if "dangerous_scheme" in url_names:
        overrides.append("dangerous_scheme")
        return _finish("BLOCK", max(risk, 0.95), False, url_res, cv_res, sig_res, overrides, breakdown)
    if "stacked_code_pattern" in cv_names:
        floor = max(floor, config.SAFE_BELOW + 0.05); overrides.append("stacked_codes")
    if "payee_vpa_mismatch" in url_names:
        floor = max(floor, 0.60); overrides.append("upi_payee_mismatch")
    if "payload_mismatch_multi_view" in cv_names:
        floor = max(floor, 0.55); overrides.append("two_photos_disagree")
    if floor and risk < floor:
        risk = floor
        verdict = _verdict_for(risk)

    return _finish(verdict, risk, False, url_res, cv_res, sig_res, overrides, breakdown)
