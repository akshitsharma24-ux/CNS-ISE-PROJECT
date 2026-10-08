"""
M4: Aggregation and Scoring Engine (F30).
Rule-first, score-second arbitration engine fusing URL ML, CV Physical Tamper,
and Ed25519 Cryptographic validation into an authoritative security verdict.
"""
from typing import Dict, Any, List
from qrshield.engine.reasons import generate_reasons

def decide(
    url_res: Dict[str, Any],
    cv_res: Dict[str, Any],
    sig_res: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Contract specified in QRshield Master Plan:
    engine.decide(url_res, cv_res, sig_res) -> {
        "verdict": "SAFE|SUSPICIOUS|BLOCK",
        "risk": 0.0-1.0,
        "certified": bool,
        "reasons": [str, ...]
    }
    """
    sig_status = sig_res.get("status", "none")
    url_risk = float(url_res.get("score", 0.0))
    tamper_risk = float(cv_res.get("score", 0.0))
    cv_status = cv_res.get("status", "ok")

    # --- Step 1: Crypto Hard Facts Check ---
    if sig_status == "valid":
        certified = True
        # If valid cryptographic token, but physical sticker is overlaid over something
        if tamper_risk >= 0.70:
            verdict = "SUSPICIOUS"
            risk = max(0.55, tamper_risk)
        else:
            verdict = "SAFE"
            risk = round(max(0.02, tamper_risk * 0.15), 4)

        reasons = generate_reasons(url_res, cv_res, sig_res, verdict, certified)
        return {
            "verdict": verdict,
            "risk": risk,
            "certified": certified,
            "reasons": reasons
        }

    if sig_status in ("invalid", "unknown_issuer", "revoked", "domain_mismatch"):
        certified = False
        verdict = "BLOCK"
        risk = 0.95
        reasons = generate_reasons(url_res, cv_res, sig_res, verdict, certified)
        return {
            "verdict": verdict,
            "risk": risk,
            "certified": certified,
            "reasons": reasons
        }

    if sig_status == "expired":
        certified = False
        verdict = "SUSPICIOUS"
        risk = 0.60
        reasons = generate_reasons(url_res, cv_res, sig_res, verdict, certified)
        return {
            "verdict": verdict,
            "risk": risk,
            "certified": certified,
            "reasons": reasons
        }

    # --- Step 2: Unsigned QR Code Scoring (Noisy-OR Fusion) ---
    certified = False
    a = 0.95
    b = 0.50 if cv_status == "inconclusive" else 0.80

    fused_risk = 1.0 - ((1.0 - a * url_risk) * (1.0 - b * tamper_risk))

    # Two independent layers agree on threat
    if url_risk > 0.50 and tamper_risk > 0.50:
        fused_risk = max(fused_risk, 0.85)

    fused_risk = round(min(max(fused_risk, 0.0), 1.0), 4)

    # Initial threshold mapping
    if fused_risk < 0.30:
        verdict = "SAFE"
    elif fused_risk < 0.65:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BLOCK"

    # --- Step 3: Hard Overrides ---
    url_signals = url_res.get("signals", [])
    has_blocklist = any(s.get("name") == "blocklist_match" for s in url_signals)
    has_dangerous_scheme = any(s.get("name") == "dangerous_scheme" for s in url_signals)
    has_payee_mismatch = any(s.get("name") == "payee_vpa_mismatch" for s in url_signals)
    has_stacked_code = any(s.get("name") == "stacked_code_pattern" for s in cv_res.get("signals", []))

    if has_blocklist:
        verdict = "BLOCK"
        fused_risk = 1.0
    elif has_dangerous_scheme:
        verdict = "BLOCK"
        fused_risk = max(fused_risk, 0.95)
    elif has_stacked_code:
        verdict = "BLOCK"
        fused_risk = max(fused_risk, 0.85)
    elif has_payee_mismatch:
        if verdict == "SAFE":
            verdict = "SUSPICIOUS"
        fused_risk = max(fused_risk, 0.60)

    reasons = generate_reasons(url_res, cv_res, sig_res, verdict, certified)

    return {
        "verdict": verdict,
        "risk": round(float(fused_risk), 4),
        "certified": certified,
        "reasons": reasons
    }
