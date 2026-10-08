"""
UPI deep-link security analysis (F11)
Checks for payee name vs VPA handle mismatches, prefilled amount risks,
unusual PSP handles, and collect-request or mandate payloads.
"""
import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List

# Recognized standard bank and fintech PSP handles in India
COMMON_PSP_HANDLES = {
    "okaxis", "okhdfcbank", "okicici", "oksbi",
    "ybl", "ibl", "axl", "ptaxis", "pthdfc", "ptsbi",
    "paytm", "apl", "razerpay", "freecharge", "barodampay",
    "upi", "postbank", "federal", "indus", "kotak"
}

def analyze_upi_payload(payload: str) -> Dict[str, Any]:
    """
    Analyzes upi://pay or upi://mandate payloads for deception and risk.
    """
    parsed = urlparse(payload)
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    pa = params.get("pa", "").strip()  # Virtual Payment Address
    pn = params.get("pn", "").strip()  # Payee Name
    am = params.get("am", "").strip()  # Prefilled Amount
    mc = params.get("mc", "").strip()  # Merchant code
    tr = params.get("tr", "").strip()  # Transaction reference

    signals: List[Dict[str, Any]] = []
    risk_score = 0.0

    is_mandate = "mandate" in parsed.path.lower() or "mandate" in payload.lower()
    if is_mandate:
        risk_score += 0.4
        signals.append({
            "name": "upi_mandate",
            "value": True,
            "text": "UPI mandate / autopay authorization request detected."
        })

    # Validate VPA structure
    if not pa or "@" not in pa:
        risk_score += 0.5
        signals.append({
            "name": "malformed_vpa",
            "value": pa,
            "text": "Missing or malformed Virtual Payment Address (VPA)."
        })
        vpa_user, psp = "", ""
    else:
        vpa_user, psp = pa.split("@", 1)
        psp = psp.lower()
        if psp not in COMMON_PSP_HANDLES and not psp.endswith("bank"):
            risk_score += 0.2
            signals.append({
                "name": "unusual_psp",
                "value": psp,
                "text": f"Unusual or private PSP handle '@{psp}'."
            })

    # Payee Name vs VPA consistency check
    # Attack pattern: pn="State Bank Of India" or "City Parking" but pa="rohit1234@ybl"
    mismatch_detected = False
    if pn and vpa_user:
        clean_pn = re.sub(r'[^a-zA-Z0-9]', '', pn).lower()
        clean_vpa = re.sub(r'[^a-zA-Z0-9]', '', vpa_user).lower()

        # If name claims to be official (bank, parking, metro, electricity, bill)
        claims_authority = any(k in clean_pn for k in [
            "bank", "sbi", "hdfc", "icici", "parking", "metro", "bill", "tax", "challan", "govt"
        ])
        vpa_has_authority = any(k in clean_vpa for k in [
            "bank", "sbi", "hdfc", "icici", "parking", "metro", "bill", "tax", "challan", "govt"
        ])

        if claims_authority and not vpa_has_authority:
            mismatch_detected = True
            risk_score += 0.5
            signals.append({
                "name": "payee_vpa_mismatch",
                "value": {"pn": pn, "pa": pa},
                "text": f"Payee name claims official entity '{pn}' but VPA handle is individual '{pa}'."
            })

    # Prefilled amount risk
    if am:
        try:
            amt_val = float(am)
            if amt_val > 500.0:
                risk_score += 0.2
                signals.append({
                    "name": "high_prefilled_amount",
                    "value": amt_val,
                    "text": f"High prefilled payment amount: INR {amt_val:,.2f}."
                })
            else:
                signals.append({
                    "name": "prefilled_amount",
                    "value": amt_val,
                    "text": f"Prefilled payment amount: INR {amt_val:,.2f}."
                })
        except ValueError:
            risk_score += 0.2
            signals.append({
                "name": "invalid_amount_format",
                "value": am,
                "text": "Malformed payment amount parameter."
            })

    # Missing merchant code on commercial claims
    if any(k in pn.lower() for k in ["parking", "store", "shop", "cafe", "restaurant", "mart"]) and not mc:
        risk_score += 0.15
        signals.append({
            "name": "missing_merchant_code",
            "value": None,
            "text": "Commercial payee name without registered merchant category code (MCC)."
        })

    risk_score = min(max(risk_score, 0.0), 1.0)

    return {
        "score": round(risk_score, 2),
        "payload_type": "upi",
        "pa": pa,
        "pn": pn,
        "am": am,
        "mc": mc,
        "mismatch": mismatch_detected,
        "signals": signals
    }
