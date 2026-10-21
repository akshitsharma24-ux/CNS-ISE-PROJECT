"""
UPI deep-link analysis (F11).

Flags the classic scam shapes: a payee name that claims an official entity while the VPA is an
individual's handle, prefilled amounts on a parking/restaurant code, collect/mandate requests
and unusual PSP handles.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import parse_qs

from qrshield.netutil import safe_urlparse

COMMON_PSP_HANDLES = {
    "okaxis", "okhdfcbank", "okicici", "oksbi", "ybl", "ibl", "axl", "ptaxis", "pthdfc", "ptsbi", "ptyes",
    "paytm", "apl", "freecharge", "barodampay", "upi", "postbank", "federal", "indus", "kotak", "fbl",
    "sbi", "hdfcbank", "icici", "axisbank", "yesbank", "pnb", "cnrb", "boi", "ikwik", "jupiteraxis", "fam",
    "airtel", "jio", "slice", "naviaxis", "tapicici", "rbl", "idfcbank", "aubank", "dbs", "hsbc", "unionbank",
}
AUTHORITY_WORDS = ("bank", "sbi", "hdfc", "icici", "axis", "parking", "metro", "bill", "tax", "challan",
                   "govt", "gov", "municipal", "mcgm", "irctc", "railway", "electricity", "fastag", "police")
COMMERCIAL_WORDS = ("parking", "store", "shop", "cafe", "restaurant", "mart", "hotel", "canteen")


def _clean(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def analyze_upi_payload(payload: str) -> Dict[str, Any]:
    parsed = safe_urlparse(payload.strip())
    raw = {k.lower(): v[0] for k, v in parse_qs(parsed.query if parsed else "", keep_blank_values=True).items()}
    pa, pn, am, mc = (raw.get(k, "").strip() for k in ("pa", "pn", "am", "mc"))
    path = (parsed.netloc + parsed.path).lower() if parsed else ""

    signals: List[Dict[str, Any]] = []
    risk = 0.0

    def add(name: str, value: Any, text: str, weight: float, direction: str = "risk") -> None:
        nonlocal risk
        risk += weight
        signals.append({"name": name, "value": value, "text": text, "direction": direction})

    if "mandate" in path or "mandate" in payload.lower().split("?", 1)[0]:
        add("upi_mandate", True, "This is a recurring-payment (autopay) mandate request, not a one-off payment.", 0.40)
    if raw.get("mode") in ("04", "05") or "collect" in payload.lower():
        add("upi_collect", True, "This asks you to approve a money REQUEST (collect), which is how many UPI scams work.", 0.35)

    vpa_user = psp = ""
    if not pa or "@" not in pa:
        add("malformed_vpa", pa, "The payment address (VPA) is missing or malformed.", 0.50)
    else:
        vpa_user, psp = pa.split("@", 1)
        psp = psp.lower()
        if psp not in COMMON_PSP_HANDLES and not psp.endswith("bank"):
            add("unusual_psp", psp, f"The payment handle '@{psp}' is not a recognised UPI provider.", 0.20)

    mismatch = False
    if pn and vpa_user:
        cn, cv = _clean(pn), _clean(vpa_user)
        claims = any(w in cn for w in AUTHORITY_WORDS)
        backs_up = any(w in cv for w in AUTHORITY_WORDS) or cv in cn or cn in cv
        if claims and not backs_up:
            mismatch = True
            add("payee_vpa_mismatch", {"pn": pn, "pa": pa},
                f"The payee is named '{pn}' but the money would go to '{pa}', which has nothing to do with that name.", 0.50)

    if am:
        try:
            amount = float(am)
            if amount > 500:
                add("high_prefilled_amount", amount, f"A high amount (INR {amount:,.0f}) is pre-filled.", 0.20)
            elif any(w in pn.lower() for w in COMMERCIAL_WORDS):
                add("prefilled_amount", amount, f"Pre-filled amount: INR {amount:,.0f}.", 0.0, "info")
        except ValueError:
            add("invalid_amount_format", am, "The amount field is not a valid number.", 0.20)

    if any(w in pn.lower() for w in COMMERCIAL_WORDS) and not mc:
        add("missing_merchant_code", None, "A business payee without a merchant category code (MCC).", 0.15)

    if not signals:
        signals.append({"name": "upi_clean", "value": True, "text": "No UPI red flags found in this payment link.",
                        "direction": "safe"})
    return {"score": round(min(max(risk, 0.0), 1.0), 3), "payload_type": "upi", "pa": pa, "pn": pn, "am": am,
            "mc": mc, "mismatch": mismatch, "signals": signals}
