"""Plain-language reasons (F31): at most three bullets, most decisive first."""
from __future__ import annotations

from typing import Any, Dict, List

_CRYPTO_BLOCK = {
    "invalid": "This code claims to be digitally signed, but the signature does not verify - it has been forged or altered.",
    "unknown_issuer": "This code claims to be certified, but its issuer is not registered with the QRshield authority.",
    "revoked": "The business's signing key was revoked by the registry - this code can no longer be trusted.",
    "domain_mismatch": "A genuine issuer signed a link outside the domain it is certified for - a classic lookalike trick.",
    "expired": "This signed code has expired and should have been replaced.",
}
_URL_PRIORITY = ("blocklist_match", "dangerous_scheme", "brand_impersonation", "payee_vpa_mismatch", "upi_collect",
                 "newly_registered_domain", "malformed_url", "domain_redirect_mismatch", "url_shortener", "shortener_unresolved")
_CV_PRIORITY = ("stacked_code_pattern", "payload_mismatch_multi_view", "hidden_code_fragments", "sticker_edge_detected",
                "sticker_elevation_shadow", "double_layer_border", "paper_color_discrepancy", "gloss_mismatch",
                "print_texture_mismatch", "photometric_relief")


def _risk_signals(signals: List[Dict[str, Any]], priority: tuple) -> List[str]:
    risky = [s for s in signals if s.get("direction", "risk") == "risk" and s.get("text")]
    order = {n: i for i, n in enumerate(priority)}
    risky.sort(key=lambda s: order.get(s.get("name"), len(priority)))
    return [s["text"] for s in risky]


def generate_reasons(url_res: Dict[str, Any], cv_res: Dict[str, Any], sig_res: Dict[str, Any], verdict: str,
                     certified: bool, overrides: List[str]) -> List[str]:
    sig = sig_res.get("status", "none")
    reasons: List[str] = []

    if certified and sig == "valid":
        issuer = sig_res.get("issuer") or {}
        reasons.append(f"Digitally signed by '{issuer.get('name', 'a registered business')}' and verified against the "
                       f"QRshield root of trust (domain {issuer.get('domain', '?')}).")
        if cv_res.get("score", 0.0) >= 0.70 and cv_res.get("status") != "low_quality":
            reasons.append("But the code physically looks stuck on top of something else - check the sign before paying.")
        return reasons[:3]

    if sig in _CRYPTO_BLOCK:
        reasons.append(_CRYPTO_BLOCK[sig])

    for text in _risk_signals(url_res.get("signals", []), _URL_PRIORITY):
        if len(reasons) < 2 and text not in reasons:
            reasons.append(text)
    for text in _risk_signals(cv_res.get("signals", []), _CV_PRIORITY):
        if len(reasons) < 3 and text not in reasons:
            reasons.append(text)
    for text in _risk_signals(url_res.get("signals", []), _URL_PRIORITY):
        if len(reasons) < 3 and text not in reasons:
            reasons.append(text)

    if cv_res.get("status") == "inconclusive" and len(reasons) < 3:
        reasons.append("The visual check is borderline - take a second photo from the side to be sure.")

    if not reasons:
        if verdict == "SAFE":
            safe = [s["text"] for s in url_res.get("signals", []) if s.get("direction") == "safe"]
            reasons.append(safe[0] if safe else "No suspicious link patterns or signs of a pasted-over sticker were found.")
            reasons.append("This code is not digitally signed, so QRshield cannot prove who issued it.")
        elif verdict == "SUSPICIOUS":
            reasons.append("Several weak warning signs add up - open the link only if you trust where you found this code.")
        else:
            reasons.append("Strong evidence of a malicious or tampered code.")
    elif verdict == "SAFE" and sig == "none":
        reasons.append("This code is not digitally signed, so QRshield cannot prove who issued it.")
    return reasons[:3]
