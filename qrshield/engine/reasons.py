"""
Plain-language explanation and reason generator (F31).
Fuses top contributing signals from URL/ML, CV/Physical, and Crypto layers
into concise, human-understandable explanation sentences (max 3 bullets).
"""
from typing import Dict, Any, List

def generate_reasons(
    url_res: Dict[str, Any],
    cv_res: Dict[str, Any],
    sig_res: Dict[str, Any],
    verdict: str,
    certified: bool
) -> List[str]:
    """
    Selects top 1 to 3 plain-language reason strings explaining the verdict.
    """
    reasons: List[str] = []
    sig_status = sig_res.get("status", "none")

    # 1. Crypto Layer Explanations
    if certified and sig_status == "valid":
        issuer = sig_res.get("issuer", {})
        issuer_name = issuer.get("name", "Verified Organization")
        reasons.append(f"Provably authentic QR issued by '{issuer_name}' and verified via Ed25519 PKI.")
        # If tampered physically despite valid crypto
        if cv_res.get("score", 0.0) >= 0.70:
            reasons.append("Warning: Cryptographic signature is valid, but physical code appears pasted over another surface.")
        return reasons[:3]

    if sig_status == "revoked":
        reasons.append("BLOCK: Business signing certificate has been revoked by Root Authority (CRL).")
    elif sig_status == "expired":
        reasons.append("SUSPICIOUS: Time-limited QR code token has expired.")
    elif sig_status == "domain_mismatch":
        issuer = sig_res.get("issuer", {})
        iss_dom = issuer.get("domain", "")
        reasons.append(f"BLOCK: Certificate domain mismatch - issuer '{iss_dom}' attempted to sign an unauthorized external link.")
    elif sig_status in ("invalid", "unknown_issuer"):
        reasons.append("BLOCK: Code claims digital certification but failed cryptographic verification.")

    # 2. Collect high-impact signals from URL and CV layers
    url_signals = url_res.get("signals", [])
    cv_signals = cv_res.get("signals", [])

    # Priority mapping for URL signals
    for s in url_signals:
        name = s.get("name", "")
        text = s.get("text", "")
        if name in ("blocklist_match", "dangerous_scheme", "typosquat_domain", "brand_in_subdomain_or_path", "payee_vpa_mismatch"):
            if text and text not in reasons:
                reasons.append(text)
        elif name in ("newly_registered_domain", "brand_new_domain", "abused_tld", "ip_address_host", "url_shortener"):
            if text and text not in reasons and len(reasons) < 3:
                reasons.append(text)

    # Priority mapping for CV signals
    for s in cv_signals:
        name = s.get("name", "")
        text = s.get("text", "")
        if name in ("stacked_code_pattern", "sticker_edge_detected", "sticker_edge_discontinuity", "cutlines_detected", "double_layer_border"):
            if text and text not in reasons and len(reasons) < 3:
                reasons.append(text)
        elif name in ("paper_color_discrepancy", "sticker_elevation_shadow", "print_dpi_mismatch", "gloss_mismatch"):
            if text and text not in reasons and len(reasons) < 3:
                reasons.append(text)

    # Inconclusive prompt hint
    if cv_res.get("status") == "inconclusive" and len(reasons) < 3:
        reasons.append("Borderline visual surface analysis: prompt user for second angle photo.")

    # Default benign reason if no alarms triggered
    if not reasons:
        if verdict == "SAFE":
            reasons.append("No lexical, physical sticker, or domain anomalies detected.")
        elif verdict == "SUSPICIOUS":
            reasons.append("Uncertain risk profile: moderate signals observed across features.")
        else:
            reasons.append("Elevated risk detected across analysis pipeline.")

    # Cap to at most 3 clear bullet points
    return reasons[:3]
