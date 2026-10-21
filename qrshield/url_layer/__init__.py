"""
M1: URL / payload analysis.  Exposes the `url_layer.analyze(payload)` contract:

    {"score": 0..1, "payload_type": "url|upi|other", "signals": [{"name","value","text","direction"}], ...}

Order of authority: (1) hard overrides (local blocklist, dangerous schemes), (2) the calibrated
LightGBM model, (3) a few explicit rules where the cost of being wrong is asymmetric
(brand impersonation floors the score; restricted/official domains cap it).
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

from qrshield import config
from qrshield.capture.payload_types import parse_payload_type
from qrshield.url_layer import blocklist, brands as B, host_intel, model as M
from qrshield.url_layer.features import FeatureResult, extract_features, ngram_text
from qrshield.url_layer.fetch_safe import KNOWN_SHORTENERS, expand_and_inspect_redirects
from qrshield.url_layer.upi import analyze_upi_payload

IMPERSONATION_RISK = 0.80      # decision-scale floor when a brand is impersonated
TRUSTED_CAP = 0.10             # ceiling for official / well-known / institution-only domains
YOUNG_DOMAIN_RISK = 0.70
YOUNG_DOMAIN_DAYS = 30

# feature -> (min contribution in log-odds to mention, sentence builder)
_TEMPLATES = {
    "tld_abused": lambda f: f"The '.{f.parts.suffix.split('.')[-1]}' domain ending is heavily used for throw-away scam sites.",
    "user_content_host": lambda f: f"Hosted on a free/shared platform ({f.parts.registered}) where anyone can publish a page.",
    "host_hyphens": lambda f: "The domain name is stuffed with hyphens, typical of look-alike scam domains.",
    "host_keywords": lambda f: "The domain contains pressure or credential words (secure, verify, refund, kyc...).",
    "sld_consonant_run": lambda f: "The domain name looks randomly generated.",
    "sld_entropy": lambda f: "The domain name looks randomly generated.",
    "host_hex_blob": lambda f: "The domain contains a long random-looking token.",
    "is_ip": lambda f: "The link uses a raw IP address instead of a real domain name.",
    "is_punycode": lambda f: "The domain uses look-alike (internationalised) characters.",
    "subdomain_depth": lambda f: "The link hides its real domain behind an unusually deep chain of subdomains.",
    "path_keywords": lambda f: "The link path asks for logins, OTPs, KYC or payments.",
    "redirect_param": lambda f: "The link contains a redirect to another site.",
    "long_token_len": lambda f: "The link carries a long tracking/session token.",
    "ext_download": lambda f: "The link downloads a program or archive.",
    "has_at": lambda f: "The link contains an '@' that can disguise the real destination.",
    "double_slash_path": lambda f: "The link path contains '//', a common open-redirect trick.",
    "port_nonstandard": lambda f: "The link uses an unusual network port.",
    "host_digit_ratio": lambda f: "The domain is mostly digits.",
    "ext_dynamic": lambda f: "The link opens a server script page (.php/.asp) typical of credential-harvesting kits.",
}


def _sig(name: str, value: Any, text: str, direction: str = "risk") -> Dict[str, Any]:
    return {"name": name, "value": value, "text": text, "direction": direction}


def _result(score: float, ptype: str, signals: List[Dict[str, Any]], **details: Any) -> Dict[str, Any]:
    return {"score": round(float(min(max(score, 0.0), 1.0)), 4), "payload_type": ptype,
            "signals": signals, "details": details}


def _online_allowed(offline: bool | None) -> bool:
    if offline is not None:
        return not offline
    return os.environ.get("QRSHIELD_ONLINE_CHECKS", "1").lower() in ("1", "true", "yes")


def _non_web(ptype: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    if ptype == "wifi":
        open_net = meta.get("auth", "").lower() in ("nopass", "")
        text = ("This code joins an OPEN Wi-Fi network - traffic on it can be read by others."
                if open_net else f"Joins the Wi-Fi network '{meta.get('ssid', '')}'.")
        return _result(0.30 if open_net else 0.10, "other", [_sig("wifi_join", meta.get("ssid"), text, "risk" if open_net else "info")])
    if ptype == "sms":
        body = meta.get("body", "")
        text = "Opens a pre-written SMS" + (f": \"{body[:60]}\"" if body else "") + ". Scammers use this to subscribe you to paid services."
        return _result(0.35 if body else 0.15, "other", [_sig("prefilled_sms", meta.get("number"), text)])
    if ptype == "tel":
        return _result(0.15, "other", [_sig("phone_call", meta.get("number"), "Starts a phone call. Premium-rate and vishing numbers are common scams.")])
    if ptype == "crypto":
        return _result(0.55, "other", [_sig("crypto_payment", meta.get("scheme"), "A cryptocurrency payment request - payments cannot be reversed.")])
    if ptype in ("mailto", "geo", "vcard"):
        return _result(0.08, "other", [_sig(f"benign_{ptype}", ptype, f"Plain {ptype} data.", "safe")])
    return _result(0.10, "other", [_sig("plain_text", ptype, "Plain text - nothing to open.", "safe")])


def analyze(payload: str, offline: bool | None = None) -> Dict[str, Any]:
    if not payload:
        return _result(0.0, "other", [_sig("empty", None, "Empty payload", "info")])

    ptype, meta = parse_payload_type(payload)

    if ptype == "upi":
        r = analyze_upi_payload(payload)
        return _result(r["score"], "upi", r["signals"], pa=r["pa"], pn=r["pn"])
    if ptype == "risky_scheme":
        return _result(0.97, "other", [_sig("dangerous_scheme", meta.get("scheme"), meta["warning"])])
    if ptype != "url":
        return _non_web(ptype, meta)

    url = payload.strip()
    fr: FeatureResult = extract_features(url)
    signals: List[Dict[str, Any]] = []

    if fr.malformed:
        return _result(0.70, "url", [_sig("malformed_url", None, "The link is malformed and cannot be inspected safely.")])

    hit = blocklist.match(url)
    if hit:
        return _result(1.0, "url", [_sig("blocklist_match", hit, "This site is on a known-phishing blocklist.")], blocklisted=True)

    scheme = fr.scheme or ("https" if meta.get("inferred_scheme") else "")
    if scheme == "http":
        signals.append(_sig("insecure_http", False, "The link is not encrypted (plain http).", "risk"))

    # shortener expansion (SSRF-safe, passive)
    redirect_info = None
    if _online_allowed(offline) and fr.parts and (fr.parts.registered in KNOWN_SHORTENERS or fr.host in KNOWN_SHORTENERS):
        redirect_info = expand_and_inspect_redirects(url)
        signals.extend({**s, "direction": "risk"} for s in redirect_info.get("signals", []))
        if redirect_info.get("reached") and redirect_info["final_url"] != url:
            final = extract_features(redirect_info["final_url"])
            if not final.malformed:
                fr_final, fr = fr, final        # judge the real destination, keep shortener signals
                fr.extra["shortener"] = fr_final.host
        elif not redirect_info.get("reached"):
            signals.append(_sig("shortener_unresolved", fr.host, "A URL shortener hides the destination and it could not be checked.", "risk"))

    art = M.active()
    model_version = "rules-only"
    p = 0.5 if fr.named["brand_impersonation"] else 0.2     # defensive fallback if no model is installed
    if art is not None:
        scored_url = redirect_info["final_url"] if (redirect_info and redirect_info.get("reached")) else url
        p = float(M.predict_proba(art, [fr.vector], [ngram_text(scored_url)])[0])
        model_version = art.get("version", "bundled")
        contribs = M.contributions(art, fr.vector)
        added = set()
        for feat, c in contribs:
            if c < 0.25 or len(added) >= 4:
                break
            build = _TEMPLATES.get(feat)
            if build and feat not in added:
                text = build(fr)
                if all(s["text"] != text for s in signals):
                    signals.append(_sig(feat, round(fr.named.get(feat, 0.0), 3), text))
                    added.add(feat)
    # Decision-scale risk: calibrated probability rescaled so weak lexical evidence cannot BLOCK on its own.
    risk = min(max((p - config.URL_P_FLOOR) / (config.URL_P_CEIL - config.URL_P_FLOOR), 0.0), 1.0)
    model_p = p

    rules: List[str] = []
    brand = fr.brand
    user_content = bool(fr.named["user_content_host"])
    if brand and brand.impersonation:
        if brand.warning:
            signals.insert(0, _sig("brand_impersonation", brand.brand, brand.warning))
        if risk < IMPERSONATION_RISK:
            risk = IMPERSONATION_RISK
            rules.append("brand_impersonation_floor")
    elif brand and brand.brand_in_path_only and brand.warning:
        signals.append(_sig("brand_in_path", brand.brand, brand.warning))

    if fr.parts and not (brand and brand.impersonation) and not user_content:
        if fr.named["tld_restricted"]:
            risk = min(risk, TRUSTED_CAP)
            rules.append("restricted_suffix_cap")
            signals.append(_sig("restricted_domain", fr.parts.suffix,
                                f"'.{fr.parts.suffix}' domains are only issued to verified institutions.", "safe"))
        elif (brand and brand.official) or fr.parts.registered in B.KNOWN_GOOD:
            risk = min(risk, TRUSTED_CAP)
            rules.append("known_domain_cap")
            signals.append(_sig("official_domain", fr.parts.registered,
                                f"'{fr.parts.registered}' is a well-known, established domain.", "safe"))

    if fr.parts and fr.parts.registered:
        age = host_intel.lookup(fr.parts.registered).get("age_days")
        if age is not None and age < YOUNG_DOMAIN_DAYS:
            risk = max(risk, YOUNG_DOMAIN_RISK)
            rules.append("young_domain_floor")
            signals.append(_sig("newly_registered_domain", age, f"This domain was registered only {age} days ago."))

    if "known_domain_cap" in rules or "restricted_suffix_cap" in rules:
        signals = [s for s in signals if s["name"] not in _TEMPLATES]      # trusted domain: drop lexical nitpicks
    elif risk < 0.30:
        for s in signals:                                                  # weak lexical hints are context, not warnings
            if s["name"] in _TEMPLATES:
                s["direction"] = "info"
    if risk >= 0.30 and not any(s["direction"] == "risk" for s in signals):
        signals.append(_sig("model_pattern", round(model_p, 2), "The overall shape of this link closely resembles known phishing links."))
    if not any(s["direction"] == "risk" for s in signals) and risk < 0.30:
        signals.append(_sig("no_url_red_flags", None, "No suspicious patterns found in this link.", "safe"))

    return _result(risk, "url", signals, model_version=model_version, model_probability=round(model_p, 4),
                   registered_domain=fr.parts.registered if fr.parts else "", rules=rules, redirect=redirect_info)
