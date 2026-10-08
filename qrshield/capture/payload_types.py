"""
Payload type parser (F04)
Distinguishes between URL, UPI deep-links, tel, sms, WiFi, mailto, geo,
and inherently dangerous schemes like javascript:, data:, intent://.
"""
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, Tuple

RISKY_SCHEMES = {"javascript", "data", "intent", "vbscript", "file"}

def parse_payload_type(payload: str) -> Tuple[str, Dict[str, Any]]:
    """
    Parses a decoded QR payload string and returns (payload_type, metadata).

    payload_type is one of:
      - 'url'
      - 'upi'
      - 'wifi'
      - 'tel'
      - 'sms'
      - 'mailto'
      - 'geo'
      - 'risky_scheme'
      - 'text'
      - 'other'
    """
    if not payload:
        return "other", {"error": "Empty payload"}

    raw = payload.strip()
    lower = raw.lower()

    # Check for known dangerous schemes immediately
    for risky in RISKY_SCHEMES:
        if lower.startswith(f"{risky}:") or lower.startswith(f"{risky}//"):
            return "risky_scheme", {
                "scheme": risky,
                "warning": f"Potentially malicious execution scheme '{risky}:' detected."
            }

    # UPI scheme
    if lower.startswith("upi://pay") or lower.startswith("upi://mandate") or lower.startswith("upi://"):
        parsed = urlparse(raw)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        return "upi", {
            "scheme": "upi",
            "params": params,
            "pa": params.get("pa", ""),
            "pn": params.get("pn", ""),
            "am": params.get("am", ""),
            "mc": params.get("mc", ""),
            "tr": params.get("tr", ""),
            "mode": "mandate" if "mandate" in lower else "pay"
        }

    # Standard Web URLs
    if lower.startswith("http://") or lower.startswith("https://"):
        parsed = urlparse(raw)
        return "url", {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "query": parsed.query,
            "params": parse_qs(parsed.query)
        }

    # WiFi QR codes: WIFI:S:MySSID;T:WPA;P:MyPassword;;
    if raw.startswith("WIFI:") or raw.startswith("wifi:"):
        parts = raw[5:].split(";")
        wifi_dict = {}
        for p in parts:
            if ":" in p:
                k, v = p.split(":", 1)
                wifi_dict[k.strip()] = v.strip()
        return "wifi", {
            "ssid": wifi_dict.get("S", ""),
            "auth": wifi_dict.get("T", "nopass"),
            "hidden": wifi_dict.get("H", "false")
        }

    # Telephony
    if lower.startswith("tel:"):
        return "tel", {"number": raw[4:]}

    # SMS
    if lower.startswith("sms:") or lower.startswith("smsto:"):
        colon_idx = raw.find(":")
        num_part = raw[colon_idx + 1:]
        body = ""
        if "?" in num_part:
            num, q = num_part.split("?", 1)
            params = parse_qs(q)
            body = params.get("body", [""])[0]
        else:
            num = num_part
        return "sms", {"number": num, "body": body}

    # Mailto
    if lower.startswith("mailto:"):
        parsed = urlparse(raw)
        return "mailto", {"to": parsed.path, "query": parse_qs(parsed.query)}

    # Geo
    if lower.startswith("geo:"):
        return "geo", {"coords": raw[4:]}

    # If it has www. or looks like a URL without scheme
    if lower.startswith("www.") or any(lower.endswith(ext) for ext in [".com", ".org", ".net", ".in", ".io", ".co"]):
        parsed = urlparse("https://" + raw)
        return "url", {
            "scheme": "https",
            "netloc": parsed.netloc,
            "path": parsed.path,
            "inferred_scheme": True
        }

    return "text", {"text_length": len(raw), "preview": raw[:100]}
