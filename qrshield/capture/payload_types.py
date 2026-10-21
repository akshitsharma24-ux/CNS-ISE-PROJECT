"""
Payload type parser (F04).

Classifies a decoded QR payload as one of:
  url, upi, wifi, tel, sms, mailto, geo, vcard, crypto, risky_scheme, text
Only `url` and `upi` are analysed by the ML/UPI machinery; everything else is routed to a
small rule set in the URL layer. Inherently dangerous schemes (javascript:, data:, intent://,
file:, vbscript:) are flagged as `risky_scheme`.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs

from qrshield.netutil import safe_urlparse

RISKY_SCHEMES = ("javascript", "data", "intent", "vbscript", "file", "blob", "ms-msdt", "search-ms")
CRYPTO_SCHEMES = ("bitcoin", "ethereum", "litecoin", "monero", "solana")
_BARE_DOMAIN = re.compile(r"^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}(?::\d+)?(?:[/?#].*)?$", re.I)


def _query_params(query: str) -> Dict[str, str]:
    return {k: v[0] for k, v in parse_qs(query, keep_blank_values=True).items()}


def parse_payload_type(payload: str) -> Tuple[str, Dict[str, Any]]:
    """Return (payload_type, metadata). Never raises."""
    if not payload or not payload.strip():
        return "text", {"error": "empty payload"}
    raw = payload.strip()
    lower = raw.lower()

    scheme = lower.split(":", 1)[0] if ":" in lower else ""
    if scheme in RISKY_SCHEMES:
        return "risky_scheme", {"scheme": scheme,
                                "warning": f"'{scheme}:' payloads can execute code or exfiltrate data when opened."}

    if lower.startswith("upi://"):
        parsed = safe_urlparse(raw)
        params = _query_params(parsed.query) if parsed else {}
        return "upi", {"scheme": "upi", "params": params, "pa": params.get("pa", ""),
                       "pn": params.get("pn", ""), "am": params.get("am", ""), "mc": params.get("mc", ""),
                       "mode": "mandate" if "mandate" in lower.split("?", 1)[0] else "pay"}

    if lower.startswith(("http://", "https://")):
        parsed = safe_urlparse(raw)
        if parsed is None:
            return "url", {"malformed": True, "preview": raw[:100]}
        return "url", {"scheme": parsed.scheme, "netloc": parsed.netloc, "path": parsed.path}

    if lower.startswith("wifi:"):
        fields = {}
        for part in re.split(r"(?<!\\);", raw[5:]):
            if ":" in part:
                k, v = part.split(":", 1)
                fields[k.strip().upper()] = v.replace("\\;", ";").strip()
        return "wifi", {"ssid": fields.get("S", ""), "auth": fields.get("T", "nopass") or "nopass",
                        "hidden": fields.get("H", "false").lower() == "true", "has_password": bool(fields.get("P"))}

    if lower.startswith("tel:"):
        return "tel", {"number": raw[4:]}
    if lower.startswith(("sms:", "smsto:")):
        rest = raw.split(":", 1)[1]
        number, _, query = rest.partition("?")
        body = _query_params(query).get("body", "")
        if not body and ":" in number:          # smsto:NUMBER:BODY form
            number, _, body = number.partition(":")
        return "sms", {"number": number, "body": body}
    if lower.startswith("mailto:"):
        to, _, query = raw[7:].partition("?")
        return "mailto", {"to": to, "query": _query_params(query)}
    if lower.startswith("geo:"):
        return "geo", {"coords": raw[4:]}
    if lower.startswith(("begin:vcard", "mecard:", "begin:vevent")):
        return "vcard", {"kind": lower.split(":", 1)[0]}
    if scheme in CRYPTO_SCHEMES:
        return "crypto", {"scheme": scheme}

    if _BARE_DOMAIN.match(raw) and " " not in raw:
        # scheme-less URL such as "evil-bank.com/login": scanners would guess http(s)
        return "url", {"scheme": "https", "inferred_scheme": True, "netloc": raw.split("/")[0], "path": ""}

    return "text", {"text_length": len(raw), "preview": raw[:100]}
