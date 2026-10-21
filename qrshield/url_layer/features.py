"""
URL feature extraction for the M1 classifier (F06, F08).

Design rules (these exist because public phishing corpora are biased - see docs/evaluation.md):
  * Features are computed from the URL *string only*. No live WHOIS/DNS/TLS lookups feed the
    model, so training and serving see identical inputs and scans are fast and offline-safe.
  * The scheme is deliberately NOT a feature (most corpora strip it from benign rows) and a
    leading "www." is removed, so the model cannot learn collection artefacts.
  * Path/query features are only trusted because the training set is resampled to have the
    same path/query rate in both classes.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from qrshield.netutil import HostParts, hostname_of, safe_urlparse, split_host
from qrshield.url_layer import brands as B

FEATURE_ORDER: List[str] = [
    # host structure
    "host_len", "n_labels", "subdomain_depth", "sld_len", "host_hyphens", "host_digits", "host_digit_ratio",
    "host_entropy", "sld_entropy", "max_label_len", "is_ip", "is_punycode", "tld_abused", "tld_len",
    "tld_restricted", "user_content_host", "sld_tokens", "sld_consonant_run", "sld_vowel_ratio",
    "sld_digit_letter_mix", "host_hex_blob", "port_nonstandard", "host_keywords",
    # brand impersonation
    "brand_impersonation", "brand_in_sld", "brand_in_subdomain", "typosquat", "brand_min_dist",
    "brand_jaro_winkler", "brand_in_path_only", "official_domain",
    # path / query
    "url_len", "path_len", "path_depth", "path_digit_ratio", "path_entropy", "has_query", "query_len",
    "n_params", "path_keywords", "ext_dynamic", "ext_download", "ext_static", "long_token_len",
    "redirect_param", "n_percent", "has_at", "double_slash_path", "path_dots",
]

_VOWELS = set("aeiou")
_CONSONANT_RUN = re.compile(r"[bcdfghjklmnpqrstvwxyz]+")
_HEX_BLOB = re.compile(r"[0-9a-f]{10,}")
_TOKEN_RUN = re.compile(r"[A-Za-z0-9_\-]{20,}")
_REDIRECT_PARAM = re.compile(r"(?:^|[?&])(?:url|u|redirect|redirect_uri|next|goto|return|continue|dest|target)=(?:https?|//)", re.I)
_EXT_DYNAMIC = {"php", "asp", "aspx", "jsp", "cgi", "php3", "php5", "pl", "cfm"}
_EXT_DOWNLOAD = {"exe", "apk", "scr", "msi", "bat", "jar", "zip", "rar", "7z", "dmg", "iso", "ipa", "vbs", "ps1", "cmd", "com", "docm", "xlsm"}
_EXT_STATIC = {"html", "htm", "xhtml", "shtml"}


def ngram_text(url: str) -> str:
    """Text fed to the character n-gram model: host (no www) + path/query. Scheme excluded."""
    from qrshield.netutil import normalise_url
    n = normalise_url(url) or ""
    i = n.find("/")
    host = hostname_of("http://" + n) if n else ""
    return host + " " + (n[i:] if i >= 0 else "")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def idna_decode(host: str) -> str:
    """Decode punycode labels to Unicode so homograph checks see the characters users see."""
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return host


@dataclass
class FeatureResult:
    vector: List[float]
    named: Dict[str, float]
    host: str = ""
    parts: Optional[HostParts] = None
    brand: Optional[B.BrandReport] = None
    scheme: str = ""
    path: str = ""
    query: str = ""
    malformed: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)


def _empty(malformed: bool = True) -> FeatureResult:
    named = {k: 0.0 for k in FEATURE_ORDER}
    return FeatureResult([0.0] * len(FEATURE_ORDER), named, malformed=malformed)


def extract_features(url: str) -> FeatureResult:
    """Return the feature vector (in FEATURE_ORDER) plus context used to explain it."""
    raw = (url or "").strip()
    if not raw:
        return _empty()
    parsed = safe_urlparse(raw if "://" in raw else "http://" + raw)
    if parsed is None:
        return _empty()
    host = hostname_of(raw if "://" in raw else "http://" + raw)
    if not host:
        return _empty()
    try:
        port = parsed.port
    except ValueError:
        port = None
    path, query = parsed.path or "", parsed.query or ""

    host_norm = host[4:] if host.startswith("www.") else host
    parts = split_host(host_norm)
    parts_u = split_host(idna_decode(host_norm)) if "xn--" in host_norm else parts
    labels = parts.labels
    sld = parts.sld if not parts.is_ip else ""
    sld_letters = re.sub(r"[^a-z]", "", sld)

    brand = B.check_brand(parts_u, path + ("?" + query if query else ""))
    rest = path + ("?" + query if query else "")
    rest_low = rest.lower()

    letters_only = [c for c in sld_letters]
    vowel_ratio = (sum(c in _VOWELS for c in letters_only) / len(letters_only)) if letters_only else 0.5
    runs = _CONSONANT_RUN.findall(sld_letters)
    last_seg = path.rsplit("/", 1)[-1]
    ext = last_seg.rsplit(".", 1)[-1].lower() if "." in last_seg else ""

    segs = [s for s in path.split("/") if s]
    digits_path = sum(c.isdigit() for c in path)
    tlds = parts.suffix.split(".")[-1] if parts.suffix else ""

    named: Dict[str, float] = {
        "host_len": float(len(host_norm)),
        "n_labels": float(len(labels)),
        "subdomain_depth": float(len([p for p in parts.subdomain.split(".") if p])),
        "sld_len": float(len(sld)),
        "host_hyphens": float(host_norm.count("-")),
        "host_digits": float(sum(c.isdigit() for c in host_norm)),
        "host_digit_ratio": sum(c.isdigit() for c in host_norm) / max(len(host_norm), 1),
        "host_entropy": shannon_entropy(host_norm),
        "sld_entropy": shannon_entropy(sld),
        "max_label_len": float(max((len(p) for p in labels), default=0)),
        "is_ip": 1.0 if parts.is_ip else 0.0,
        "is_punycode": 1.0 if any(p.startswith("xn--") for p in labels) else 0.0,
        "tld_abused": 1.0 if tlds in B.ABUSED_TLDS else 0.0,
        "tld_len": float(len(tlds)),
        "tld_restricted": 1.0 if B.is_restricted_suffix(parts.suffix) else 0.0,
        "user_content_host": 1.0 if B.is_user_content_host(parts.registered, host_norm) else 0.0,
        "sld_tokens": float(len([t for t in re.split(r"[-_]", sld) if t])),
        "sld_consonant_run": float(max((len(r) for r in runs), default=0)),
        "sld_vowel_ratio": vowel_ratio,
        "sld_digit_letter_mix": 1.0 if (any(c.isdigit() for c in sld) and any(c.isalpha() for c in sld)) else 0.0,
        "host_hex_blob": 1.0 if _HEX_BLOB.search(host_norm) else 0.0,
        "port_nonstandard": 1.0 if (port is not None and port not in (80, 443)) else 0.0,
        "host_keywords": float(sum(1 for k in B.PHISH_KEYWORDS if k in host_norm)),
        "brand_impersonation": 1.0 if brand.impersonation else 0.0,
        "brand_in_sld": 1.0 if (brand.impersonation and brand.where in ("sld", "typo")) else 0.0,
        "brand_in_subdomain": 1.0 if (brand.impersonation and brand.where == "subdomain") else 0.0,
        "typosquat": 1.0 if brand.typosquat else 0.0,
        "brand_min_dist": float(brand.min_norm_dist),
        "brand_jaro_winkler": float(brand.jaro_winkler),
        "brand_in_path_only": 1.0 if brand.brand_in_path_only else 0.0,
        "official_domain": 1.0 if brand.official else 0.0,
        "url_len": float(len(host_norm) + len(rest)),
        "path_len": float(len(path)),
        "path_depth": float(len(segs)),
        "path_digit_ratio": digits_path / max(len(path), 1),
        "path_entropy": shannon_entropy(path),
        "has_query": 1.0 if query else 0.0,
        "query_len": float(len(query)),
        "n_params": float(query.count("&") + 1 if query else 0),
        "path_keywords": float(sum(1 for k in B.PHISH_KEYWORDS if k in rest_low)),
        "ext_dynamic": 1.0 if ext in _EXT_DYNAMIC else 0.0,
        "ext_download": 1.0 if ext in _EXT_DOWNLOAD else 0.0,
        "ext_static": 1.0 if ext in _EXT_STATIC else 0.0,
        "long_token_len": float(max((len(m) for m in _TOKEN_RUN.findall(rest)), default=0)),
        "redirect_param": 1.0 if _REDIRECT_PARAM.search("?" + query if query else "") else 0.0,
        "n_percent": float(rest.count("%")),
        "has_at": 1.0 if "@" in raw.split("//", 1)[-1].split("/", 1)[0] else 0.0,
        "double_slash_path": 1.0 if "//" in path else 0.0,
        "path_dots": float(path.count(".")),
    }
    vector = [float(named[k]) for k in FEATURE_ORDER]
    return FeatureResult(vector, named, host=host_norm, parts=parts, brand=brand,
                         scheme=(parsed.scheme or "").lower() if "://" in raw else "", path=path, query=query)
