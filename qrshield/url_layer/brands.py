"""
Brand definitions and Typosquatting / Homoglyph detection (F08).
Covers Indian payment apps, major banks, e-commerce, and public utilities.
"""
import re
from typing import Dict, Any, Tuple, Optional
from rapidfuzz.distance import Levenshtein, JaroWinkler

# Common targets for quishing and phishing in India
TARGET_BRANDS = [
    "paytm",
    "phonepe",
    "gpay",
    "googlepay",
    "bhim",
    "amazon",
    "flipkart",
    "sbi",
    "onlinesbi",
    "hdfc",
    "hdfcbank",
    "icici",
    "icicibank",
    "axis",
    "axisbank",
    "pnb",
    "kotak",
    "irctc",
    "bookmyshow",
    "mcgm",
    "parkplus",
    "fastag",
    "zomato",
    "swiggy",
    "tataneu",
    "cred",
    "mumbai-metro",
    "citypark"
]

# Homoglyph substitution map (Cyrillic, digits, similar latin)
HOMOGLYPH_MAP = {
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '8': 'b',
    '@': 'a',
    '$': 's',
    'vv': 'w',
    'rn': 'm',
    'cl': 'd',
    # Cyrillic lookalikes
    '\u0430': 'a',  # Cyrillic small a
    '\u0441': 'c',  # Cyrillic small es
    '\u0435': 'e',  # Cyrillic small ie
    '\u043e': 'o',  # Cyrillic small o
    '\u0440': 'p',  # Cyrillic small er
    '\u0455': 's',  # Cyrillic small dze
    '\u0445': 'x',  # Cyrillic small ha
    '\u0443': 'y',  # Cyrillic small u
    '\u0456': 'i',  # Cyrillic small Byelorussian-Ukrainian i
    '\u0458': 'j',  # Cyrillic small je
}

def normalize_homoglyphs(text: str) -> str:
    """Replaces known visual homoglyphs with standard ASCII equivalents."""
    normalized = text.lower()
    # Multi-character replacements first
    for k in ['vv', 'rn', 'cl']:
        if k in normalized:
            normalized = normalized.replace(k, HOMOGLYPH_MAP[k])
    # Single character replacements
    res = []
    for ch in normalized:
        res.append(HOMOGLYPH_MAP.get(ch, ch))
    return "".join(res)

def check_brand_typosquat(domain_sld: str) -> Dict[str, Any]:
    """
    Evaluates how closely the second-level domain (SLD) matches known brands.
    Returns:
      - is_exact_brand: bool
      - is_typosquat: bool
      - matched_brand: str
      - min_levenshtein: int
      - jaro_winkler: float
      - warning: str or None
    """
    clean_sld = normalize_homoglyphs(domain_sld.lower().strip())
    # Strip common prefixes/suffixes like pay-, verify-, -login, -online
    stripped = re.sub(r'^(verify|login|pay|secure|update|online|my)-?', '', clean_sld)
    stripped = re.sub(r'-?(verify|login|pay|secure|update|online|portal|bank|app)$', '', stripped)

    best_match = None
    min_dist = 999
    best_jw = 0.0

    for brand in TARGET_BRANDS:
        # Check exact equality on either full SLD or stripped SLD
        if clean_sld == brand or stripped == brand:
            return {
                "is_exact_brand": True,
                "is_typosquat": False,
                "matched_brand": brand,
                "min_levenshtein": 0,
                "jaro_winkler": 1.0,
                "warning": None
            }

        # Substring impersonation check: e.g. "paytm-refunds" or "phonepe-rewards"
        if brand in clean_sld and clean_sld != brand:
            return {
                "is_exact_brand": False,
                "is_typosquat": True,
                "matched_brand": brand,
                "min_levenshtein": 1,
                "jaro_winkler": 0.95,
                "warning": f"Domain '{domain_sld}' contains brand '{brand}' with deceptive affix."
            }

        dist = Levenshtein.distance(clean_sld, brand)
        jw = JaroWinkler.similarity(clean_sld, brand)

        if dist < min_dist:
            min_dist = dist
            best_match = brand
            best_jw = jw

    # Typosquat heuristics:
    # 1. Edit distance 1 or 2 on brands with length >= 4
    # 2. Jaro-Winkler score > 0.88
    is_typosquat = False
    warning = None

    if best_match:
        if (min_dist <= 2 and len(best_match) >= 4) or (best_jw >= 0.88 and min_dist <= 3):
            is_typosquat = True
            warning = f"Domain '{domain_sld}' closely imitates target brand '{best_match}' (similarity {best_jw:.2f})."

    return {
        "is_exact_brand": False,
        "is_typosquat": is_typosquat,
        "matched_brand": best_match,
        "min_levenshtein": min_dist,
        "jaro_winkler": round(best_jw, 4),
        "warning": warning
    }

def check_brand_in_subdomain_or_path(subdomains: str, path: str, registered_domain: str) -> Optional[str]:
    """
    Detects phishing pattern where a brand name is placed in the subdomain or path
    to trick users on mobile (e.g., https://phonepe.com.payment-security.xyz/login)
    """
    sub_lower = subdomains.lower()
    path_lower = path.lower()
    reg_lower = registered_domain.lower()

    for brand in TARGET_BRANDS:
        # If brand is in subdomain or path, but NOT in registered domain
        if (brand in sub_lower or brand in path_lower) and (brand not in reg_lower):
            return f"Brand '{brand}' appears in subdomain/path but registered domain is '{registered_domain}'"
    return None
