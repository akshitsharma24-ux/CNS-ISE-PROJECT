"""
Brand impersonation and typosquatting detection (F08).

A brand is only "genuine" when the *registered domain* is one of its official domains:
`paytm.xyz` is an impersonation even though its label is exactly "paytm". Short brand names
(cred, axis, sbi) are matched on whole tokens only, so "accredited.org" is not flagged.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set

from rapidfuzz.distance import JaroWinkler, Levenshtein

from qrshield.netutil import HostParts

# brand token -> official registered domains
BRANDS: Dict[str, Set[str]] = {
    # payments / wallets
    "paytm": {"paytm.com", "paytmbank.com", "paytm.in"},
    "phonepe": {"phonepe.com"},
    "gpay": {"pay.google.com", "google.com"},
    "googlepay": {"pay.google.com", "google.com"},
    "bhim": {"bhimupi.org.in", "npci.org.in"},
    "npci": {"npci.org.in"},
    "razorpay": {"razorpay.com"},
    "cred": {"cred.club"},
    "mobikwik": {"mobikwik.com"},
    "freecharge": {"freecharge.in"},
    "paypal": {"paypal.com"},
    # banks
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbilife.co.in"},
    "onlinesbi": {"onlinesbi.sbi", "onlinesbi.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com", "hdfcsec.com", "hdfclife.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icici": {"icicibank.com", "icicidirect.com", "icicisecurities.com", "icicilombard.com"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "axis": {"axisbank.com", "axis.com"},
    "kotak": {"kotak.com", "kotakbank.com"},
    "pnb": {"pnbindia.in", "netpnb.com"},
    "yesbank": {"yesbank.in"},
    "idfcfirst": {"idfcfirstbank.com"},
    "citibank": {"citibank.com", "citi.com"},
    # commerce / services
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com", "amazon.jobs", "amazonpay.in"},
    "flipkart": {"flipkart.com"},
    "myntra": {"myntra.com"},
    "swiggy": {"swiggy.com", "swiggy.in"},
    "zomato": {"zomato.com"},
    "irctc": {"irctc.co.in", "irctc.com"},
    "bookmyshow": {"bookmyshow.com"},
    "tataneu": {"tataneu.com"},
    "jio": {"jio.com", "ril.com"},
    "airtel": {"airtel.in", "airtel.com"},
    "fastag": {"ihmcl.com", "ihmcl.co.in", "netc.org.in"},
    "mcgm": {"mcgm.gov.in"},
    "parkplus": {"parkplus.io", "parkplus.in"},
    "uber": {"uber.com"},
    "ola": {"olacabs.com"},
    # global tech
    "google": {"google.com", "google.co.in", "gstatic.com", "googleapis.com", "goo.gl", "youtube.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "windows.com", "azure.com", "msn.com"},
    "apple": {"apple.com", "icloud.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "citypark": {"citypark.example"},          # demo business used in the live demo
}

# Hand-curated well-known registered domains (global + India). A link on one of these is first-party
# content of a large, takedown-responsive operator, so the model's lexical doubts are discounted.
# Platforms that let anyone publish (see USER_CONTENT_HOSTS) are excluded on purpose.
KNOWN_GOOD: Set[str] = {
    "google.com", "google.co.in", "youtube.com", "gmail.com", "wikipedia.org", "wikimedia.org", "facebook.com",
    "instagram.com", "whatsapp.com", "twitter.com", "x.com", "linkedin.com", "microsoft.com", "live.com",
    "office.com", "outlook.com", "apple.com", "icloud.com", "amazon.com", "amazon.in", "netflix.com",
    "spotify.com", "github.com", "gitlab.com", "stackoverflow.com", "python.org", "mozilla.org", "reddit.com",
    "yahoo.com", "bing.com", "duckduckgo.com", "zoom.us", "dropbox.com", "adobe.com", "paypal.com", "ebay.com",
    "cloudflare.com", "medium.com", "quora.com", "imdb.com", "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com",
    "telegram.org", "signal.org", "slack.com", "notion.so", "canva.com", "figma.com", "kaggle.com", "arxiv.org", "springer.com", "ieee.org", "acm.org", "nptel.ac.in",
    # India: payments, banks, commerce, travel, telecom, media, government
    "paytm.com", "phonepe.com", "razorpay.com", "bhimupi.org.in", "npci.org.in", "sbi.co.in", "onlinesbi.sbi",
    "onlinesbi.com", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com", "pnbindia.in", "yesbank.in",
    "idfcfirstbank.com", "bankofbaroda.in", "canarabank.com", "unionbankofindia.co.in", "flipkart.com",
    "myntra.com", "ajio.com", "nykaa.com", "bigbasket.com", "blinkit.com", "zeptonow.com", "swiggy.com",
    "zomato.com", "irctc.co.in", "makemytrip.com", "goibibo.com", "redbus.in", "cleartrip.com", "ixigo.com",
    "bookmyshow.com", "olacabs.com", "uber.com", "jio.com", "airtel.in", "myvi.in", "bsnl.co.in", "tataneu.com",
    "tatacliq.com", "jiocinema.com", "hotstar.com", "ndtv.com", "thehindu.com", "timesofindia.com",
    "hindustantimes.com", "indianexpress.com", "moneycontrol.com", "zerodha.com", "groww.in", "upstox.com",
    "policybazaar.com", "lic.in", "licindia.in", "uidai.gov.in", "incometax.gov.in", "digilocker.gov.in",
    "india.gov.in", "mygov.in", "gst.gov.in", "epfindia.gov.in", "passportindia.gov.in", "parivahan.gov.in",
    "nic.in", "mcgm.gov.in", "mu.ac.in", "spit.ac.in", "iitb.ac.in", "iitd.ac.in", "bits-pilani.ac.in",
    "citypark.example",
}

# Platforms that serve arbitrary user content: a "well known" domain here is NOT evidence of safety.
USER_CONTENT_HOSTS: Set[str] = {
    "pages.dev", "workers.dev", "netlify.app", "vercel.app", "github.io", "gitlab.io", "firebaseapp.com",
    "web.app", "weebly.com", "wixsite.com", "wix.com", "godaddysites.com", "blogspot.com", "wordpress.com",
    "sites.google.com", "docs.google.com", "forms.gle", "drive.google.com", "storage.googleapis.com",
    "herokuapp.com", "glitch.me", "repl.co", "replit.app", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "duckdns.org", "no-ip.org", "000webhostapp.com", "infinityfreeapp.com", "ipfs.io", "infura-ipfs.io",
    "cloudflare-ipfs.com", "dweb.link", "mybluehost.me", "framer.app", "carrd.co", "webflow.io", "square.site",
    "typeform.com", "jotform.com", "notion.site", "s3.amazonaws.com", "azurewebsites.net", "r2.dev",
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "ow.ly", "rebrand.ly", "rb.gy", "shorturl.at",
}

# Registry-restricted suffixes: ordinary people cannot register under these.
RESTRICTED_SUFFIXES = ("gov.in", "nic.in", "ac.in", "edu.in", "res.in", "mil.in", "gov", "edu", "mil",
                       "gov.uk", "ac.uk", "edu.au", "gov.au", "gov.sg", "edu.sg")

ABUSED_TLDS: Set[str] = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "work", "biz", "monster", "vip", "icu", "buzz",
    "click", "fit", "rest", "cam", "kim", "sbs", "cfd", "online", "site", "shop", "live", "link", "cyou",
    "bond", "lol", "mom", "quest", "support", "surf", "world", "today", "life", "fun", "wang", "men",
}

PHISH_KEYWORDS = (
    "login", "signin", "sign-in", "verify", "verification", "secure", "security", "account", "update",
    "confirm", "authenticate", "otp", "upi", "wallet", "kyc", "refund", "reward", "cashback", "claim",
    "bonus", "gift", "prize", "winner", "lottery", "challan", "fine", "suspend", "unlock", "recover",
    "support", "helpdesk", "customer", "care", "bill", "invoice", "payment", "pay", "recharge", "reactivate",
)

_HOMOGLYPH_SINGLE = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s",
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "ѕ": "s", "х": "x",
    "у": "y", "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ԛ": "q", "ɡ": "g",
}
_HOMOGLYPH_MULTI = (("rn", "m"), ("vv", "w"), ("cl", "d"))
_SPLIT = re.compile(r"[^a-z]+")


def normalize_homoglyphs(text: str) -> str:
    """Map look-alike characters to their ASCII lookalike (0->o, rn->m, Cyrillic а->a ...)."""
    text = unicodedata.normalize("NFKC", text.lower())
    out = "".join(_HOMOGLYPH_SINGLE.get(ch, ch) for ch in text)
    out = "".join(c for c in unicodedata.normalize("NFKD", out) if not unicodedata.combining(c))
    for src, dst in _HOMOGLYPH_MULTI:
        out = out.replace(src, dst)
    return out


def tokens_of(label: str) -> List[str]:
    return [t for t in _SPLIT.split(normalize_homoglyphs(label)) if t]


def is_official(registered: str, brand: str) -> bool:
    official = BRANDS.get(brand, set())
    return any(registered == d or registered.endswith("." + d) for d in official)


def is_restricted_suffix(suffix: str) -> bool:
    return suffix in RESTRICTED_SUFFIXES or any(suffix.endswith("." + s) for s in RESTRICTED_SUFFIXES)


def is_user_content_host(registered: str, host: str) -> bool:
    return registered in USER_CONTENT_HOSTS or host in USER_CONTENT_HOSTS or any(
        host.endswith("." + h) for h in USER_CONTENT_HOSTS)


def is_official_for_any_brand(registered: str) -> bool:
    return any(is_official(registered, b) for b in BRANDS)


@dataclass
class BrandReport:
    impersonation: bool = False          # brand appears in host/sld but domain is not official
    brand: Optional[str] = None
    where: str = ""                      # "sld" | "subdomain" | "typo"
    typosquat: bool = False
    brand_in_path_only: bool = False
    min_norm_dist: float = 1.0           # normalised Levenshtein (0 identical .. 1 unrelated)
    jaro_winkler: float = 0.0
    official: bool = False               # registered domain is an official domain of some brand
    warning: Optional[str] = None


def _brand_in_tokens(brand: str, tokens: Iterable[str]) -> bool:
    toks = list(tokens)
    if brand in toks:
        return True
    if len(brand) >= 6:                  # long names are distinctive enough for substring matching
        return any(brand in t for t in toks)
    return False


def check_brand(parts: HostParts, path: str = "") -> BrandReport:
    """Assess brand impersonation for a split hostname (and, weakly, the URL path)."""
    rep = BrandReport(official=is_official_for_any_brand(parts.registered))
    sld_tokens = tokens_of(parts.sld)
    sub_tokens = [t for lab in parts.subdomain.split(".") if lab for t in tokens_of(lab)]
    sld_norm = normalize_homoglyphs(parts.sld)

    best_dist, best_jw = 1.0, 0.0
    for brand in BRANDS:
        if is_official(parts.registered, brand):
            continue
        if _brand_in_tokens(brand, sld_tokens) and sld_norm != "":
            return BrandReport(True, brand, "sld", False, False, 0.0, 1.0, rep.official,
                               f"The name contains '{brand}' but the site is not an official {brand} domain.")
        if _brand_in_tokens(brand, sub_tokens):
            return BrandReport(True, brand, "subdomain", False, False, 0.0, 1.0, rep.official,
                               f"'{brand}' appears in the subdomain but the real domain is '{parts.registered}'.")
        if len(brand) >= 5 and len(sld_norm) >= 4:
            allowed = 2 if len(brand) >= 9 else 1        # short brands tolerate one edit only
            for cand in [sld_norm, *sld_tokens]:
                if len(cand) < 4 or abs(len(cand) - len(brand)) > 1:
                    continue
                dist = Levenshtein.distance(cand, brand)
                norm = dist / max(len(cand), len(brand))
                if norm < best_dist:
                    best_dist, best_jw = norm, JaroWinkler.similarity(cand, brand)
                if 0 < dist <= allowed:
                    return BrandReport(True, brand, "typo", True, False, norm,
                                       JaroWinkler.similarity(cand, brand), rep.official,
                                       f"'{parts.sld}' looks like a misspelling of '{brand}'.")
        # homoglyph-normalised equality ("paytrn", "ph0nepe", Cyrillic letters)
        if sld_norm == brand and parts.sld != brand:
            return BrandReport(True, brand, "typo", True, False, 0.0, 1.0, rep.official,
                               f"'{parts.sld}' uses look-alike characters to imitate '{brand}'.")

    rep.min_norm_dist, rep.jaro_winkler = best_dist, best_jw
    if path:
        low = path.lower()
        for brand in BRANDS:
            if len(brand) >= 5 and brand in low and not is_official(parts.registered, brand):
                rep.brand_in_path_only = True
                rep.brand = brand
                rep.warning = f"The link path mentions '{brand}' but the site is '{parts.registered}'."
                break
    return rep
