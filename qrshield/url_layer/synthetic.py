"""
Synthetic QR-style URLs (clearly labelled as synthetic everywhere they are used).

Public phishing corpora know little about the *Indian quishing* setting this project targets
(UPI/bank brand lookalikes) and their benign URLs are random web pages rather than the
local-business pages that QR codes usually point to (parking meters, menus, event passes).
These generators fill that gap with seeded, reproducible examples. They are mixed into the
training pool but excluded from every reported evaluation metric.
"""
from __future__ import annotations

import random
from typing import List, Tuple

from qrshield.url_layer.brands import BRANDS, ABUSED_TLDS

_AFFIX = ["secure", "verify", "login", "update", "refund", "kyc", "reward", "cashback", "support", "help",
          "claim", "offer", "bonus", "care", "alert", "pay", "wallet", "upi", "recharge", "account", "service"]
_BAD_TLD = sorted(ABUSED_TLDS) + ["com", "in", "net", "co", "info", "org"]
_PHISH_PATHS = ["", "/", "/login.php", "/verify/otp", "/kyc/update.html", "/claim?ref=", "/secure/index.php",
                "/upi/collect?id=", "/account/confirm", "/refund/status", "/wallet/topup", "/auth/signin.aspx",
                "/pay/confirm?txn=", "/reward/redeem.html", "/support/ticket", "/update-details"]
_BRAND_PATHS = ["/", "/pay", "/help/contact-us", "/personal/cards", "/offers/festive-2025", "/support/faq?topic=upi",
                "/login", "/business/solutions", "/about-us", "/careers/jobs", "/download", "/recharge/mobile",
                "/account/overview", "/track-order?id=4821", "/security/tips"]
_BIZ_WORDS = ["chai", "bistro", "cafe", "udupi", "dosa", "pizza", "bakery", "clinic", "dental", "gym", "salon",
              "parking", "garage", "metro", "mall", "cinema", "expo", "conclave", "college", "library", "hostel",
              "temple", "trust", "society", "market", "mart", "hotel", "lodge", "tours", "travels", "books", "fresh"]
_BIZ_PATHS = ["/menu", "/menu/dinner", "/m/42", "/pay?table=7", "/book", "/events/2026", "/tickets/checkout?id=88",
              "/feedback", "/wifi", "/parking/slot-14", "/offers", "/contact", "/p/42", "/order/12345", "/rate-us",
              "/", "/scan/entry", "/visitor/register", "/docs/brochure.pdf", "/location/andheri-west"]
_BIZ_TLDS = ["com", "in", "co.in", "org", "net", "org.in", "io", "app", "shop", "store"]


def _typo(word: str, rng: random.Random) -> str:
    if len(word) < 5:
        return word
    i = rng.randrange(1, len(word) - 1)
    op = rng.choice(["swap", "drop", "dup", "sub"])
    if op == "swap":
        return word[:i] + word[i + 1] + word[i] + word[i + 2:]
    if op == "drop":
        return word[:i] + word[i + 1:]
    if op == "dup":
        return word[:i] + word[i] + word[i:]
    return word[:i] + rng.choice("aeiou0135") + word[i + 1:]


def brand_phishing(n: int, seed: int = 7) -> List[str]:
    """Lookalike-domain URLs impersonating the brands in BRANDS (label = phishing)."""
    rng = random.Random(seed)
    brands = [b for b in BRANDS if b != "citypark" and len(b) >= 4]
    out: List[str] = []
    for _ in range(n):
        brand = rng.choice(brands)
        tld = rng.choice(_BAD_TLD)
        aff, aff2 = rng.choice(_AFFIX), rng.choice(_AFFIX)
        style = rng.randrange(7)
        if style == 0:
            host = f"{brand}-{aff}.{tld}"
        elif style == 1:
            host = f"{aff}-{brand}-{aff2}.{tld}"
        elif style == 2:
            host = f"{brand}{aff}.{tld}"
        elif style == 3:
            host = f"{brand}.com.{aff}-{rng.choice(_AFFIX)}.{tld}"
        elif style == 4:
            host = f"{_typo(brand, rng)}.{tld}"
        elif style == 5:
            host = f"{aff}.{brand}.{rng.choice(_BIZ_WORDS)}{rng.randrange(10, 999)}.{tld}"
        else:
            host = f"{brand}-{aff}-{rng.randrange(1, 99)}.{tld}"
        out.append(host + rng.choice(_PHISH_PATHS))
    return out


def brand_official(n: int, seed: int = 11) -> List[str]:
    """Genuine brand URLs with realistic paths (label = benign)."""
    rng = random.Random(seed)
    domains = sorted({d for ds in BRANDS.values() for d in ds if d != "citypark.example"})
    out = []
    for _ in range(n):
        d = rng.choice(domains)
        sub = rng.choice(["", "www.", "", "pay.", "help.", "retail.", "m.", "secure.", "login."])
        sub = "" if sub == "www." else sub
        out.append(f"{sub}{d}{rng.choice(_BRAND_PATHS)}")
    return out


def local_business(n: int, seed: int = 13) -> List[str]:
    """QR-style local business pages: parking meters, menus, event passes (label = benign)."""
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        word = rng.choice(_BIZ_WORDS)
        name = rng.choice([f"{word}{rng.choice(_BIZ_WORDS)}", f"{word}-{rng.choice(_BIZ_WORDS)}",
                           f"{rng.choice(['sai','shree','royal','city','new','om','star','metro','green'])}{word}"])
        sub = rng.choice(["", "", "pay.", "order.", "www.", "book."])
        sub = "" if sub == "www." else sub
        out.append(f"{sub}{name}.{rng.choice(_BIZ_TLDS)}{rng.choice(_BIZ_PATHS)}")
    return out


def all_synthetic(seed: int = 5, n_phish: int = 4000, n_official: int = 1500, n_local: int = 3500) -> List[Tuple[str, int, str]]:
    rows = [(u, 1, "synthetic_brand_phish") for u in brand_phishing(n_phish, seed)]
    rows += [(u, 0, "synthetic_brand_official") for u in brand_official(n_official, seed + 1)]
    rows += [(u, 0, "synthetic_local_business") for u in local_business(n_local, seed + 2)]
    return rows
