"""M1: features, brand logic, UPI, analyzer behaviour."""
import pytest

from qrshield.netutil import split_host
from qrshield.url_layer import analyze, blocklist
from qrshield.url_layer.brands import check_brand, normalize_homoglyphs
from qrshield.url_layer.features import FEATURE_ORDER, extract_features, ngram_text
from qrshield.url_layer.upi import analyze_upi_payload


# ---------------------------------------------------------------- features
def test_scheme_and_www_do_not_change_the_vector():
    a = extract_features("https://www.example-shop.com/menu?id=3").vector
    b = extract_features("http://example-shop.com/menu?id=3").vector
    assert a == b, "scheme/www are collection artefacts and must not be features"


def test_vector_matches_declared_order():
    f = extract_features("https://secure-phonepe-refund.xyz/claim?amt=2000")
    assert len(f.vector) == len(FEATURE_ORDER) and list(f.named) == FEATURE_ORDER


@pytest.mark.parametrize("hostile", ["http://[x", "http://", "http://%", "http://a b/c", "https://" + "a" * 5000 + ".com",
                                     "http://[::1", "http://\x00evil.com", "‮https://evil.com", "http://user:pw@/x", ":::::"],
                         ids=["bad-ipv6", "no-host", "percent", "space", "5000-char-host", "open-bracket", "nul", "rtl-override", "empty-userinfo", "colons"])
def test_hostile_urls_never_raise(hostile):
    r = analyze(hostile, offline=True)
    assert 0.0 <= r["score"] <= 1.0 and r["signals"]


def test_registered_domain_handles_unknown_tlds():
    p = split_host("pay.citypark.example")
    assert (p.sld, p.suffix, p.registered, p.subdomain) == ("citypark", "example", "citypark.example", "pay")
    assert split_host("a.b.spit.ac.in").registered == "spit.ac.in"
    assert split_host("192.168.1.1").is_ip


def test_ngram_text_excludes_scheme():
    assert ngram_text("https://www.Example.com/Path?q=1") == ngram_text("http://example.com/Path?q=1")


# ---------------------------------------------------------------- brands
@pytest.mark.parametrize("url,impersonation", [
    ("https://paytm.xyz/pay", True),                     # right name, wrong domain
    ("https://paytm-kyc-update.top/x", True),
    ("https://phonepe.com.track-delivery.xyz/verify", True),
    ("https://paytrn.com/login", True),                  # rn -> m homoglyph
    ("https://ph0nepe.in/login", True),
    ("http://" + "phоnepe.com".encode("idna").decode() + "/login", True),    # Cyrillic 'o' homograph (punycode)
    ("http://" + "phónepe.com".encode("idna").decode() + "/login", True),    # accented lookalike (punycode)
    ("https://paytm.com/recharge", False),
    ("https://www.amazon.in/gp/help", False),
    ("https://s3.amazonaws.com/b/menu.pdf", False),      # official amazon infrastructure
    ("https://accredited.org/members", False),           # 'cred' inside a word
    ("https://maple.com/", False),                       # one edit from 'apple' but not a brand squat
    ("https://spit.ac.in/departments", False),
])
def test_brand_impersonation(url, impersonation):
    assert extract_features(url).named["brand_impersonation"] == (1.0 if impersonation else 0.0)


def test_homoglyph_normalisation():
    assert normalize_homoglyphs("paytrn") == "paytm"
    assert normalize_homoglyphs("g00gle") == "google"
    assert normalize_homoglyphs("рaytм") == "paytm" or "ayt" in normalize_homoglyphs("рaytм")


def test_brand_report_explains_itself():
    rep = check_brand(split_host("secure-phonepe-refund.xyz"))
    assert rep.impersonation and rep.brand == "phonepe" and "phonepe" in rep.warning


# ---------------------------------------------------------------- analyzer
@pytest.mark.parametrize("url", [
    "https://spit.ac.in/departments/comps", "https://pay.citypark.example/m/42", "https://www.irctc.co.in/nget/train-search",
    "https://en.wikipedia.org/wiki/QR_code", "https://s3.amazonaws.com/bucket/menu.pdf", "https://onlinesbi.sbi/retail/login.htm",
    "https://github.com/akshitsharma24-ux/CNS-ISE-PROJECT", "https://accredited.org/members",
])
def test_known_good_links_score_low(url):
    assert analyze(url, offline=True)["score"] < 0.30


@pytest.mark.parametrize("url", [
    "https://secure-phonepe-refund.xyz/claim-cashback?amt=2000", "https://paytm-kyc-update.top/wallet/kyc-verification.php",
    "https://paytm.xyz/pay", "http://sbi-reward-claim.online/redeem-points/otp.html", "https://paytrn.com/login",
    "http://192.168.1.100:8080/axis-bank/login.action", "https://phonepe.com.track-delivery.xyz/account/verify",
])
def test_phishing_links_reach_block_territory(url):
    r = analyze(url, offline=True)
    assert r["score"] >= 0.65, (url, r["score"])
    assert any(s["direction"] == "risk" for s in r["signals"])


def test_signals_are_plain_language_and_directional():
    r = analyze("https://secure-phonepe-refund.xyz/claim-cashback", offline=True)
    assert all({"name", "value", "text", "direction"} <= set(s) for s in r["signals"])
    assert r["signals"][0]["name"] == "brand_impersonation"


def test_dangerous_schemes_and_nonweb_payloads():
    assert analyze("javascript:alert(1)")["score"] >= 0.9
    assert analyze("WIFI:S:Free;T:nopass;;")["score"] == pytest.approx(0.30)
    assert analyze("tel:+911234")["payload_type"] == "other"
    assert analyze("")["score"] == 0.0


def test_blocklist_is_a_hard_override():
    r = analyze("https://known-bad-demo.example/anything", offline=True)
    assert r["score"] == 1.0 and r["signals"][0]["name"] == "blocklist_match"
    assert blocklist.match("https://qr-parking-fraud.example/pay/session")
    assert not blocklist.match("https://spit.ac.in/")


def test_user_content_hosts_get_no_trust_discount():
    # a well-known *platform* is not evidence the page is safe
    f = extract_features("https://sp18ct10-burvak-biz-qazelo.pages.dev/send_appeal_request")
    assert f.named["user_content_host"] == 1.0


# ---------------------------------------------------------------- UPI
def test_upi_legit_payment():
    r = analyze_upi_payload("upi://pay?pa=citypark@okicici&pn=City%20Parking&mc=7523&am=50")
    assert r["score"] < 0.3 and not r["mismatch"]


def test_upi_payee_mismatch_and_collect_flagged():
    r = analyze_upi_payload("upi://pay?pa=rohit1234@ybl&pn=State%20Bank%20Of%20India&am=1500")
    assert r["mismatch"] and r["score"] >= 0.6
    c = analyze_upi_payload("upi://pay?pa=x@ybl&pn=Shop&mode=04&tr=1")
    assert any(s["name"] == "upi_collect" for s in c["signals"])


def test_upi_malformed_and_mandate():
    assert analyze_upi_payload("upi://pay?pn=NoVpa")["score"] >= 0.5
    assert any(s["name"] == "upi_mandate" for s in analyze_upi_payload("upi://mandate?pa=a@ybl&pn=X")["signals"])
