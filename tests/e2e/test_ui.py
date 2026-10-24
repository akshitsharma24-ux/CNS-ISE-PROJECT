"""
Browser end-to-end tests (Playwright). They start a real server on a free port with an isolated runtime home and
drive the actual UI: scenarios, safe-open flow, admin sign-in, issuer portal, report -> review, XSS resistance.

Run:  pip install playwright && playwright install chromium && pytest -m e2e
They are skipped automatically when Playwright or a browser is unavailable.
"""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

playwright_sync = pytest.importorskip("playwright.sync_api")
pytestmark = pytest.mark.e2e

ROOT = Path(__file__).resolve().parents[2]
TOKEN = "e2e-admin-token"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    port = _free_port()
    env = {**os.environ, "QRSHIELD_HOME": str(tmp_path_factory.mktemp("e2e_home")), "QRSHIELD_ADMIN_TOKEN": TOKEN,
           "QRSHIELD_ONLINE_CHECKS": "0", "PYTHONUNBUFFERED": "1"}
    log = open(tmp_path_factory.mktemp("e2e_log") / "server.log", "wb")        # never PIPE: an unread pipe fills and blocks the server
    proc = subprocess.Popen([sys.executable, "-m", "qrshield", "serve", "--port", str(port)], cwd=ROOT, env=env,
                            stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    import urllib.request
    for _ in range(80):
        try:
            urllib.request.urlopen(f"{base}/api/health", timeout=1)
            break
        except Exception:
            time.sleep(0.5)
    else:
        proc.kill()
        pytest.fail("server did not start")
    yield base
    proc.terminate()
    proc.wait(timeout=10)
    log.close()


@pytest.fixture(scope="module")
def browser():
    fake_camera = ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream"]     # synthetic webcam, auto-allow
    with playwright_sync.sync_playwright() as p:
        launched = None
        for kwargs in ({}, {"channel": "msedge"}, {"channel": "chrome"}):
            try:
                launched = p.chromium.launch(args=fake_camera, **kwargs)
                break
            except Exception:
                continue
        if launched is None:
            pytest.skip("no Chromium-based browser available")
        yield launched
        launched.close()


@pytest.fixture()
def page(browser, server):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.goto(f"{server}/#scan")
    page.wait_for_selector("#scenario-list .scenario")
    yield page
    assert not [e for e in errors if "Failed to load resource" not in e], errors
    ctx.close()


def verdict(page, timeout=60000):
    page.wait_for_selector("#result-body .verdict", timeout=timeout)
    return page.inner_text("#result-body .verdict-word").strip()


def test_page_loads_with_nav_and_models(page):
    assert page.title().startswith("QRshield")
    assert page.locator("[data-nav]").count() == 9
    page.wait_for_selector("#model-chip:has-text('link')")


def test_clean_scenario_is_safe_and_open_is_allowed(page):
    page.click("#scenario-list .scenario:nth-child(1)")
    assert verdict(page) == "SAFE"
    assert page.locator("#result-body .payload").inner_text().startswith("https://spit.ac.in")
    assert page.locator("#result-body button:has-text('Open link')").is_enabled()


def test_phishing_scenario_blocks_and_hides_the_open_button(page):
    page.click("#scenario-list .scenario:nth-child(2)")
    assert verdict(page) == "BLOCK"
    assert page.locator("#result-body button:has-text('Open anyway')").is_hidden()
    page.click("text=Show override options")
    page.check("#confirm-open")
    assert page.locator("#result-body button:has-text('Open anyway')").is_enabled()


def test_signed_scenario_is_certified_and_layer_cards_show_the_chain(page):
    page.click("#scenario-list .scenario:nth-child(3)")
    assert verdict(page) == "SAFE"
    assert page.locator("#result-body .certified").is_visible()
    body = page.inner_text("#result-body")
    assert "City Parking" in body and "pay.citypark.example" in body and "Verified" in body


def test_forged_scenario_blocks_on_signature(page):
    page.click("#scenario-list .scenario:nth-child(5)")
    assert verdict(page) == "BLOCK"
    assert "INVALID" in page.inner_text("#result-body")


def test_link_check_without_a_photo(page):
    page.click("[data-source=link]")
    page.fill("#link-input", "https://paytm-kyc-update.top/wallet")
    page.click("#link-check")
    assert verdict(page) == "BLOCK"
    assert "Not checked" in page.inner_text("#result-body")


def test_issuer_portal_requires_login_then_sign_scan_revoke(page):
    page.click("[data-nav=issuer]")
    page.wait_for_selector("#issuer-gate button")
    page.click("#issuer-gate button")
    page.fill("#login-token", "wrong")
    page.click("#login-send")
    page.wait_for_selector("#login-error:not([hidden])")
    page.fill("#login-token", TOKEN)
    page.click("#login-send")
    page.wait_for_selector("#issuer-body:not([hidden])")
    page.fill("#sign-url", "https://pay.citypark.example/m/77")
    page.click("#sign-form button[type=submit]")
    page.wait_for_selector("#sign-result img")
    assert "valid" in page.inner_text("#sign-result")
    page.click("#sign-result button:has-text('Scan this code now')")
    assert verdict(page) == "SAFE" and page.locator("#result-body .certified").is_visible()
    page.click("[data-nav=issuer]")
    page.wait_for_selector("#issuer-table tbody tr")
    page.once("dialog", lambda d: d.accept())
    page.click("#issuer-table tr:has-text('City Parking') button:has-text('Revoke')")
    page.wait_for_selector("#issuer-table tr:has-text('City Parking') .chip:has-text('Revoked')")


def test_report_then_admin_review_and_xss_is_inert(page):
    page.click("#scenario-list .scenario:nth-child(6)")        # scenario 6 opens the report dialog
    page.wait_for_selector("#report-dialog[open]")
    page.fill("#report-note", "<img src=x onerror=window.__xss=1><script>window.__xss=2</script>")
    page.click("#report-send")
    page.wait_for_selector(".toast:has-text('Report sent')")
    page.click("[data-nav=admin]")
    page.wait_for_selector("#admin-gate button")
    page.click("#admin-gate button")
    page.fill("#login-token", TOKEN)
    page.click("#login-send")
    page.wait_for_selector("#report-table tbody tr td.url")
    assert "<img src=x" in page.inner_text("#report-table")                 # shown as literal text
    assert page.evaluate("window.__xss") is None
    page.click("#report-table button:has-text('Approve')")
    page.wait_for_selector(".toast:has-text('Approved')")


def test_save_report_downloads_a_plain_text_evidence_file(page):
    page.click("#scenario-list .scenario:nth-child(2)")
    assert verdict(page) == "BLOCK"
    with page.expect_download() as dl:
        page.click("#save-report")
    path = dl.value.path()
    text = open(path, encoding="utf-8").read()
    assert dl.value.suggested_filename.startswith("qrshield-report-") and dl.value.suggested_filename.endswith(".txt")
    assert "Verdict        : BLOCK" in text and "SHA-256:" in text and "M3 Signature" in text and "data:image" not in text


def test_architecture_diagram_explains_components_and_runs_a_live_scan(page):
    page.click("[data-nav=how]")
    page.wait_for_selector("#arch-diagram .arch-node")
    page.click("#arch-diagram [data-node=crypto]")
    assert "Ed25519" in page.inner_text("#arch-detail")
    page.click("#arch-run")
    page.wait_for_selector("#arch-status .chip", timeout=60000)
    assert page.locator("#arch-diagram .arch-ms:visible").count() >= 4
    assert "ms on the last scan" in page.inner_text("#arch-detail") or page.locator("#arch-diagram .arch-ms:visible").count() >= 4


def test_crypto_lab_inspector_attack_lab_and_transparency_log(page):
    page.click("[data-nav=lab]")
    page.wait_for_selector("#log-table tbody tr")
    # transparency log: verify an entry in the browser, then "edit" it and watch the proof fail
    page.click("#log-table tbody tr:nth-child(1) button:has-text('Verify')")
    page.wait_for_selector("#log-proof .notice:has-text('is in the log')")
    page.click("#log-table tbody tr:nth-child(1) button:has-text('Edit & verify')")
    page.wait_for_selector("#log-proof .notice:has-text('tampering detected')")
    # append-only check: the first click remembers the head, the second proves the log only grew
    page.click("#log-consistency-btn")
    page.click("#log-consistency-btn")
    page.wait_for_selector("#log-consistency .chip:has-text('append-only')")
    # attack lab needs the admin token
    page.wait_for_selector("#attack-gate button")
    page.click("#attack-gate button")
    page.fill("#login-token", TOKEN)
    page.click("#login-send")
    page.wait_for_selector("#attack-run")
    page.click("#attack-run")
    page.wait_for_selector("#attack-result .notice:has-text('9 of 9')")
    assert page.locator("#attack-result tbody tr").count() == 10
    page.click("#attack-result tr:has-text('Edit the link') button:has-text('Inspect')")
    page.wait_for_selector("#inspect-result .trace-step.st-fail")
    assert "INVALID" in page.inner_text("#inspect-result .trace-head")
    assert page.locator("#inspect-result .trace-step.st-skipped").count() >= 1


@pytest.fixture(scope="module")
def borderline_pair(tmp_path_factory):
    """Two photos (different angle/light) of one scene whose first photo lands in the borderline band."""
    import cv2
    from qrshield.cv_layer import analyze
    from qrshield.cv_layer.simulate import SURFACES, render_scene
    out = tmp_path_factory.mktemp("borderline")
    for i in range(200):
        seed = 7_700_000 + i
        surface = SURFACES[i % len(SURFACES)]
        first = render_scene(seed, label=i % 2, surface=surface, session=700 + i % 5, view=0)
        if analyze(first.image)["status"] == "inconclusive":
            second = render_scene(seed, label=i % 2, surface=surface, session=700 + i % 5, view=1)
            a, b = out / "first.jpg", out / "second.jpg"
            cv2.imwrite(str(a), first.image)
            cv2.imwrite(str(b), second.image)
            return a, b
    pytest.skip("no borderline scene found in 200 tries")


def test_borderline_photo_asks_for_a_second_angle_and_rescoring_works(page, borderline_pair):
    first, second = borderline_pair
    page.set_input_files("#file-gallery", str(first))
    page.click("#scan-btn")
    page.wait_for_selector("#second-photo:not([hidden])", timeout=60000)
    assert "Borderline" in page.inner_text("#result-body")
    page.set_input_files("#file-second", str(second))
    page.wait_for_selector("#second-name:has-text('Second photo ready')")
    page.wait_for_selector("#scan-status:has-text('Done')", timeout=60000)
    page.wait_for_selector("#result-body .verdict")
    assert page.locator("#second-photo").is_hidden(), "with two photos the prompt must go away"
    assert "Borderline" not in page.inner_text("#result-body")


def test_live_camera_start_capture_scan_roundtrip(browser, server):
    """localhost is a secure context, so getUserMedia works; the fake camera shows a test pattern (no QR)."""
    ctx = browser.new_context(permissions=["camera"], viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    page.goto(f"{server}/#scan")
    page.click("[data-source=camera]")
    assert page.locator("#camera-notice").is_hidden(), "no HTTPS warning on localhost"
    page.click("#camera-start")
    page.wait_for_selector("#camera-capture:not([disabled])", timeout=15000)
    page.wait_for_timeout(800)                        # let the fake camera deliver its first frames
    page.click("#camera-capture")
    page.wait_for_selector("#result-body .verdict-word:has-text('NO CODE READ')", timeout=60000)
    assert page.locator("#camera-stop").is_disabled(), "the camera must be released after capturing"
    ctx.close()


def test_camera_tab_explains_the_https_requirement_on_insecure_origins(browser, server):
    """On http://<LAN-IP> getUserMedia is unavailable; the UI must say why instead of failing silently."""
    ctx = browser.new_context()
    page = ctx.new_page()
    page.goto(f"{server}/#scan")
    page.add_init_script("Object.defineProperty(window, 'isSecureContext', {get: () => false});")
    page.reload()
    page.click("[data-source=camera]")
    notice = page.locator("#camera-notice")
    notice.wait_for(state="visible")
    assert "HTTPS" in notice.inner_text() and page.locator("#camera-start").is_disabled()
    ctx.close()


def test_theme_toggle_and_mobile_layout(browser, server):
    ctx = browser.new_context(viewport={"width": 390, "height": 800}, is_mobile=True)
    p = ctx.new_page()
    p.goto(f"{server}/#scan")
    p.wait_for_selector("#scenario-list .scenario")
    assert p.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), "no horizontal scrolling on a phone"
    before = p.evaluate("getComputedStyle(document.body).backgroundColor")
    p.click("#theme-toggle")
    assert p.evaluate("getComputedStyle(document.body).backgroundColor") != before
    ctx.close()

