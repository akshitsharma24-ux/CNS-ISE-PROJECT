"""Network-security properties of the analyser itself: SSRF guard, DNS pinning, redirect re-validation."""
import http.server
import socket
import threading

import pytest

from qrshield.url_layer import fetch_safe
from qrshield.url_layer.fetch_safe import SSRFBlocked, expand_and_inspect_redirects, head_once, is_ip_allowed, resolve_public


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "127.1.2.3", "10.0.0.1", "172.16.5.5", "172.31.255.255", "192.168.1.1", "169.254.169.254",
    "100.64.0.1", "0.0.0.0", "224.0.0.1", "240.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1",
    "::ffff:10.0.0.1", "2002:7f00:0001::1", "64:ff9b::7f00:1", "192.0.2.1", "198.51.100.7",
])
def test_non_public_addresses_are_rejected(ip):
    allowed, reason = is_ip_allowed(ip)
    assert not allowed and "SSRF blocked" in reason


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(ip):
    assert is_ip_allowed(ip)[0]


@pytest.mark.parametrize("sneaky", ["2130706433", "0x7f.1", "0177.0.0.1", "127.1", "localhost", "[::1]"])
def test_numeric_and_alias_spellings_of_loopback_are_blocked_after_resolution(sneaky):
    with pytest.raises(SSRFBlocked):
        resolve_public(sneaky, 80)


def test_one_private_record_poisons_a_mixed_dns_answer(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 80))])
    with pytest.raises(SSRFBlocked):
        resolve_public("rebind.example", 80)


def test_connection_uses_the_validated_ip_without_a_second_resolution(monkeypatch):
    """DNS rebinding: the 2nd lookup would return a private IP. We must resolve exactly once and connect to that IP."""
    calls = {"n": 0}
    connected = {}

    def fake_getaddrinfo(host, port, *a, **k):
        calls["n"] += 1
        ip = "93.184.216.34" if calls["n"] == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    class FakeSock:
        def settimeout(self, t): pass
        def connect(self, addr): connected["addr"] = addr; raise OSError("stop here")
        def close(self): pass

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(socket, "socket", lambda *a, **k: FakeSock())
    with pytest.raises(OSError):
        fetch_safe._connect_validated("rebind.example", 80, 1.0)
    assert calls["n"] == 1 and connected["addr"][0] == "93.184.216.34"


def test_real_connection_to_loopback_is_refused_by_default():
    with pytest.raises(SSRFBlocked):
        head_once("http://127.0.0.1:9/")


def test_non_http_schemes_refused():
    for url in ("file:///etc/passwd", "gopher://x/", "ftp://x/", "javascript:1"):
        with pytest.raises(SSRFBlocked):
            head_once(url)


class _Redirector(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        if self.path == "/start":
            self.send_response(302); self.send_header("Location", "/hop2")
        elif self.path == "/hop2":
            self.send_response(302); self.send_header("Location", "/final")
        else:
            self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture()
def local_server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Redirector)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_pinned_connection_works_and_follows_redirects_when_private_allowed(local_server):
    status, headers = head_once(f"http://127.0.0.1:{local_server}/start", allow_private=True)
    assert status == 302 and headers["location"] == "/hop2"
    res = expand_and_inspect_redirects(f"http://127.0.0.1:{local_server}/start", allow_private=True)
    assert res["hop_count"] == 2 and res["final_url"].endswith("/final") and res["reached"]


def test_redirect_to_internal_address_is_not_followed(monkeypatch):
    seen = []

    def fake_head(url, timeout=3.0, allow_private=False):
        seen.append(url)
        if "169.254.169.254" in url:
            raise SSRFBlocked("SSRF blocked: link-local / cloud-metadata address 169.254.169.254")
        return 302, {"location": "http://169.254.169.254/latest/meta-data/"}

    monkeypatch.setattr(fetch_safe, "head_once", fake_head)
    res = expand_and_inspect_redirects("https://bit.ly/abc")
    assert res["safe"] is False and res["signals"][0]["name"] == "ssrf_blocked"
    assert seen[-1].startswith("http://169.254.169.254")


def test_shortener_reveals_domain_switch(monkeypatch):
    chain = {"https://bit.ly/x": (301, {"location": "https://secure-phonepe-refund.xyz/claim"}),
             "https://secure-phonepe-refund.xyz/claim": (200, {})}
    monkeypatch.setattr(fetch_safe, "head_once", lambda url, timeout=3.0, allow_private=False: chain[url])
    res = expand_and_inspect_redirects("https://bit.ly/x")
    names = {s["name"] for s in res["signals"]}
    assert {"url_shortener", "domain_redirect_mismatch"} <= names and res["final_url"].startswith("https://secure-phonepe")
