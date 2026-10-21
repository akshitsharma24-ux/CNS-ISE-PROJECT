"""
SSRF-safe passive URL inspection (F09).

Resolving or fetching an attacker-chosen URL from our server is an SSRF risk. Defences here:
  * only http/https; redirects are followed manually and EVERY hop is re-validated
  * DNS is resolved by us, every returned address must be globally routable, and the socket is
    then connected to that validated IP - there is no second resolution an attacker could
    answer differently (DNS rebinding / TOCTOU)
  * IPv4-mapped / 6to4 / Teredo IPv6 forms are unwrapped and re-checked, and numeric host
    spellings ("2130706433", "0x7f.1") are handled because we validate resolved addresses
  * HEAD requests only, hard timeouts, no cookies, no body read, no JavaScript, max 5 hops
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from qrshield.netutil import safe_urlparse, split_host

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "ow.ly", "buff.ly", "goo.gl", "rebrand.ly",
    "tiny.cc", "qr.ae", "v.gd", "rb.gy", "shorturl.at", "t.ly", "s.id", "lnkd.in", "bit.do", "shorturl.asia",
}
USER_AGENT = "QRshield-SafeInspector/2.0 (+passive-head-only)"


class SSRFBlocked(Exception):
    pass


def is_ip_allowed(ip_str: str) -> Tuple[bool, str]:
    """True only for globally routable unicast addresses."""
    try:
        ip = ipaddress.ip_address(ip_str.strip("[]"))
    except ValueError:
        return False, f"SSRF blocked: invalid IP address {ip_str!r}"
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = ip.ipv4_mapped or ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
        if embedded is not None:
            return is_ip_allowed(str(embedded))
        if ip in ipaddress.ip_network("64:ff9b::/96"):            # NAT64 -> embedded IPv4
            return is_ip_allowed(str(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)))
    if ip.is_loopback:
        return False, f"SSRF blocked: loopback address {ip}"
    if ip.is_link_local:
        return False, f"SSRF blocked: link-local / cloud-metadata address {ip}"
    if ip.is_private:
        return False, f"SSRF blocked: private (RFC1918/ULA) address {ip}"
    if ip.is_multicast:
        return False, f"SSRF blocked: multicast address {ip}"
    if not ip.is_global:                                          # CGNAT, reserved, documentation, 0.0.0.0 ...
        return False, f"SSRF blocked: non-global address {ip}"
    return True, "public address"


def resolve_public(host: str, port: int) -> List[Tuple[int, str]]:
    """Resolve `host` and return validated (family, ip) pairs; raise SSRFBlocked otherwise."""
    if not host:
        raise SSRFBlocked("SSRF blocked: empty hostname")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFBlocked(f"DNS resolution failed for {host}: {exc}") from exc
    pairs = []
    for family, _, _, _, sockaddr in infos:
        ok, reason = is_ip_allowed(sockaddr[0])
        if not ok:
            raise SSRFBlocked(reason)          # one bad record poisons the whole answer
        pairs.append((family, sockaddr[0]))
    if not pairs:
        raise SSRFBlocked(f"no addresses for {host}")
    return pairs


def safe_resolve_host(hostname: str) -> Tuple[bool, str, List[str]]:
    """Backwards-compatible wrapper: (allowed, reason, ips)."""
    try:
        pairs = resolve_public(hostname, 80)
        return True, "OK", [ip for _, ip in pairs]
    except SSRFBlocked as exc:
        return False, str(exc), []


def _connect_validated(host: str, port: int, timeout: float, allow_private: bool = False) -> socket.socket:
    last: Optional[Exception] = None
    if allow_private:                                    # tests only
        return socket.create_connection((host, port), timeout)
    for family, ip in resolve_public(host, port):
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))                     # connect to the IP we validated
            return sock
        except OSError as exc:
            last = exc
    raise OSError(f"could not connect to {host}:{port}: {last}")


class _PinnedHTTP(http.client.HTTPConnection):
    allow_private = False

    def connect(self) -> None:
        self.sock = _connect_validated(self.host, self.port, self.timeout, self.allow_private)


class _PinnedHTTPS(http.client.HTTPSConnection):
    allow_private = False

    def connect(self) -> None:
        raw = _connect_validated(self.host, self.port, self.timeout, self.allow_private)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)


def head_once(url: str, timeout: float = 3.0, allow_private: bool = False) -> Tuple[int, Dict[str, str]]:
    """One HEAD request, no redirects. Raises SSRFBlocked / OSError / ssl.SSLError."""
    p = safe_urlparse(url)
    if p is None or p.scheme not in ("http", "https") or not p.hostname:
        raise SSRFBlocked("SSRF blocked: only absolute http(s) URLs are fetched")
    port = p.port or (443 if p.scheme == "https" else 80)
    cls = _PinnedHTTPS if p.scheme == "https" else _PinnedHTTP
    conn = cls(p.hostname, port, timeout=timeout)
    conn.allow_private = allow_private
    try:
        target = (p.path or "/") + (f"?{p.query}" if p.query else "")
        conn.request("HEAD", target, headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}
    finally:
        conn.close()


def expand_and_inspect_redirects(
    url: str, max_hops: int = 5, timeout: float = 3.0, allow_private: bool = False
) -> Dict[str, Any]:
    """Trace redirects hop by hop (validating each) and report what a shortener hides."""
    hops: List[str] = [url]
    first = safe_urlparse(url)
    base = {"safe": True, "error": None, "initial_url": url, "final_url": url, "hop_count": 0, "hops": hops,
            "shortener_used": False, "domain_changed": False, "tld_changed": False, "signals": [], "reached": False}
    if first is None or first.scheme not in ("http", "https"):
        return {**base, "safe": False, "error": "Disallowed scheme. Only http/https are inspected."}

    init_host = (first.hostname or "").lower()
    init_parts = split_host(init_host)
    shortener = init_host in KNOWN_SHORTENERS or init_parts.registered in KNOWN_SHORTENERS
    current = url
    for hop in range(max_hops):
        try:
            status, headers = head_once(current, timeout, allow_private)
        except SSRFBlocked as exc:
            base.update(safe=False, error=str(exc), final_url=current, hop_count=hop, shortener_used=shortener)
            base["signals"] = [{"name": "ssrf_blocked", "value": current,
                                "text": f"A redirect pointed at a non-public address and was not followed ({exc})."}]
            return base
        except (OSError, ssl.SSLError, http.client.HTTPException):
            break                                    # network trouble is not a verdict
        base["reached"] = True
        loc = headers.get("location")
        if status in (301, 302, 303, 307, 308) and loc:
            current = urljoin(current, loc)
            hops.append(current)
            nxt = safe_urlparse(current)
            if nxt is None or nxt.scheme not in ("http", "https"):
                break
            nh = (nxt.hostname or "").lower()
            shortener = shortener or nh in KNOWN_SHORTENERS or split_host(nh).registered in KNOWN_SHORTENERS
        else:
            break

    final = safe_urlparse(current)
    final_parts = split_host((final.hostname or "") if final else "")
    domain_changed = bool(final_parts.registered) and final_parts.registered != init_parts.registered
    base.update(final_url=current, hop_count=len(hops) - 1, shortener_used=shortener,
                domain_changed=domain_changed,
                tld_changed=bool(final_parts.suffix) and final_parts.suffix != init_parts.suffix)
    signals = []
    if shortener:
        signals.append({"name": "url_shortener", "value": True, "text": "A URL shortener hides the real destination."})
    if base["hop_count"] > 1:
        signals.append({"name": "multiple_redirects", "value": base["hop_count"],
                        "text": f"The link bounces through {base['hop_count']} redirects."})
    if domain_changed and base["reached"]:
        signals.append({"name": "domain_redirect_mismatch",
                        "value": {"from": init_parts.registered, "to": final_parts.registered},
                        "text": f"The link redirects from '{init_parts.registered}' to '{final_parts.registered}'."})
    base["signals"] = signals
    return base
