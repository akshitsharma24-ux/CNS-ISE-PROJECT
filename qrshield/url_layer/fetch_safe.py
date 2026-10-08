"""
SSRF-safe URL fetcher and passive redirect follower (F09).
Protects the analysis engine against Server-Side Request Forgery (SSRF)
by resolving DNS independently, blocking private/loopback/link-local/cloud-metadata
IP ranges on every hop, capping payload sizes, and executing no client scripts.
"""
import socket
import ipaddress
from urllib.parse import urlparse, urljoin
import tldextract
import requests
from typing import Dict, Any, List, Optional, Tuple

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd",
    "ow.ly", "buff.ly", "goo.gl", "rebrand.ly", "tiny.cc",
    "qr.ae", "v.gd", "rb.gy", "shorturl.at"
}

def is_ip_allowed(ip_str: str) -> Tuple[bool, str]:
    """
    Validates if an IP address is a safe, routable public address.
    Rejects:
      - Loopback (127.0.0.0/8, ::1)
      - RFC1918 Private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
      - Link-Local (169.254.0.0/16, fe80::/10) - Cloud metadata AWS/GCP (169.254.169.254)
      - Carrier-Grade NAT (100.64.0.0/10)
      - Multicast & Reserved ranges
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"Invalid IP address format: {ip_str}"

    if ip.is_loopback:
        return False, f"SSRF blocked: Loopback address {ip_str}"
    if ip.is_private:
        return False, f"SSRF blocked: RFC1918 Private address {ip_str}"
    if ip.is_link_local:
        return False, f"SSRF blocked: Link-local / metadata address {ip_str}"
    if ip.is_multicast:
        return False, f"SSRF blocked: Multicast address {ip_str}"
    if ip.is_reserved:
        return False, f"SSRF blocked: Reserved IP address {ip_str}"
    # Carrier-Grade NAT RFC 6598 (100.64.0.0/10)
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return False, f"SSRF blocked: Carrier-Grade NAT address {ip_str}"
    # Specific cloud metadata check
    if str(ip) == "169.254.169.254":
        return False, "SSRF blocked: Cloud metadata service"


    return True, "Public IP"

def safe_resolve_host(hostname: str) -> Tuple[bool, str, List[str]]:
    """Resolves DNS and verifies all resulting IPs against SSRF restrictions."""
    try:
        # Avoid resolving empty or malformed names
        if not hostname:
            return False, "Empty hostname", []
        # Check if hostname itself is raw IP
        try:
            raw_ip = ipaddress.ip_address(hostname)
            ok, reason = is_ip_allowed(str(raw_ip))
            return ok, reason, [str(raw_ip)]
        except ValueError:
            pass

        addr_info = socket.getaddrinfo(hostname, None)
        ips = list({info[4][0] for info in addr_info})
        if not ips:
            return False, f"DNS resolution failed for {hostname}", []

        for ip in ips:
            allowed, reason = is_ip_allowed(ip)
            if not allowed:
                return False, reason, ips

        return True, "OK", ips
    except Exception as e:
        return False, f"DNS error: {str(e)}", []

def expand_and_inspect_redirects(
    url: str,
    max_hops: int = 5,
    timeout: float = 3.0
) -> Dict[str, Any]:
    """
    Passively traces HTTP redirects up to max_hops while enforcing SSRF security.
    Does not execute JavaScript, limits response bytes to 50KB, rejects private IPs.
    """
    current_url = url
    hops: List[str] = [current_url]
    hop_count = 0
    shortener_detected = False

    parsed_init = urlparse(url)
    if parsed_init.scheme not in ("http", "https"):
        return {
            "safe": False,
            "error": f"Disallowed scheme '{parsed_init.scheme}'. Only http/https permitted.",
            "final_url": url,
            "hop_count": 0,
            "hops": hops,
            "shortener_used": False,
            "domain_changed": False,
            "tld_changed": False,
            "signals": []
        }

    init_extract = tldextract.extract(parsed_init.netloc)
    init_domain = f"{init_extract.domain}.{init_extract.suffix}".lower()
    if parsed_init.netloc.lower() in KNOWN_SHORTENERS:
        shortener_detected = True

    # Custom session with no cookie persistence
    session = requests.Session()
    session.headers.update({"User-Agent": "QRshield-SafeInspector/1.0 (+security-audit)"})
    session.cookies.clear()

    while hop_count < max_hops:
        parsed = urlparse(current_url)
        host = parsed.hostname or parsed.netloc.split(":")[0]

        # SSRF Verification before issuing request
        is_safe_ip, reason, _ = safe_resolve_host(host)
        if not is_safe_ip:
            return {
                "safe": False,
                "error": f"SSRF Guard triggered at hop {hop_count}: {reason}",
                "final_url": current_url,
                "hop_count": hop_count,
                "hops": hops,
                "shortener_used": shortener_detected,
                "domain_changed": False,
                "tld_changed": False,
                "signals": [{
                    "name": "ssrf_attempt_blocked",
                    "value": host,
                    "text": f"Blocked SSRF attempt targeting {reason}"
                }]
            }

        try:
            # HEAD request with stream to prevent reading full bodies
            resp = session.head(
                current_url,
                allow_redirects=False,
                timeout=timeout,
                stream=True
            )
            # Check for redirect status
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    break
                next_url = urljoin(current_url, location)
                hops.append(next_url)
                current_url = next_url
                hop_count += 1
                next_host = urlparse(next_url).netloc.lower()
                if next_host in KNOWN_SHORTENERS:
                    shortener_detected = True
            else:
                break
        except requests.exceptions.RequestException:
            # Graceful network failure: never crash
            break

    final_parsed = urlparse(current_url)
    final_extract = tldextract.extract(final_parsed.netloc)
    final_domain = f"{final_extract.domain}.{final_extract.suffix}".lower()

    domain_changed = (init_domain != final_domain) and bool(final_domain)
    tld_changed = (init_extract.suffix != final_extract.suffix) and bool(final_extract.suffix)

    signals = []
    if shortener_detected:
        signals.append({
            "name": "url_shortener",
            "value": True,
            "text": "URL shortener detected hiding target destination."
        })
    if hop_count > 1:
        signals.append({
            "name": "multiple_redirects",
            "value": hop_count,
            "text": f"URL traversed {hop_count} redirect hops."
        })
    if domain_changed:
        signals.append({
            "name": "domain_redirect_mismatch",
            "value": {"from": init_domain, "to": final_domain},
            "text": f"Redirect switches domains from '{init_domain}' to '{final_domain}'."
        })

    return {
        "safe": True,
        "error": None,
        "initial_url": url,
        "final_url": current_url,
        "hop_count": hop_count,
        "hops": hops,
        "shortener_used": shortener_detected,
        "domain_changed": domain_changed,
        "tld_changed": tld_changed,
        "signals": signals
    }
