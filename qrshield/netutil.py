"""
Safe URL / hostname helpers shared by every layer.

QR payloads are attacker-controlled, so nothing here may raise on malformed input
(`urllib.parse` raises ValueError for strings such as "http://[x"). Hostnames are split
with an offline public-suffix snapshot so scanning never blocks on a network fetch.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import ParseResult, urlparse

import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


@dataclass(frozen=True)
class HostParts:
    host: str                 # full hostname, lowercase, no port, no trailing dot
    subdomain: str            # everything left of the registered domain
    sld: str                  # second-level label ("citypark" in pay.citypark.example)
    suffix: str               # public suffix / unknown TLD ("ac.in", "xyz", "example")
    registered: str           # sld + "." + suffix ("citypark.example")
    is_ip: bool

    @property
    def labels(self) -> list[str]:
        return [p for p in self.host.split(".") if p]


def safe_urlparse(url: str) -> Optional[ParseResult]:
    """urlparse that returns None instead of raising on hostile input."""
    try:
        return urlparse(url)
    except (ValueError, TypeError):
        return None


def hostname_of(url: str) -> str:
    parsed = safe_urlparse(url)
    if parsed is None:
        return ""
    try:
        return (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def split_host(host: str) -> HostParts:
    """Split a hostname into subdomain / second-level domain / suffix.

    Unknown TLDs (".example", ".local", new gTLDs missing from the snapshot) are treated as
    a one-label suffix so the registered domain is still "<label>.<tld>".
    """
    host = (host or "").lower().strip().rstrip(".")
    if not host:
        return HostParts("", "", "", "", "", False)
    if is_ip_literal(host):
        return HostParts(host, "", host, "", host, True)

    ext = _EXTRACT(host)
    labels = host.split(".")
    if ext.suffix:
        sub, sld, suffix = ext.subdomain, ext.domain, ext.suffix
    elif len(labels) >= 2:           # unknown TLD: last label acts as the suffix
        suffix, sld = labels[-1], labels[-2]
        sub = ".".join(labels[:-2])
    else:                            # single label such as "localhost"
        sub, sld, suffix = "", labels[0], ""
    registered = f"{sld}.{suffix}" if suffix and sld else sld
    return HostParts(host, sub, sld, suffix, registered, False)


def normalise_url(raw: str, max_len: int = 1500) -> Optional[str]:
    """Scheme-less, www-less, fragment-less URL form; None if it is not a usable web URL."""
    u = (raw or "").strip().strip('"').strip("'")
    if not u or len(u) > max_len or any(c.isspace() for c in u):
        return None
    low = u.lower()
    if "://" in low and not low.startswith(("http://", "https://")):
        return None
    probe = u if "://" in u else "http://" + u
    if safe_urlparse(probe) is None:
        return None
    host = hostname_of(probe)
    if not host or ("." not in host and ":" not in host):
        return None
    u = u.split("#", 1)[0].split("://", 1)[-1]
    return u[4:] if u.lower().startswith("www.") else u


def registered_domain_of(norm: str) -> str:
    host = hostname_of("http://" + norm)
    return split_host(host).registered or host


def is_valid_hostname(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host or len(host) > 253:
        return False
    return all(_HOST_LABEL.match(label) for label in host.split("."))
