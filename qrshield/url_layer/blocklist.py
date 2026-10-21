"""
Local threat-intelligence cache used as a hard override (F10).

Entries are registered domains or exact scheme-less URLs, loaded from
  <home>/blocklist.txt                  (refresh with `python -m qrshield blocklist-update`)
  qrshield/url_layer/data/blocklist_demo.txt   (documentation/test entries only)
A hit forces BLOCK regardless of the model. Deliberately small: the ML model, not this list,
is what catches *new* campaigns (the live-demo phishing domain is NOT on any list).
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional, Set

from qrshield import config
from qrshield.netutil import normalise_url, registered_domain_of

_DEMO = Path(__file__).parent / "data" / "blocklist_demo.txt"
_LOCK = threading.Lock()
_STATE = {"mtime": None, "domains": set(), "urls": set()}


def _read(path: Path) -> list[str]:
    try:
        return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def _refresh() -> None:
    user = config.home_dir() / "blocklist.txt"
    stamp = (user.stat().st_mtime if user.exists() else 0, _DEMO.stat().st_mtime if _DEMO.exists() else 0)
    with _LOCK:
        if _STATE["mtime"] == stamp:
            return
        domains: Set[str] = set()
        urls: Set[str] = set()
        for entry in _read(_DEMO) + _read(user):
            n = normalise_url(entry)
            if not n:
                continue
            if "/" in n.rstrip("/"):
                urls.add(n.rstrip("/").lower())
            else:
                domains.add(registered_domain_of(n).lower())
        _STATE.update(mtime=stamp, domains=domains, urls=urls)


def match(url: str) -> Optional[str]:
    """Return the matching entry ("domain" or "url") or None."""
    _refresh()
    n = normalise_url(url)
    if not n:
        return None
    if n.rstrip("/").lower() in _STATE["urls"]:
        return n
    dom = registered_domain_of(n).lower()
    return dom if dom in _STATE["domains"] else None


def update_from_openphish(timeout: float = 20.0) -> int:
    """Download the OpenPhish community feed into <home>/blocklist.txt; returns entry count."""
    import requests
    text = requests.get("https://openphish.com/feed.txt", timeout=timeout).text
    lines = [l.strip() for l in text.splitlines() if l.strip().startswith(("http://", "https://"))]
    (config.home_dir() / "blocklist.txt").write_text("\n".join(lines), encoding="utf-8")
    _STATE["mtime"] = None
    return len(lines)
