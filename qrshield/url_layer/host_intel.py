"""
Optional live host intelligence: domain age via RDAP (F07).

Disabled by default so scans stay offline-safe and deterministic. Enable with
QRSHIELD_LIVE_HOST_INTEL=1. Results are cached on disk (24 h) and every failure degrades to
"unknown" - a slow or blocked lookup must never break or delay a scan beyond the timeout.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from qrshield import config

TTL_SECONDS = 24 * 3600
TIMEOUT_SECONDS = 2.5
RDAP_ENDPOINT = "https://rdap.org/domain/{domain}"

def enabled() -> bool:
    return os.environ.get("QRSHIELD_LIVE_HOST_INTEL", "0").lower() in ("1", "true", "yes")


def _cache_path():
    return config.home_dir() / "host_intel_cache.json"


def _load_cache() -> Dict[str, Any]:
    try:
        return json.loads(_cache_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def lookup(registered_domain: str) -> Dict[str, Any]:
    """Return {"age_days": int|None, "source": str}. Never raises."""
    if not enabled():
        return {"age_days": None, "source": "disabled"}

    cache = _load_cache()
    hit = cache.get(registered_domain)
    if hit and time.time() - hit.get("ts", 0) < TTL_SECONDS:
        return {"age_days": hit.get("age_days"), "source": "cache"}

    age: Optional[int] = None
    try:
        import requests
        r = requests.get(RDAP_ENDPOINT.format(domain=registered_domain), timeout=TIMEOUT_SECONDS,
                         headers={"Accept": "application/rdap+json"})
        if r.ok:
            for ev in r.json().get("events", []):
                if ev.get("eventAction") == "registration":
                    created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                    age = max(0, (datetime.now(timezone.utc) - created).days)
                    break
    except Exception:
        age = None
    cache[registered_domain] = {"age_days": age, "ts": time.time()}
    try:
        _cache_path().write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        pass
    return {"age_days": age, "source": "rdap"}
