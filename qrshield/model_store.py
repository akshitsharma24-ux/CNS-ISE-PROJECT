"""
Model artefact discovery, versioning and hot reload (F35).

Layout:
  qrshield/models/<kind>_model.joblib            shipped with the repo (version "bundled")
  <home>/models/<kind>/<version>.joblib          retrained candidates that passed the gate
  <home>/models/<kind>/active.json               {"version": "...", "file": "..."}

`load(kind)` returns the active artefact and transparently picks up a newly promoted
version without restarting the server.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import joblib

from qrshield import config

_LOCK = threading.RLock()
_CACHE: Dict[str, Tuple[Tuple[str, float], Any]] = {}


def bundled_path(kind: str) -> Path:
    return config.BUNDLED_MODELS_DIR / f"{kind}_model.joblib"


def versions_dir(kind: str) -> Path:
    d = config.home_dir() / "models" / kind
    d.mkdir(parents=True, exist_ok=True)
    return d


def _active_pointer(kind: str) -> Optional[Path]:
    ptr = config.home_dir() / "models" / kind / "active.json"
    if not ptr.exists():
        return None
    try:
        data = json.loads(ptr.read_text(encoding="utf-8"))
        path = versions_dir(kind) / data["file"]
        return path if path.exists() else None
    except (OSError, ValueError, KeyError):
        return None


def active_path(kind: str) -> Optional[Path]:
    return _active_pointer(kind) or (bundled_path(kind) if bundled_path(kind).exists() else None)


def load(kind: str) -> Optional[Dict[str, Any]]:
    """Return the active model artefact dict for `kind` ("url" | "cv"), or None if none exists."""
    path = active_path(kind)
    if path is None:
        return None
    key = (str(path), path.stat().st_mtime)
    with _LOCK:
        cached = _CACHE.get(kind)
        if cached and cached[0] == key:
            return cached[1]
        artefact = joblib.load(path)
        _CACHE[kind] = (key, artefact)
        return artefact


def promote(kind: str, version: str, artefact: Dict[str, Any]) -> Path:
    """Persist `artefact` as `version` and make it the active model."""
    d = versions_dir(kind)
    fname = f"{version}.joblib"
    joblib.dump(artefact, d / fname)
    (d / "active.json").write_text(json.dumps({"version": version, "file": fname}), encoding="utf-8")
    with _LOCK:
        _CACHE.pop(kind, None)
    return d / fname


def active_version(kind: str) -> str:
    art = load(kind)
    return str(art.get("version", "bundled")) if art else "none"


def reset_cache() -> None:
    with _LOCK:
        _CACHE.clear()
