"""
Human-gated continuous learning (F35).

  reports -> admin approves -> candidate trained on base corpus + approved rows
          -> candidate vs active on a FIXED benchmark + canary links -> promoted only if not worse

Because every row is approved by a person and the gate re-checks the fixed benchmark, an attacker who
mass-reports good links as bad (or vice versa) cannot silently poison the live model.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict

from qrshield import model_store
from qrshield.netutil import normalise_url
from qrshield.registry import Registry

_STATE: Dict[str, Any] = {"running": False, "last": None}
_LOCK = threading.Lock()


def status() -> Dict[str, Any]:
    with _LOCK:
        return dict(_STATE)


def run(registry: Registry) -> Dict[str, Any]:
    """Synchronous retrain + gate + (maybe) promote. Returns the report that is also stored."""
    from qrshield.url_layer import train

    started = time.time()
    approved = [r for r in registry.approved_reports() if r["user_label"] in ("phishing", "benign") and normalise_url(r["url"])]
    urls = [r["url"] for r in approved]
    labels = [1 if r["user_label"] == "phishing" else 0 for r in approved]

    active = model_store.load("url")
    candidate = train.retrain(urls, labels)
    bench_urls, bench_y = train.load_benchmark()
    passed, gate_report = train.gate(active, candidate, bench_urls, bench_y)

    n_versions = len(registry.list_model_versions("url"))
    version = f"v{n_versions + 1}-{time.strftime('%Y%m%d-%H%M')}"
    candidate["version"] = version
    summary = {"version": version, "promoted": passed, "approved_reports_used": len(urls),
               "seconds": round(time.time() - started, 1), "gate": gate_report}
    if passed:
        model_store.promote("url", version, candidate)
        registry.mark_reports_used([r["report_id"] for r in approved], version)
        registry.record_model_version("url", version, "active", gate_report["candidate"], note=f"+{len(urls)} approved reports")
        registry.audit("model.promote", version, f"reports={len(urls)}")
    else:
        failed = [k for k, ok in gate_report["checks"].items() if not ok]
        registry.record_model_version("url", version, "rejected", gate_report["candidate"], note="gate failed: " + ", ".join(failed))
        registry.audit("model.reject", version, "gate failed: " + ", ".join(failed))
    return summary


def run_in_background(registry: Registry) -> bool:
    """Start a retrain thread unless one is already running. Returns True if started."""
    with _LOCK:
        if _STATE["running"]:
            return False
        _STATE.update(running=True, last=None)

    def work() -> None:
        try:
            result = run(registry)
        except Exception as exc:                      # surfaced in the admin UI, never crashes the server
            result = {"error": f"{type(exc).__name__}: {exc}"}
        with _LOCK:
            _STATE.update(running=False, last=result)

    threading.Thread(target=work, name="qrshield-retrain", daemon=True).start()
    return True
