"""
End-to-end evaluation and layer ablation (plan Section 12).

    python -m qrshield evaluate [--scale 1.0]

Builds labelled scenarios, renders each as a simulated photograph, pushes it through the REAL pipeline
(decode -> M1/M2/M3 -> engine) and recombines the stored per-layer outputs to measure URL-only, CV-only,
crypto-only and every combination. Output: docs/results/system_metrics.json (read by the UI and the docs).

Scenario families (good = should end SAFE, bad = should not):
  genuine_unsigned, genuine_signed                          (good)
  phishing_url, sticker_over_unsigned, sticker_over_signed,
  forged_token, rogue_issuer                                (bad)

Honest scope: photos are simulated, the sticker model was trained on the same simulator (different seeds
and sessions), and phishing/benign links come from real corpora when data/url is present. Treat the numbers
as a test of the *fusion design*, not as a field accuracy claim.
"""
from __future__ import annotations

import argparse
import json
import random
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Tuple

import cv2
import numpy as np

from qrshield import config
from qrshield.crypto_layer import generate_keypair, sign_url_token, verify as verify_crypto
from qrshield.cv_layer.simulate import BENIGN_STYLES, SURFACES, TAMPER_STYLES, render_scene
from qrshield.engine import decide

FAMILIES = [  # name, truth, n
    ("genuine_unsigned", "good", 60), ("genuine_signed", "good", 40), ("phishing_url", "bad", 60),
    ("sticker_over_unsigned", "bad", 60), ("sticker_over_signed", "bad", 40), ("forged_token", "bad", 30), ("rogue_issuer", "bad", 20),
]
SIGNED = "https://pay.citypark.example/m/{n}"


def _render(task: Dict[str, Any]) -> bytes:
    scene = render_scene(task["seed"], label=task["label"], surface=task["surface"], style=task["style"],
                         session=task["session"], payload=task["payload"], under_payload=task.get("under"))
    ok, buf = cv2.imencode(".jpg", scene.image, [cv2.IMWRITE_JPEG_QUALITY, 92])
    return buf.tobytes()


def _url_pools() -> Tuple[List[str], List[str], str]:
    from qrshield.url_layer.synthetic import local_business, brand_phishing
    d = config.DATA_DIR / "url"
    rng = random.Random(11)
    try:
        import pandas as pd
        ext = pd.read_parquet(d / "external.parquet")
        rec = pd.read_parquet(d / "recent_phishing.parquet")
        benign = ["https://" + u for u in ext[ext.label == 0].url.sample(300, random_state=5)]
        benign = [u for u in benign if len(u) < 150][:120] + ["https://" + u for u in local_business(120, seed=909)]
        phish = ["https://" + u for u in rec.url.sample(300, random_state=6) if len(u) < 180][:120]
        rng.shuffle(benign)
        return benign, phish, "real corpora (pirocheto benign + 2026 phishing feeds) + synthetic local-business"
    except Exception:
        return (["https://" + u for u in local_business(200, seed=909)],
                ["https://" + u for u in brand_phishing(200, seed=910)], "synthetic only (data/url not built)")


def build_cases(reg, scale: float) -> List[Dict[str, Any]]:
    benign, phish, _ = _url_pools()
    rng = random.Random(2026)
    attacker_priv, _ = generate_keypair()
    rogue_priv, _ = generate_keypair()
    cases: List[Dict[str, Any]] = []
    seed = 7_000_000

    def visual(label: int) -> Dict[str, Any]:
        styles = TAMPER_STYLES if label else BENIGN_STYLES
        return {"surface": rng.choice(SURFACES), "style": rng.choice(styles), "label": label, "session": 300 + rng.randrange(8)}

    def signed(n: int) -> str:
        return reg.sign_for_issuer("citypark-01", SIGNED.format(n=n), f"meter-{n:03d}", 72)["signed_url"]

    for family, truth, n in FAMILIES:
        for i in range(max(1, int(n * scale))):
            seed += 1
            c: Dict[str, Any] = {"family": family, "truth": truth, "seed": seed}
            if family == "genuine_unsigned":
                c.update(visual(0), payload=rng.choice(benign))
            elif family == "genuine_signed":
                c.update(visual(0), payload=signed(i))
            elif family == "phishing_url":
                c.update(visual(0), payload=rng.choice(phish))
            elif family == "sticker_over_unsigned":
                c.update(visual(1), payload=rng.choice(benign), under=rng.choice(benign))
            elif family == "sticker_over_signed":
                real = signed(i)
                c.update(visual(1), payload=SIGNED.format(n=i), under=real)          # clean sticker, token stripped
            elif family == "forged_token":
                real = signed(i)
                forged = real.replace(f"/m/{i}", f"/m/{i + 900}") if f"/m/{i}" in real else real.replace("/m/", "/x/")
                c.update(visual(0), payload=forged)
            else:   # rogue issuer: attacker-signed tokens (half claim the real issuer id, half an unregistered one)
                iss = "citypark-01" if i % 2 == 0 else "rogue-bank"
                priv = attacker_priv if i % 2 == 0 else rogue_priv
                url = sign_url_token(SIGNED.format(n=i), priv, iss, "key-1", "meter-x", iat=int(time.time()), exp=int(time.time()) + 3600)[0]
                c.update(visual(0), payload=url)
            cases.append(c)
    return cases


def combo(case: Dict[str, Any], use_url: bool, use_cv: bool, use_sig: bool) -> Dict[str, Any]:
    L = case["layers"]
    url = L["url_layer"] if use_url else {"score": 0.0, "signals": [], "payload_type": L["url_layer"]["type"]}
    cv = L["cv_layer"] if use_cv else {"score": 0.0, "status": "ok", "signals": []}
    sig = L["crypto_layer"] if use_sig else {"status": "none", "issuer": None}
    return decide({"score": url["score"], "signals": url["signals"], "payload_type": url.get("type", "url")}, cv, sig)


def _pct(x: float) -> float:
    return round(100 * x, 1)


def run(scale: float, workers: int, out: Path, log=print) -> Dict[str, Any]:
    from qrshield.app.api import run_scan
    from qrshield.registry import Registry

    from qrshield.crypto_layer import TrustStore
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        reg = Registry(home=Path(tmp), trust_store=TrustStore()).ensure_ready(seed_demo=True)
        try:
            cases = build_cases(reg, scale)
            log(f"rendering {len(cases)} scenario photos ...")
            with ProcessPoolExecutor(max_workers=workers) as ex:
                images = list(ex.map(_render, cases, chunksize=4))
            log("scanning ...")
            scored, decode_fail = [], 0
            for c, img in zip(cases, images):
                res = run_scan(reg, img, None)
                if not res["success"]:
                    decode_fail += 1
                    continue
                c["layers"], c["decision"], c["elapsed_ms"] = res["layers"], res["decision"], res["elapsed_ms"]
                scored.append(c)
            sanity = verify_crypto(next(c["payload"] for c in scored if c["family"] == "genuine_signed"), reg.store)["status"]
        finally:
            reg.close()

    configs = {"url_only": (1, 0, 0), "cv_only": (0, 1, 0), "crypto_only": (0, 0, 1), "url+cv": (1, 1, 0),
               "url+crypto": (1, 0, 1), "cv+crypto": (0, 1, 1), "all_three": (1, 1, 1)}
    families = [f for f, _, _ in FAMILIES]
    report: Dict[str, Any] = {"generated_at": time.strftime("%Y-%m-%d"), "n_scenarios": len(cases), "n_scanned": len(scored),
                              "decode_failures": decode_fail, "signed_sanity_check": sanity, "url_sources": _url_pools()[2],
                              "simulated_photos": True, "ablation": {}, "verdicts_all_three": {}}
    for name, flags in configs.items():
        verdicts = [(c["family"], c["truth"], combo(c, *flags)["verdict"]) for c in scored]
        row: Dict[str, Any] = {}
        for f in families:
            v = [x[2] for x in verdicts if x[0] == f]
            truth = next(t for ff, t, _ in FAMILIES if ff == f)
            row[f] = {"n": len(v), "flagged_pct": _pct(np.mean([vv != "SAFE" for vv in v])), "blocked_pct": _pct(np.mean([vv == "BLOCK" for vv in v])),
                      "truth": truth}
        good = [x[2] for x in verdicts if x[1] == "good"]
        bad = [x[2] for x in verdicts if x[1] == "bad"]
        row["_summary"] = {"attack_detection_pct": _pct(np.mean([v != "SAFE" for v in bad])),
                           "attack_blocked_pct": _pct(np.mean([v == "BLOCK" for v in bad])),
                           "false_alarm_pct_on_genuine": _pct(np.mean([v != "SAFE" for v in good])),
                           "false_block_pct_on_genuine": _pct(np.mean([v == "BLOCK" for v in good]))}
        report["ablation"][name] = row
    for f in families:
        vs = [c["decision"]["verdict"] for c in scored if c["family"] == f]
        report["verdicts_all_three"][f] = {k: vs.count(k) for k in ("SAFE", "SUSPICIOUS", "BLOCK")}
    lat = sorted(c["elapsed_ms"] for c in scored)
    report["latency_ms"] = {"p50": round(lat[len(lat) // 2], 1), "p95": round(lat[int(len(lat) * 0.95)], 1), "max": round(lat[-1], 1)}

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log(f"wrote {out}")
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", type=Path, default=config.REPO_ROOT / "docs" / "results" / "system_metrics.json")
    a = ap.parse_args()
    rep = run(a.scale, a.workers, a.out)
    print(json.dumps({k: v["_summary"] for k, v in rep["ablation"].items()}, indent=2))
    print("latency", rep["latency_ms"], "decode failures", rep["decode_failures"])
