"""
QRshield command line.

    python -m qrshield setup            # create keys + demo registry, check the install
    python -m qrshield serve            # http://127.0.0.1:8000
    python -m qrshield serve --https --host 0.0.0.0    # phone cameras need HTTPS
    python -m qrshield test             # run the test-suite
    python -m qrshield data             # download public corpora and build the URL training pool
    python -m qrshield train-url|train-cv
    python -m qrshield retrain          # gated retrain from admin-approved reports
    python -m qrshield evaluate         # end-to-end ablation -> docs/results/system_metrics.json
    python -m qrshield demo-assets      # printable QR codes for the live demo
    python -m qrshield blocklist-update # refresh the local OpenPhish cache
    python -m qrshield doctor           # diagnose a broken install
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import socket
import subprocess
import sys
from pathlib import Path

from qrshield import config


def lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def ensure_self_signed_cert() -> tuple[Path, Path]:
    """Create (once) a self-signed certificate valid for localhost and this machine's LAN address."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    d = config.home_dir() / "certs"
    d.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = d / "qrshield-dev.crt", d / "qrshield-dev.key"
    ip = lan_ip()
    marker = d / "ip.txt"
    if cert_path.exists() and key_path.exists() and marker.exists() and marker.read_text() == ip:
        return cert_path, key_path
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "QRshield dev")])
    sans = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.IPAddress(ipaddress.ip_address(ip))]
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    marker.write_text(ip)
    return cert_path, key_path


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    scheme = "https" if args.https else "http"
    kwargs = {}
    if args.https:
        cert, key = ensure_self_signed_cert()
        kwargs.update(ssl_certfile=str(cert), ssl_keyfile=str(key))
        print(f"\n  Self-signed certificate: {cert}\n  Your browser will warn once; choose 'Advanced > continue' (it is your own laptop).")
    print(f"\n  QRshield:  {scheme}://127.0.0.1:{args.port}")
    if args.host in ("0.0.0.0", "::"):
        print(f"  On your phone (same Wi-Fi):  {scheme}://{lan_ip()}:{args.port}")
        if not args.https:
            print("  Note: phones only allow the live camera over HTTPS. 'Take photo' works over http; add --https for live camera.")
    uvicorn.run("qrshield.app.api:app", host=args.host, port=args.port, reload=args.reload, log_level="info", **kwargs)
    return 0


def cmd_setup(_: argparse.Namespace) -> int:
    from qrshield.registry import Registry
    reg = Registry().ensure_ready(seed_demo=True)
    print(f"Runtime home      : {reg.home}")
    print(f"Root public key   : {reg.root_public_key_b64}")
    print(f"Demo issuers      : {', '.join(i['issuer_id'] for i in reg.list_issuers())}")
    print(f"Admin token       : {reg.admin_token()}   (saved in {reg.home / 'admin_token'})")
    return cmd_doctor(_)


def cmd_doctor(_: argparse.Namespace) -> int:
    ok = True

    def line(name: str, good: bool, note: str = "") -> None:
        nonlocal ok
        ok &= good
        print(f"  [{'ok' if good else 'FAIL'}] {name}{(' - ' + note) if note else ''}")

    print(f"QRshield doctor (Python {sys.version.split()[0]})")
    line("python >= 3.10", sys.version_info >= (3, 10), "3.11 or 3.12 recommended")
    for mod, why in (("cv2", "opencv-python-headless"), ("zxingcpp", "zxing-cpp (primary QR decoder)"), ("lightgbm", "lightgbm"),
                     ("sklearn", "scikit-learn"), ("skimage", "scikit-image"), ("cryptography", "cryptography"),
                     ("fastapi", "fastapi"), ("tldextract", "tldextract"), ("rapidfuzz", "rapidfuzz"), ("qrcode", "qrcode")):
        try:
            __import__(mod)
            line(f"import {mod}", True)
        except Exception as exc:
            line(f"import {mod}", False, f"pip install {why}  ({exc})")
    from qrshield import model_store
    for kind in ("url", "cv"):
        p = model_store.active_path(kind)
        line(f"{kind} model", p is not None, str(p) if p else f"run `python -m qrshield train-{kind}`")
    line("static UI", (config.STATIC_DIR / "index.html").exists())
    print("\nAll good." if ok else "\nFix the FAIL lines above, then re-run.")
    return 0 if ok else 1


def _run_module(*mod_args: str) -> int:
    return subprocess.call([sys.executable, "-m", *mod_args])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="qrshield", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the web app")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--https", action="store_true", help="serve over HTTPS with a self-signed certificate (needed for phone cameras)")
    s.add_argument("--reload", action="store_true")
    sub.add_parser("setup", help="create keys and the demo registry, then run doctor")
    sub.add_parser("doctor", help="check the installation")
    sub.add_parser("test", help="run the test-suite")
    sub.add_parser("data", help="download public corpora and build the URL training pool")
    sub.add_parser("retrain", help="human-gated retrain of the link model from approved reports")
    sub.add_parser("train-url", help="retrain the link model from data/url")
    sub.add_parser("train-cv", help="retrain the sticker model (add --real DIR for real photos)")
    sub.add_parser("evaluate", help="end-to-end evaluation and ablation")
    sub.add_parser("robustness", help="stress-test the sticker model under camera degradations; measure calibration")
    sub.add_parser("demo-assets", help="write printable QR codes for the live demo")
    sub.add_parser("blocklist-update", help="refresh the local OpenPhish blocklist cache")
    args, extra = ap.parse_known_args(argv)

    if args.cmd == "serve":
        return cmd_serve(args)
    if args.cmd == "setup":
        return cmd_setup(args)
    if args.cmd == "doctor":
        return cmd_doctor(args)
    if args.cmd == "test":
        return _run_module("pytest", "tests", "-q", *extra)
    if args.cmd == "data":
        return _run_module("scripts.build_url_dataset", "--download", *extra)
    if args.cmd == "retrain":
        return _run_module("scripts.retrain")
    if args.cmd == "train-url":
        return _run_module("qrshield.url_layer.train")
    if args.cmd == "train-cv":
        return _run_module("qrshield.cv_layer.train", *extra)
    if args.cmd == "evaluate":
        return _run_module("scripts.evaluate", *extra)
    if args.cmd == "robustness":
        return _run_module("scripts.robustness_eval", *extra)
    if args.cmd == "demo-assets":
        return _run_module("scripts.make_demo_assets", *extra)
    if args.cmd == "blocklist-update":
        from qrshield.url_layer.blocklist import update_from_openphish
        print(f"cached {update_from_openphish()} entries")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
