"""
CLI Utility: make_signed_qr.py (F25, F27).
Generates an Ed25519-signed printable QR code PNG for businesses.
Usage:
  python -m scripts.make_signed_qr --url https://pay.citypark.example/m/42 --issuer citypark-01 --out qr.png
"""
import os
import time
import argparse
import qrcode
from qrshield.crypto_layer.token import sign_url_token
from qrshield.crypto_layer.keys import load_private_key_b64
from scripts.seed_registry import CITYPARK_PRIV_B64, SPIT_PRIV_B64

def generate_signed_qr_cli(
    url: str,
    issuer_id: str,
    output_path: str = "signed_qr.png",
    loc_id: str = "counter-01",
    valid_hours: int = 48
):
    priv_key_b64 = CITYPARK_PRIV_B64 if issuer_id == "citypark-01" else SPIT_PRIV_B64
    priv = load_private_key_b64(priv_key_b64)

    now = int(time.time())
    exp = now + (valid_hours * 3600)

    signed_url, token = sign_url_token(
        url=url,
        private_key=priv,
        issuer_id=issuer_id,
        key_id="key-1",
        location_id=loc_id,
        iat=now,
        exp=exp
    )

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4
    )
    qr.add_data(signed_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_path)

    print(f"[+] Signed QR successfully created: {output_path}")
    print(f"[+] Issuer: {issuer_id}")
    print(f"[+] Signed URL: {signed_url}")
    print(f"[+] Token Details: {token}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Ed25519 Signed QR Code")
    parser.add_argument("--url", default="https://pay.citypark.example/m/42", help="Target URL")
    parser.add_argument("--issuer", default="citypark-01", help="Issuer ID")
    parser.add_argument("--out", default="demo_signed_qr.png", help="Output PNG path")
    parser.add_argument("--loc", default="andheri-counter-04", help="Location ID")
    parser.add_argument("--hours", type=int, default=48, help="Validity window in hours")
    args = parser.parse_args()

    generate_signed_qr_cli(args.url, args.issuer, args.out, args.loc, args.hours)
