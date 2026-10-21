"""
Print a signed QR code for a registered business (F25, F27).

    python -m scripts.make_signed_qr --issuer citypark-01 --url https://pay.citypark.example/m/42 --out meter42.png

Works for registry-managed (demo) issuers. A business that holds its own private key signs with
qrshield.crypto_layer.sign_url_token() on its own machine - the registry never sees that key.
"""
import argparse

import qrcode

from qrshield.crypto_layer import verify
from qrshield.registry import Registry, RegistryError


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--issuer", default="citypark-01")
    ap.add_argument("--url", default="https://pay.citypark.example/m/42")
    ap.add_argument("--out", default="signed_qr.png")
    ap.add_argument("--loc", default="andheri-west-meter-04", help="location / terminal id bound into the signature")
    ap.add_argument("--hours", type=int, default=72, help="validity in hours (0 = never expires)")
    a = ap.parse_args()

    reg = Registry().ensure_ready()
    try:
        res = reg.sign_for_issuer(a.issuer, a.url, a.loc, a.hours)
    except RegistryError as exc:
        print(f"error: {exc}")
        return 1
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=12, border=4)
    qr.add_data(res["signed_url"])
    qr.make(fit=True)
    qr.make_image(fill_color="black", back_color="white").save(a.out)
    check = verify(res["signed_url"], reg.store)
    print(f"wrote {a.out}  ({len(res['signed_url'].encode())} bytes encoded)")
    print(f"signed URL : {res['signed_url']}")
    print(f"self-check : {check['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
