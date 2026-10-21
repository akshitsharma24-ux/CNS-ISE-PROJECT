"""
Printable assets for the live demo (plan Section 13): one A4 sheet with the six codes plus individual PNGs.

    python -m qrshield demo-assets            # writes ./demo_assets/

Print at 100% scale. Cut the codes out: paste the "clean sticker" over the signed parking code on your cardboard
meter for scenario 4. The signed codes only verify on the machine whose registry signed them (keys are generated
per installation), so print on the laptop you will demo from.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import qrcode
from PIL import Image, ImageDraw, ImageFont

from qrshield.registry import Registry

SIGNED_URL = "https://pay.citypark.example/m/42"


def _qr(data: str, box: int = 12) -> Image.Image:
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=box, border=4)
    q.add_data(data)
    q.make(fit=True)
    return q.make_image(fill_color="black", back_color="white").convert("RGB")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=Path("demo_assets"))
    ap.add_argument("--hours", type=int, default=24 * 30, help="validity of the signed codes")
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)

    reg = Registry().ensure_ready()
    signed = reg.sign_for_issuer("citypark-01", SIGNED_URL, "andheri-west-meter-04", a.hours)["signed_url"]
    items = [
        ("01_college_unsigned", "1. Ordinary college QR  ->  expect SAFE", "https://spit.ac.in/departments/comps"),
        ("02_phishing_phonepe", "2. Fresh phishing link  ->  expect BLOCK", "https://secure-phonepe-refund.xyz/claim-cashback?amt=2000"),
        ("03_citypark_signed", "3. Signed parking code  ->  SAFE + CERTIFIED", signed),
        ("04_sticker_clean_url", "4. Sticker (clean URL): paste OVER #3  ->  SUSPICIOUS", "https://citypark.example/m/42"),
        ("05_forged_token", "5. Forged token (path edited)  ->  expect BLOCK", signed.replace("/m/42", "/m/99")),
        ("06_kyc_phishing", "6. KYC scam - report it  ->  expect BLOCK", "https://paytm-kyc-update.top/wallet/kyc-verification.php"),
    ]
    try:
        font = ImageFont.truetype("arial.ttf", 26)
    except OSError:
        font = ImageFont.load_default()

    W, H, cell = 1654, 2339, 560                    # A4 at 200 dpi
    sheet = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(sheet)
    d.text((80, 50), "QRshield live-demo codes - print at 100%", fill="black", font=font)
    for i, (name, caption, data) in enumerate(items):
        img = _qr(data)
        img.save(a.out / f"{name}.png")
        x, y = 80 + (i % 2) * 780, 140 + (i // 2) * 700
        sheet.paste(img.resize((cell, cell), Image.NEAREST), (x, y))
        d.text((x, y + cell + 12), caption, fill="black", font=font)
    sheet.save(a.out / "demo_sheet_A4.png", dpi=(200, 200))
    (a.out / "README.txt").write_text(__doc__ or "", encoding="utf-8")
    print(f"wrote {len(items)} codes + demo_sheet_A4.png to {a.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
