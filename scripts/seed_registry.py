"""
Seed Registry and Demo Certificates (F26, F28).
Pre-registers sample demo authorities and businesses:
1. Mumbai Smart City Parking (pay.citypark.example)
2. SPIT Admissions Authority (spit.ac.in)
Generates root authority key and signs certificates.
"""
import os
import json
from qrshield.registry.admin import (
    init_db,
    get_or_create_root_key,
    register_issuer,
    sync_all_certificates_to_verifier
)
from qrshield.crypto_layer.keys import (
    generate_keypair,
    export_public_key_b64,
    export_private_key_b64,
    load_private_key_b64
)

# Deterministic demo private keys
CITYPARK_PRIV_B64 = "eHl6MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODk"
SPIT_PRIV_B64 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY"

def seed_demo_issuers():
    init_db()
    root_priv, root_pub = get_or_create_root_key()

    # Issuer 1: Mumbai Smart City Parking
    citypark_priv = load_private_key_b64(CITYPARK_PRIV_B64)
    citypark_pub = citypark_priv.public_key()
    citypark_pub_b64 = export_public_key_b64(citypark_pub)

    cert1 = register_issuer(
        issuer_id="citypark-01",
        name="Mumbai Smart City Parking",
        domain="pay.citypark.example",
        issuer_pubkey_b64=citypark_pub_b64
    )
    print("Registered Issuer: Mumbai Smart City Parking (citypark-01)")

    # Issuer 2: SPIT Mumbai
    spit_priv = load_private_key_b64(SPIT_PRIV_B64)
    spit_pub = spit_priv.public_key()
    spit_pub_b64 = export_public_key_b64(spit_pub)

    cert2 = register_issuer(
        issuer_id="spit-admit",
        name="SPIT Admissions Authority",
        domain="spit.ac.in",
        issuer_pubkey_b64=spit_pub_b64
    )
    print("Registered Issuer: SPIT Admissions Authority (spit-admit)")

    sync_all_certificates_to_verifier()
    print("Demo registry successfully seeded and synchronized.")

if __name__ == "__main__":
    seed_demo_issuers()
