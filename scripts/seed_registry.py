"""
Create the runtime registry: root key, demo issuers (keys generated locally - nothing is committed).

    python -m scripts.seed_registry
"""
from qrshield.registry import Registry


def main() -> None:
    reg = Registry().ensure_ready(seed_demo=True)
    print(f"Runtime home    : {reg.home}")
    print(f"Root public key : {reg.root_public_key_b64}")
    for i in reg.list_issuers():
        print(f"Issuer          : {i['issuer_id']:12s} {i['name']}  ({i['domain']})  key {i['key_id']}")
    print(f"Admin token     : {reg.admin_token()}")


if __name__ == "__main__":
    main()
