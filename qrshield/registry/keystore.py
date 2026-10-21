"""
Private-key custody for the demo deployment.

* The registry ROOT private key signs issuer certificates and CRLs. In production it would
  live offline / in an HSM; here it is a 0600 file inside the (git-ignored) runtime home.
* Demo issuers ("managed" issuers) also keep their private keys here so the Issuer Portal can
  print signed QR codes. A real business would hold its own key and never send it anywhere.

Nothing in this module is ever committed: keys are generated on first run.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from qrshield.crypto_layer.keys import (
    export_private_key_b64,
    export_public_key_b64,
    generate_keypair,
    load_private_key_b64,
    load_public_key_b64,
)


def _write_private(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


class Keystore:
    def __init__(self, home: Path):
        self.dir = Path(home) / "keys"
        self.root_file = self.dir / "root.json"
        self.issuer_dir = self.dir / "issuers"

    # ---- root authority -------------------------------------------------------
    def root_keypair(self) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        if self.root_file.exists():
            data = json.loads(self.root_file.read_text(encoding="utf-8"))
            priv = load_private_key_b64(data["private_key"])
            return priv, priv.public_key()
        priv, pub = generate_keypair()
        _write_private(self.root_file, {
            "private_key": export_private_key_b64(priv),
            "public_key": export_public_key_b64(pub),
            "note": "QRshield demo root authority. Never commit this file.",
        })
        return priv, pub

    # ---- managed (demo) issuer keys -------------------------------------------
    def _issuer_file(self, issuer_id: str, key_id: str) -> Path:
        safe = "".join(c for c in f"{issuer_id}__{key_id}" if c.isalnum() or c in "-_")
        return self.issuer_dir / f"{safe}.json"

    def new_issuer_key(self, issuer_id: str, key_id: str) -> ed25519.Ed25519PublicKey:
        priv, pub = generate_keypair()
        _write_private(self._issuer_file(issuer_id, key_id), {
            "issuer_id": issuer_id, "key_id": key_id,
            "private_key": export_private_key_b64(priv),
            "public_key": export_public_key_b64(pub),
        })
        return pub

    def issuer_private_key(self, issuer_id: str, key_id: str) -> Optional[ed25519.Ed25519PrivateKey]:
        path = self._issuer_file(issuer_id, key_id)
        if not path.exists():
            return None
        return load_private_key_b64(json.loads(path.read_text(encoding="utf-8"))["private_key"])

    def issuer_public_key(self, issuer_id: str, key_id: str) -> Optional[ed25519.Ed25519PublicKey]:
        path = self._issuer_file(issuer_id, key_id)
        if not path.exists():
            return None
        return load_public_key_b64(json.loads(path.read_text(encoding="utf-8"))["public_key"])
