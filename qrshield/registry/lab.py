"""
Attack lab: forge signed QR codes on purpose and watch the real verifier reject them.

Each attack builds a malicious payload the way an attacker with the stated capability would, then runs it through
the live `verify()` against the live trust store (the same code path as a real scan). Nothing here weakens the
verifier or touches the registry state: the attacks only *create* payloads. Genuine signing uses the managed demo
key; "attacker" keys are fresh random keys the registry has never seen.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from qrshield.crypto_layer import generate_keypair, sign_url_token, verify
from qrshield.crypto_layer.keys import b64u_decode
from qrshield.crypto_layer.token import TOKEN_PARAM, pack_token, unpack_token
from qrshield.crypto_layer.trace import trace
from qrshield.registry.service import Registry, RegistryError


def _with_token(url: str, token_b64: str) -> str:
    p = urlparse(url)
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != TOKEN_PARAM] + [(TOKEN_PARAM, token_b64)]
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q), p.fragment))


def _token_of(url: str) -> str:
    return dict(parse_qsl(urlparse(url).query))[TOKEN_PARAM]


def run_attacks(registry: Registry, issuer_id: str, url: Optional[str] = None) -> Dict[str, Any]:
    issuer = next((i for i in registry.list_issuers() if i["issuer_id"] == issuer_id), None)
    if issuer is None:
        raise RegistryError(f"issuer '{issuer_id}' not found", status=404)
    if not issuer["managed_key"]:
        raise RegistryError("the attack lab needs a registry-managed issuer key", status=409)
    if issuer["is_revoked"]:
        raise RegistryError("restore this issuer first: a revoked issuer would reject even the genuine control code", status=409)
    priv = registry.keystore.issuer_private_key(issuer_id, issuer["key_id"])
    if priv is None:
        raise RegistryError("issuer key material is missing from the keystore", status=500)

    kid, domain = issuer["key_id"], issuer["domain"]
    url = (url or f"https://{domain}/m/42").strip()
    now = int(time.time())
    genuine, _ = sign_url_token(url, priv, issuer_id, kid, "attack-lab", iat=now, exp=now + 3600)
    parts = unpack_token(_token_of(genuine))
    attacker_priv, _ = generate_keypair()

    flipped = bytearray(b64u_decode(parts["sig"]))
    flipped[10] ^= 0x01
    p = urlparse(genuine)
    edited_path = urlunparse((p.scheme, p.netloc, p.path.rstrip("/") + "9", p.params, p.query, p.fragment))
    other_host = "https://secure-login-verify.example.net/pay"
    expired, _ = sign_url_token(url, priv, issuer_id, kid, "attack-lab", iat=now - 7200, exp=now - 3600)
    future, _ = sign_url_token(url, priv, issuer_id, kid, "attack-lab", iat=now + 86400, exp=now + 90000)
    forged, _ = sign_url_token(url, attacker_priv, issuer_id, kid, "attack-lab", iat=now, exp=now + 3600)
    unknown, _ = sign_url_token(url, attacker_priv, "evil-corp", "key-1", "attack-lab", iat=now, exp=now + 3600)
    wrong_domain, _ = sign_url_token(other_host, priv, issuer_id, kid, "attack-lab", iat=now, exp=now + 3600)
    bit_flip = _with_token(url, pack_token(parts["iss"], parts["kid"], parts["loc"], parts["iat"], parts["exp"], bytes(flipped)))

    attacks: List[Dict[str, Any]] = [
        {"id": "genuine", "title": "Control: the genuine code", "attacker": "nobody",
         "how": "The issuer signs its own link with its certified key.", "payload": genuine, "expected": "valid"},
        {"id": "edit_path", "title": "Edit the link after signing", "attacker": "can reprint a code",
         "how": "Change the path of a genuine signed link (/m/42 becomes /m/429) but keep the token.", "payload": edited_path, "expected": "invalid"},
        {"id": "bit_flip", "title": "Flip one bit of the signature", "attacker": "can reprint a code",
         "how": "Corrupt a single bit in the 64-byte signature.", "payload": bit_flip, "expected": "invalid"},
        {"id": "forged_signature", "title": "Forge the signature with their own key", "attacker": "knows the public issuer name and key id",
         "how": "Sign the link with a fresh attacker key while claiming to be the real issuer.", "payload": forged, "expected": "invalid"},
        {"id": "unknown_issuer", "title": "Invent a fake issuer", "attacker": "can run their own signing key",
         "how": "Sign with a brand-new key under the made-up issuer name 'evil-corp'.", "payload": unknown, "expected": "unknown_issuer"},
        {"id": "token_transplant", "title": "Copy a valid token onto a phishing link", "attacker": "photographed a genuine code",
         "how": "Take the real token and attach it to a different, malicious URL.", "payload": _with_token(other_host, _token_of(genuine)), "expected": "invalid"},
        {"id": "wrong_domain", "title": "Real key, someone else's domain", "attacker": "stole or misused the issuer key",
         "how": f"A correctly signed token for {other_host}, outside the certified domain {domain}.", "payload": wrong_domain, "expected": "domain_mismatch"},
        {"id": "expired", "title": "Replay an expired code", "attacker": "kept an old printed code",
         "how": "A genuine signature whose validity ended an hour ago.", "payload": expired, "expected": "expired"},
        {"id": "future_dated", "title": "Pre-date the token", "attacker": "can choose the timestamps",
         "how": "A token claiming to be issued tomorrow, to dodge expiry.", "payload": future, "expected": "invalid"},
        {"id": "strip_token", "title": "Strip the signature (downgrade)", "attacker": "can reprint a code",
         "how": "Remove the token entirely and present a plain link. It is no longer verified, so the link and sticker checks take over.",
         "payload": url, "expected": "none"},
    ]

    results = []
    for a in attacks:
        t = trace(a["payload"], registry.store, now)
        status = verify(a["payload"], registry.store, now)["status"]
        decided = next((s for s in t["steps"] if s["state"] == "fail"), None)
        results.append({
            "id": a["id"], "title": a["title"], "attacker": a["attacker"], "how": a["how"], "payload": a["payload"],
            "expected": a["expected"], "actual": status, "as_expected": status == a["expected"],
            "accepted": status == "valid", "decided_at": decided["id"] if decided else None,
            "reason": decided["why"] if decided else (t["steps"][0]["why"] if status == "none" else "All checks passed."),
        })
    forgeries = [r for r in results if r["id"] != "genuine"]
    return {"issuer_id": issuer_id, "url": url, "results": results,
            "summary": {"attacks": len(forgeries), "rejected": sum(1 for r in forgeries if not r["accepted"]),
                        "all_as_expected": all(r["as_expected"] for r in results)}}
