"""
Step-by-step trace of the signed-QR verification (the "token inspector").

`verify()` answers *what* the verdict is. `trace()` shows *why*: it replays the same eight checks in the same
order, recording what each one looked at (certificate fields, CRL version, the exact bytes that were signed, the
public key, the signature) and whether it passed, failed or was never reached. The final status always comes from
`verify()` itself, and `agrees` says whether the replayed steps reach the same conclusion, so the trace can never
tell a different story from the real verifier.

Only public material is shown: tokens, certificates, public keys and signatures. No private key ever reaches here.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature

from qrshield.crypto_layer.keys import b64u_decode, export_public_key_b64, load_public_key_b64
from qrshield.crypto_layer.pki import verify_domain_binding, verify_issuer_certificate
from qrshield.crypto_layer.revocation import is_revoked, key_revocation_id
from qrshield.crypto_layer.token import build_signature_message, extract_token_from_url
from qrshield.crypto_layer.verify import CLOCK_SKEW_SECONDS, TrustStore, verify
from qrshield.netutil import hostname_of

PASS, FAIL, SKIP, INFO = "pass", "fail", "skipped", "info"

def fingerprint(public_key_b64: str) -> str:
    """SHA-256 of the raw 32-byte public key, hex (what a human would compare out of band)."""
    return hashlib.sha256(b64u_decode(public_key_b64)).hexdigest()


def _step(sid: str, title: str, state: str, why: str, **facts: Any) -> Dict[str, Any]:
    return {"id": sid, "title": title, "state": state, "why": why, "facts": facts}


def trace(payload: str, store: TrustStore, now: Optional[int] = None) -> Dict[str, Any]:
    now = int(time.time()) if now is None else int(now)
    real = verify(payload, store, now)
    steps: List[Dict[str, Any]] = []
    token, canonical = extract_token_from_url(payload or "")
    out: Dict[str, Any] = {"status": real["status"], "detail": real["detail"], "now": now, "token": None, "steps": steps}

    def skip_rest(ids: List[tuple]) -> None:
        for sid, title in ids:
            steps.append(_step(sid, title, SKIP, "Not reached: an earlier check already decided the verdict."))

    ALL = [("anchor", "Pinned trust anchor"), ("certificate", "Issuer certificate"), ("revocation", "Revocation list"),
           ("keyid", "Key id matches certificate"), ("signature", "Ed25519 signature"), ("domain", "Domain binding"),
           ("time", "Validity window")]

    # 1. parse ---------------------------------------------------------------------------------
    if token is None:
        steps.append(_step("parse", "Parse the QR content", PASS, "No `qrs` parameter: this is an ordinary unsigned link.", canonical_url=canonical))
        skip_rest(ALL)
        return _finish(out)
    if "error" in token:
        steps.append(_step("parse", "Parse the QR content", FAIL, f"A `qrs` token is present but unusable: {token['error']}.", canonical_url=canonical))
        skip_rest(ALL)
        return _finish(out)
    out["token"] = {k: token[k] for k in ("v", "iss", "kid", "loc", "iat", "exp", "sig")}
    steps.append(_step("parse", "Parse the QR content", PASS, "Token decoded: version, issuer, key id, location, issue/expiry time and a 64-byte signature.",
                       canonical_url=canonical, issuer=token["iss"], key_id=token["kid"], location=token["loc"],
                       issued_at=token["iat"], expires_at=token["exp"], signature_b64u=token["sig"]))

    # 2. trust anchor --------------------------------------------------------------------------
    if store.root_public_key is None:
        steps.append(_step("anchor", "Pinned trust anchor", FAIL, "No root key is pinned, so nothing can be verified (fail closed)."))
        skip_rest(ALL[1:])
        return _finish(out)
    root_b64 = export_public_key_b64(store.root_public_key)
    steps.append(_step("anchor", "Pinned trust anchor", PASS, "The verifier trusts exactly one root key, pinned in the app.",
                       root_public_key=root_b64, root_sha256=fingerprint(root_b64)))

    # 3. certificate ---------------------------------------------------------------------------
    cert = store.get_certificate(token["iss"])
    if not cert:
        steps.append(_step("certificate", "Issuer certificate", FAIL, f"Issuer '{token['iss']}' is not registered, so there is no certificate to check."))
        skip_rest(ALL[2:])
        return _finish(out)
    ok, why = verify_issuer_certificate(cert, store.root_public_key, now)
    cert_facts = dict(issuer=cert.get("name"), certified_domain=cert.get("domain"), key_id=cert.get("kid"),
                      issuer_public_key=cert.get("issuer_pubkey"), valid_from=cert.get("valid_from"), valid_to=cert.get("valid_to"),
                      root_signature_b64u=cert.get("sig"))
    steps.append(_step("certificate", "Issuer certificate", PASS if ok else FAIL,
                       "The certificate carries a valid root signature and is inside its validity window." if ok else why.capitalize() + ".", **cert_facts))
    if not ok:
        skip_rest(ALL[2:])
        return _finish(out)

    # 4. revocation ----------------------------------------------------------------------------
    crl = store.crl
    hit = None
    for ident in (token["iss"], key_revocation_id(token["iss"], token["kid"])):
        revoked, reason = is_revoked(crl, ident)
        if revoked:
            hit = (ident, reason)
            break
    steps.append(_step("revocation", "Revocation list", FAIL if hit else PASS,
                       f"'{hit[0]}' is on the root-signed revocation list ({hit[1]})." if hit else "Neither the issuer nor this key appears on the root-signed revocation list.",
                       crl_version=(crl or {}).get("version"), checked=[token["iss"], key_revocation_id(token["iss"], token["kid"])]))
    if hit:
        skip_rest(ALL[3:])
        return _finish(out)

    # 5. key id --------------------------------------------------------------------------------
    same = cert.get("kid", token["kid"]) == token["kid"]
    steps.append(_step("keyid", "Key id matches certificate", PASS if same else FAIL,
                       "The token names the key the certificate certifies." if same else "The token names a different key than the certificate certifies.",
                       token_key_id=token["kid"], certified_key_id=cert.get("kid")))
    if not same:
        skip_rest(ALL[4:])
        return _finish(out)

    # 6. signature -----------------------------------------------------------------------------
    try:
        message = build_signature_message(canonical, token["iss"], token["kid"], token["loc"], token["iat"], token["exp"])
        load_public_key_b64(cert["issuer_pubkey"]).verify(b64u_decode(token["sig"]), message)
        sig_ok = True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        message, sig_ok = locals().get("message", b""), False
    steps.append(_step("signature", "Ed25519 signature", PASS if sig_ok else FAIL,
                       "The signature verifies over the canonical URL and token fields with the certified key." if sig_ok
                       else "The signature does not verify: the URL or a token field changed after signing, or a different key signed it.",
                       signed_message_hex=message.hex(), signed_message_sha256=hashlib.sha256(message).hexdigest(),
                       public_key=cert.get("issuer_pubkey"), signature_b64u=token["sig"]))
    if not sig_ok:
        skip_rest(ALL[5:])
        return _finish(out)

    # 7. domain binding ------------------------------------------------------------------------
    bound = verify_domain_binding(cert, payload)
    steps.append(_step("domain", "Domain binding", PASS if bound else FAIL,
                       "The link's host is the certified domain or one of its subdomains." if bound else "The link points outside the domain this issuer is certified for.",
                       link_host=hostname_of(payload), certified_domain=cert.get("domain")))
    if not bound:
        skip_rest(ALL[6:])
        return _finish(out)

    # 8. time ----------------------------------------------------------------------------------
    future = token["iat"] > now + CLOCK_SKEW_SECONDS
    expired = bool(token["exp"]) and now > token["exp"]
    steps.append(_step("time", "Validity window", FAIL if (future or expired) else PASS,
                       "The token claims to be issued in the future." if future else "The token's validity window has passed." if expired
                       else ("The token is inside its validity window." if token["exp"] else "The token never expires."),
                       now=now, issued_at=token["iat"], expires_at=token["exp"]))
    return _finish(out)


def _finish(out: Dict[str, Any]) -> Dict[str, Any]:
    """Cross-check the replayed steps against the verdict the real verifier returned."""
    failed = next((s for s in out["steps"] if s["state"] == FAIL), None)
    status = out["status"]
    if failed is None:
        out["agrees"] = status in ("valid", "none")
    else:
        out["agrees"] = status != "valid" and status != "none"
    out["decided_at"] = failed["id"] if failed else None
    return out
