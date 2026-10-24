"""
Append-only transparency log for the registry (Certificate-Transparency style, RFC 6962 / RFC 9162 hashing).

Every certificate-lifecycle event (issuer registered, revoked, restored, key rotated) becomes a leaf of a Merkle
tree. The registry publishes a root-signed *tree head* (size + root hash). From it anyone can check, without
trusting the server and without downloading the log:

  * inclusion   - "this event really is in the log"        (O(log n) hashes)
  * consistency - "today's log extends yesterday's log"    (nothing was edited or deleted)

so a registry that silently rewrote history (e.g. hid that it once certified a rogue issuer) is caught.

Hashing is domain-separated: leaf = SHA-256(0x00 || data), node = SHA-256(0x01 || left || right), which stops a
node from ever being passed off as a leaf (second-preimage attack on Merkle trees).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from qrshield.crypto_layer.keys import b64u_decode, b64u_encode

STH_CONTEXT = b"QRSHIELD-STH-v1\x00"


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    return _h(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01" + left + right)


EMPTY_ROOT = _h(b"")


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def merkle_root(hashes: Sequence[bytes]) -> bytes:
    n = len(hashes)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return hashes[0]
    k = _split(n)
    return node_hash(merkle_root(hashes[:k]), merkle_root(hashes[k:]))


def inclusion_proof(index: int, hashes: Sequence[bytes]) -> List[bytes]:
    n = len(hashes)
    if not 0 <= index < n:
        raise ValueError("leaf index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(index, hashes[:k]) + [merkle_root(hashes[k:])]
    return inclusion_proof(index - k, hashes[k:]) + [merkle_root(hashes[:k])]


def verify_inclusion(leaf: bytes, index: int, size: int, proof: Sequence[bytes], root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def consistency_proof(first: int, hashes: Sequence[bytes]) -> List[bytes]:
    """Proof that the tree of the first `first` leaves is a prefix of the tree of all `hashes`."""
    n = len(hashes)
    if not 0 < first <= n:
        raise ValueError("first tree size out of range")
    if first == n:
        return []

    def sub(m: int, leaves: Sequence[bytes], complete: bool) -> List[bytes]:
        size = len(leaves)
        if m == size:
            return [] if complete else [merkle_root(leaves)]
        k = _split(size)
        if m <= k:
            return sub(m, leaves[:k], complete) + [merkle_root(leaves[k:])]
        return sub(m - k, leaves[k:], False) + [merkle_root(leaves[:k])]

    return sub(first, hashes, True)


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes, proof: Sequence[bytes]) -> bool:
    """RFC 9162 section 2.1.4.2."""
    if not 0 < first <= second:
        return False
    if first == second:
        return not proof and first_root == second_root
    proof = list(proof)
    if first & (first - 1) == 0:                      # first is a power of two: its root is a node of the new tree
        proof.insert(0, first_root)
    if not proof:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


# ---- signed tree head ---------------------------------------------------------------------------
def _sth_bytes(size: int, root: bytes, timestamp: int) -> bytes:
    body = {"size": int(size), "root": root.hex(), "timestamp": int(timestamp)}
    return STH_CONTEXT + json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_tree_head(size: int, root: bytes, timestamp: int, root_private_key: ed25519.Ed25519PrivateKey) -> Dict[str, Any]:
    return {"size": int(size), "root_hash": root.hex(), "timestamp": int(timestamp),
            "sig": b64u_encode(root_private_key.sign(_sth_bytes(size, root, timestamp)))}


def verify_tree_head(head: Dict[str, Any], root_public_key: ed25519.Ed25519PublicKey) -> Tuple[bool, str]:
    try:
        root_public_key.verify(b64u_decode(head.get("sig") or ""),
                               _sth_bytes(int(head["size"]), bytes.fromhex(head["root_hash"]), int(head["timestamp"])))
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False, "tree head signature is invalid"
    return True, "tree head signed by the pinned root"
