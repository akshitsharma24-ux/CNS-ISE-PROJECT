# QRshield Threat Model & Security Analysis (F40)

This document formalizes the threat landscape, adversary capabilities, and defense mechanisms engineered into QRshield, mapping directly onto the requirements of the Cryptography and Network Security (CE305/CS305) syllabus.

---

## 1. Adversary Model & Assumptions

We assume an adversary with the following capabilities:
1. **Physical Access**: The adversary can print stickers, manipulate physical QR posters, and paste fraudulent codes onto public infrastructure (e.g. municipal parking meters, restaurant tables, college notice boards).
2. **Network Capabilities**: The adversary can register new lookalike domains, deploy phishing landing pages, configure homoglyph characters, and manipulate redirect chains.
3. **Cryptographic Knowledge**: The adversary has full access to the open-source client code and protocol specifications. They can craft arbitrary QR tokens, generate their own asymmetric keys, and attempt replay or parameter-tampering attacks.
4. **Adversary Limitations**: The adversary **cannot** forge Ed25519 signatures without the private key, **cannot** obtain a certificate signed by the pinned root authority without compromise, and **cannot** break SHA-256 collision resistance.

---

## 2. Attack Vectors and Defense Mechanisms

| Attack Scenario | Adversary Action | Detection Layer | Engine Decision | Defense & Mathematical Justification |
|---|---|---|---|---|
| **Sticker Replacement (Physical Quishing)** | Pastes fraudulent QR sticker over genuine parking meter | **M2: Computer Vision** | `SUSPICIOUS` or `BLOCK` | Multi-physics features flag boundary gradient discontinuity, straight cutlines, 3D micro-shadows, and Delta-E color differences. |
| **Zero-Day Phishing URL** | Uses un-blacklisted brand-new domain with typosquatting | **M1: URL / Payload ML** | `BLOCK` | Calibrated ML classifier flags low domain age, abused TLDs (.xyz, .top), high host entropy, and Jaro-Winkler proximity to target brands. |
| **Forged Signature Token** | Crafts invalid or fabricated Ed25519 token claiming to be certified | **M3: Crypto Layer** | `BLOCK` | Signature verification against issuer public key fails. Reject code claiming certification that cannot prove it. |
| **Rogue / Self-Signed Root** | Attacker signs own certificate with self-generated authority key | **M3: Crypto Layer** | `BLOCK` (unknown issuer) | Verifier checks certificate against the pinned Root Public Key embedded directly in the application trust store. |
| **Domain Binding Violation** | Legitimate issuer key hijacked or abused to sign a phishing URL | **M3: Crypto Layer** | `BLOCK` (domain mismatch) | Verifier extracts domain from issuer cert and validates that the target URL host strictly matches or is a certified subdomain. |
| **Replay of Signed Token** | Copies a genuine signed QR from a legitimate store to a fake site | **M3 + M2 + M1** | `SUSPICIOUS` or `BLOCK` | Honest limit of static signatures. Mitigated by: location binding (`loc` parameter), expiration windows (`exp`), and physical sticker detection (M2). |
| **Parameter Tampering** | Attacker modifies payment amount or URL path inside signed link | **M3: Crypto Layer** | `BLOCK` (invalid) | Signature is computed over canonical URL including sorted query parameters. Any modification invalidates the Ed25519 signature. |
| **Compromised Issuer Key** | Organization private key leaked | **M3: Crypto Layer** | `BLOCK` (revoked) | Root authority signs and distributes an updated Certificate Revocation List (CRL). Cached by clients and enforced locally. |
| **Server-Side Request Forgery (SSRF)** | Attacker submits QR with `127.0.0.1` or AWS metadata IP `169.254.169.254` | **M1: fetch_safe.py** | Request Blocked | Resolver blocks RFC 1918 private, loopback, link-local, carrier-grade NAT, and cloud metadata IPs prior to any socket connection. |
| **Data Poisoning via Feedback Queue** | Attackers flood user report queue to mark good links as bad | **M5 / Admin Gate** | Quarantined | Reports enter a quarantined pending queue requiring human admin approval before feeding retraining benchmark gates. |

---

## 3. Cryptographic Primitives Justification (Viva Preparation)

### Why Ed25519 instead of RSA-2048 or ECDSA?
1. **Compact Signature Size**: Ed25519 signatures are exactly 64 bytes (public keys are 32 bytes). RSA-2048 signatures are 256 bytes, which would create dense, high-version QR codes that are slow or impossible to scan on low-end cameras.
2. **Deterministic Signing**: Ed25519 uses RFC 8032 deterministic nonce generation ($r = H(h_b, \dots, M)$). ECDSA requires a fresh random nonce $k$ per signature; any flaw or bias in the RNG leaks the private key (e.g. Sony PS3 private key recovery).
3. **High Performance**: Verification requires $< 0.1\text{ ms}$, ensuring zero perceptible latency during live mobile scanning.
4. **Collision Resistance**: Uses SHA-512 internally for hash digest expansion.

### SSRF Guard as a Core Network Security Decision
When an analysis engine follows redirects or fetches headers from user-supplied URLs, it acts as an HTTP client on behalf of an untrusted actor. If not protected, an attacker can use QR codes to scan internal infrastructure, hit `localhost:8000`, or extract cloud credentials from `http://169.254.169.254/latest/meta-data/`.
In `fetch_safe.py`, QRshield resolves DNS independently and validates all resolved IP addresses against an explicit private/link-local/loopback filter before issuing any request. It caps responses to 50KB, sets a 3-second timeout, limits redirects to 5 hops, and never executes JavaScript.
