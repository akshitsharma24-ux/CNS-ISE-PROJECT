# QRshield Live Demonstration Script & Viva Defense Guide (F41)

This document contains the step-by-step presentation script, rehearsed actions, backup protocols, and crisp viva question answers for Team Black Sparrow.

---

## 1. Demo Setup and Physical Props

- **Physical Props**:
  * Cardboard mock "Parking Meter" with pre-printed QR code base.
  * Restaurant table tent stand with UPI QR.
  * Pre-cut sticker overlays on vinyl and paper backing with clean-peeling adhesive.
- **Hardware & Software**:
  * Laptop running QRshield backend on `localhost:8000`.
  * Mobile phone on a small stand connected to local WiFi / laptop hotspot.
  * Seeded SQLite registry initialized via `python -m scripts.seed_registry`.
- **Backup Plan**:
  * Pre-rendered scenario images accessible via the top quick-test bar buttons.
  * Offline cached WHOIS/DNS tables (`HOST_CACHE`) ensuring zero reliance on campus WiFi.

---

## 2. Six Rehearsed Live Demo Scenarios (Section 13)

### Scenario 1: Scan Ordinary Unsigned Genuine Code
- **Action**: Scan genuine SPIT college website placard (`https://spit.ac.in/departments/comps`).
- **Expected Verdict**: `SAFE` (Green banner, Risk $< 0.20$, No Certified badge).
- **Explanation to Judges**:
  > *"Normal everyday QR codes are not blocked. Because false positives annoy users, our calibrated ML model and low visual tamper score correctly classify this as SAFE."*

### Scenario 2: Scan a Fresh Zero-Day Phishing QR
- **Action**: Scan lookalike payment domain (`https://secure-phonepe-refund.xyz/claim-cashback?amt=2000`).
- **Expected Verdict**: `BLOCK` (Red banner, M1 fires: Typosquatting + Abused TLD).
- **Explanation to Judges**:
  > *"Traditional scanners and blocklists fail here because this domain was registered 3 days ago and appears on no blacklist. Our URL ML classifier catches it using lexical entropy, brand Jaro-Winkler distance, and domain age before any browser window opens."*

### Scenario 3: Scan a Signed City Parking QR
- **Action**: Scan genuine municipal parking placard with Ed25519 token (`https://pay.citypark.example/m/42?qrs=...`).
- **Expected Verdict**: `SAFE` with **✓ QRSHIELD CERTIFIED** badge (Green banner).
- **Explanation to Judges**:
  > *"This QR code is provably authentic. The scanner validated the business's Ed25519 certificate against our pinned Root Authority, verified that the domain matches the certificate, and confirmed the signature over the canonical URL. Normal phones open the parking payment link directly without installing anything."*

### Scenario 4: Paste a Sticker Over the Parking Code (Physical Tamper)
- **Action**: Hand-paste a pre-printed sticker (carrying a clean-looking URL) over the parking placard, then scan the meter.
- **Expected Verdict**: `SUSPICIOUS` or `BLOCK` (Red/Yellow banner, M2 fires: Sticker boundary + cutline detected, Grad-CAM glowing red).
- **Explanation to Judges**:
  > *"URL-only scanners say this link is fine. But this is the attack happening at real parking meters across the world. Our Computer Vision layer detects the physical sticker boundary, straight cutlines, and 3D micro-shadows, displaying the glowing Grad-CAM heatmap overlay to alert the user."*

### Scenario 5: Scan a Forged or Tampered Token QR
- **Action**: Scan a QR where an attacker copied a valid token but changed `/m/42` to `/m/99` or used a self-signed key.
- **Expected Verdict**: `BLOCK` (Red banner, M3 fires: Cryptographic verification failed).
- **Explanation to Judges**:
  > *"The attacker tried to claim certification without possessing the registered private key. Under our rule-first design, a code claiming authenticity that fails cryptographic verification is stronger evidence of attack than an unsigned code, triggering an immediate BLOCK."*

### Scenario 6: User Feedback Reporting & Admin Retraining Loop
- **Action**: Press **🚩 Report Feedback** in the UI, enter note *"Suspect sticker on Andheri meter"*, switch to Admin tab, approve the report, and show `make retrain`.
- **Expected Verdict**: Report accepted into SQLite database; Admin human gate prevents data-poisoning before retraining.
- **Explanation to Judges**:
  > *"When a user flags a novel attack, it enters our privacy-preserving review queue. A human administrator approves the sample before our benchmark gate retrains and promotes the updated model."*

---

## 3. Anticipated Viva Questions & Crisp Answers

#### Q1: Why Ed25519 and not RSA-2048 or ECDSA?
**Answer**: Ed25519 signatures are only 64 bytes (RSA-2048 is 256 bytes), allowing the token to fit in a compact, easily scannable QR code. Unlike ECDSA, Ed25519 signs deterministically, eliminating catastrophic private key leaks caused by repeated or biased random nonces.

#### Q2: What if someone copies a genuine signed QR and pastes it elsewhere (Replay Attack)?
**Answer**: A static digital signature proves who created the payload, not where it is physically pasted. We mitigate replay attacks three ways: binding a location ID (`loc`) checked against the registry, enforcing short expiration timestamps (`exp`), and detecting physical sticker overlays via our CV layer (M2).

#### Q3: How does the application trust the registry?
**Answer**: The Root Authority's public key is hardcoded and pinned inside the QRshield application. All issuer certificates and Certificate Revocation Lists (CRLs) must be cryptographically signed by this pinned root key.

#### Q4: Why not just use a blocklist like Google Safe Browsing or PhishTank?
**Answer**: Blocklists are purely reactive—they only know attacks *after* victims have already been compromised and reported them. Blocklists cannot catch zero-day phishing links created 10 minutes ago, and they cannot see a physical sticker pasted over a benign code.

#### Q5: How do you prevent the analyzer from being abused as a Server-Side Request Forgery (SSRF) vector?
**Answer**: In `fetch_safe.py`, we resolve DNS ourselves before connecting and reject all private IP ranges (RFC 1918), loopback (`127.0.0.1`), link-local metadata addresses (`169.254.169.254`), and carrier-grade NAT on every hop. We enforce a 3-second timeout, cap response size to 50KB, and never execute JavaScript.

#### Q6: What are the genuine limitations of the system?
**Answer**: The CV model requires adequate lighting and can be hindered by heavy specular glare or flush industrial die-cut reprints. The cryptographic layer requires merchant adoption to display the Certified badge. Unsigned codes rely on our ML and CV layers.
