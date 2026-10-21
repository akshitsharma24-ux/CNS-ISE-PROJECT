# Live demo script (about 8 minutes)

## Before you start (5 minutes, the day before and again 30 minutes before)

1. `run_demo.bat` (Windows) or `python -m qrshield setup && python -m qrshield serve`. The console prints the **admin token** - keep it handy.
2. **Print the props on the laptop you will demo from** (signed codes only verify against the registry that signed them):
   `python -m qrshield demo-assets` -> `demo_assets/demo_sheet_A4.png`. Print at 100 %. Cut the six codes out.
3. Build the props: a cardboard "parking meter" with code **#3** glued on; a table tent with code **#1**. Keep code **#4** (the "clean sticker") loose with peelable adhesive; stick it over #3 for scenario 4. Print the sheet twice and keep spares.
4. Phone camera over HTTPS (browsers block live cameras on plain http except on localhost): `python -m qrshield serve --https --host 0.0.0.0`, open the printed `https://<laptop-ip>:8000` on the phone, accept the certificate once. If that is fiddly on the day, use **Photo > Take photo** - it opens the phone's camera app and works over http.
5. Backup: the six **simulated scenario photos** in the UI need no props or camera. Record a 3-minute screen video of them as a last resort.

## The six scenarios

| # | Do | Expect | What to say |
|---|---|---|---|
| 1 | Scan code #1 (college site) | **SAFE** | "Normal codes are not blocked - false alarms are a cost we measure." Point at "not digitally signed, so we cannot prove who issued it" |
| 2 | Scan code #2 (PhonePe look-alike) | **BLOCK** | "No blocklist has seen this domain. The model flags a brand look-alike on a throw-away TLD; open *Show the working*." Show the Open button is hidden behind an override |
| 3 | Scan code #3 on the cardboard meter | **SAFE + QRSHIELD CERTIFIED** | "Signed by the registered business: root-signed certificate, domain-bound, Ed25519 signature." Read out issuer, certified domain, expiry from the card |
| 4 | Stick #4 over #3, scan the meter | **SUSPICIOUS** | "A URL-only scanner sees a clean link. The photo shows the pasted edge, the shadow and the *original code's corners peeking out* - see the overlay." Also: M3 says "Unsigned" - the signed original is hidden |
| 5 | Scan code #5 (edited token) | **BLOCK** | "Same code, path changed after signing - the signature no longer matches. A code that *claims* certification and fails is worse than an unsigned one." |
| 6 | Press **Report** on #2, open Admin, approve, press **Retrain** | report queued -> model history shows promote/reject | "A person approves; the retrained model must beat the live one on a fixed benchmark and get canary links right, otherwise it is rejected - that blocks poisoning." |

**Bonus crypto moments (1 minute each):** Issuer portal -> generate a signed QR -> *Scan this code now* -> certified; then **Revoke** the issuer and scan again -> **BLOCK, revoked** (CRL version increments); **Rotate key** -> old codes revoked, new ones valid. Press *Restore all issuers* to reset.

## If something goes wrong

* **Camera will not start / no HTTPS:** use Photo > Take photo, or the simulated scenarios.
* **Glare or blur:** the UI says "Retake photo" and refuses to judge - say so, it is a feature (it never gives a verdict from an unreadable photo).
* **A scenario gives a different verdict on a real photo:** say honestly that the sticker model was trained on simulated photos and show the evaluation report's limitations; then show the same scenario in simulated form.

## Likely viva questions - short answers

| Question | Answer |
|---|---|
| Why Ed25519, not RSA or ECDSA? | 64-byte signatures keep the QR sparse (RSA-2048 is 256 B), deterministic signing avoids nonce-reuse bugs, fast verification, strong security level, audited library. |
| What if someone copies a genuine signed code elsewhere? | Replay is a limit of every signature scheme. We sign location + expiry, show the location, and the sticker check flags paste-overs; rolling tokens for payment counters are the next step. We say this up front. |
| How does the app trust the registry? | The root public key is pinned in the verifier; certificates and the CRL must verify against it. No pinned key means nothing verifies (fail closed). |
| Why verify the signature before checking expiry? | Otherwise a forged token could claim to be "expired" and get a milder verdict. |
| What stops an attacker rolling the CRL back? | Verifiers keep the highest CRL version seen and verify its signature. |
| Why can a photo never BLOCK on its own? | Visual evidence is probabilistic with a measured false-positive rate; BLOCK needs another independent layer or a cryptographic fact. |
| Is the sticker detector accurate? | On simulated photos, leave-one-surface-out AUC is about 0.88; it catches imperfect covers but not a perfectly fitted sticker. It has not been measured on real photos yet - see `docs/evaluation.md`. |
| How do you stop the analyser being abused to attack the network? | SSRF guard: http(s) only, resolve once, globally-routable addresses only, connect to the validated IP (rebinding-proof), re-validate every redirect, HEAD only, timeouts. |
| Why are the URL results lower than papers that report 99 %? | We removed dataset shortcuts (scheme, `www.`, path presence, per-domain flooding) and evaluate on an external corpus and 2026 feeds. Raw corpora let a model "cheat"; the report shows the bias with numbers. |
| What is the privacy impact? | Photos are not stored; reports hold a link, a label and a note; telemetry holds only hashes and timings. |
| Which CNS concepts are in the project? | Digital signatures, PKI and certificates, domain binding, key rotation and revocation (signed, versioned CRL, rollback protection), domain separation, hashing, replay analysis, TLS for the phone camera, SSRF defence, secure parsing of hostile input, rate limiting, CSP, and a human-gated, benchmark-gated learning loop. |
