# QRshield threat model

## Assets and actors

| Asset | Why it matters |
|---|---|
| The person scanning | credentials, OTPs, payments, device |
| A business's brand and payment channel | impersonated by look-alike links and pasted stickers |
| The registry root key and issuer keys | whoever holds them can mint "certified" codes |
| The analyser server | it fetches attacker-chosen URLs (SSRF surface) and parses attacker-chosen images |
| The training pipeline | fed by user reports (poisoning surface) |

**Adversary:** can print any QR code, paste stickers on public signage, register look-alike domains, run web servers, submit reports and uploads, and observe/copy any signed code. **Cannot:** break Ed25519/SHA-2, steal the registry root key, or alter the verifier's pinned root. A compromised *issuer* key is in scope (see revocation).

**Trust anchors:** the pinned registry root public key (in this demo the registry and verifier share a machine, so the key is read from the local registry; a production verifier would ship it inside the app). The admin token protects registry operations.

## Attack table - and the test that proves each defence

| # | Attack | Result | Defence | Honest limit | Test |
|---|---|---|---|---|---|
| 1 | Print a code with a fake / random token | `invalid` -> BLOCK | Ed25519 verification; "claims certification but fails" is stronger evidence than unsigned | none | `test_attack_fake_token_random_bytes` |
| 2 | Sign with own key while claiming a real issuer | `invalid` | signature checked against the *certified* key | none | `test_attack_signature_from_attackers_own_key...` |
| 3 | Self-signed issuer under a rogue root | `unknown_issuer` | certificate must verify against the pinned root | none | `test_attack_self_signed_certificate_with_a_rogue_root` |
| 4 | Swap a cached certificate for a forged one | `unknown_issuer` | cache entries are re-verified against the root at use | none | `test_attack_cache_poisoning_...` |
| 5 | Real issuer key certifies a look-alike domain | `domain_mismatch` -> BLOCK | domain binding: host must equal / be a subdomain of the certified domain (`evil.com` suffix tricks fail) | none | `test_attack_legit_key_certifies_a_lookalike_domain`, `test_lookalike_suffix_is_not_a_subdomain` |
| 6 | Strip the token and paste an unsigned sticker | `none` (never `certified`) | only a *positive* verification yields "certified"; the link + sticker layers still run | an unsigned code gets no cryptographic protection. Certified businesses should print a visible "QRshield certified" mark so a missing mark is a red flag (user education) | `test_attack_stripped_token_is_never_certified` |
| 7 | Edit the URL or any token field | `invalid` | signature covers canonical URL, issuer, key id, location, iat, exp | none | `test_attack_any_edit_breaks_the_signature`, `test_attack_edit_token_fields_individually` |
| 8 | Forged token that is also "expired" to get the milder verdict | `invalid` (BLOCK) | signature is verified **before** expiry/domain are trusted | none | `test_forged_signature_cannot_hide_behind_expiry` |
| 9 | Replay an old code after expiry | `expired` -> SUSPICIOUS | `exp` is signed | codes issued with "never expires" are replayable until revoked | `test_attack_replay_after_expiry` |
| 10 | **Copy a genuine signed code to another place** | `valid` | the signed location id is surfaced; expiry; the sticker check flags paste-overs | **A signature cannot detect a faithful copy.** This is an inherent limit of any signature scheme. Mitigations are partial (location binding is *shown*, not enforced by a registry lookup; rolling tokens for payment counters are future work) | `test_replay_of_a_genuine_signed_code_...` |
| 11 | Use a stolen issuer key | `revoked` after the CRL update | root-signed, versioned CRL; per-key revocation; key rotation; short-lived certificates | valid until the verifier sees the new CRL (offline verifiers lag by their cache age) | `test_attack_stolen_key_after_revocation`, `test_key_rotation_invalidates_the_stolen_old_key` |
| 12 | Roll the CRL back to hide a revocation | rejected | verifiers keep the highest version seen and verify the CRL signature | a brand-new verifier with no cache has nothing to compare against | `test_attack_crl_rollback_hides_a_revocation`, `test_crl_rollback_is_rejected` |
| 13 | Forge a CRL | rejected | CRL must verify against the pinned root | none | `test_attack_forged_crl_signed_by_someone_else` |
| 14 | Run the verifier without a trust anchor | everything `unknown_issuer` | fail closed | none | `test_no_trust_anchor_means_nothing_verifies` |
| 15 | Register a certificate for a bare suffix (`com`, `co.in`) or an IP | refused | `validate_certified_domain` | the registry still trusts the *admin* to vet who owns a domain (no DNS challenge in this demo) | `test_bare_suffix_and_garbage_domains_rejected` |
| 16 | Call registry/admin routes without the token | 401 | admin token, constant-time compare | the token is a single shared secret, appropriate for a demo, not for production | `test_admin_routes_require_the_token` |
| 17 | Make the analyser fetch internal URLs (SSRF) via a shortener or redirect | blocked | http(s) only; resolve once, every address must be globally routable; connect to the validated IP (DNS-rebinding-proof); every hop re-validated; HEAD only, timeouts | a hostile *public* server can still learn that its link was scanned (privacy) - shortener inspection can be disabled with `QRSHIELD_ONLINE_CHECKS=0` | `tests/test_network_security.py` |
| 18 | Upload a decompression bomb / giant file / garbage | refused before decoding | size and pixel limits checked from the header | none | `test_decompression_bomb_*`, `test_oversized_upload_*` |
| 19 | Hostile payload (`http://[x`, 4 kB strings, NULs, script tags) | never a 500 | parsing never raises; output is data, rendered as text | none | `test_hostile_payloads_never_cause_a_500` |
| 20 | Stored XSS through reports or issuer names | inert | UI builds DOM with `textContent` only; strict CSP forbids inline script | none | `test_report_then_admin_review_and_xss_is_inert` (browser) |
| 21 | Click-jack a "SAFE" verdict | blocked | `frame-ancestors 'none'` / `X-Frame-Options: DENY` | none | `test_index_and_assets_served_with_security_headers` |
| 22 | **Poison the model** by mass-reporting good links as phishing | candidate rejected | human review + fixed benchmark + canary links; only approved reports are used | an attacker who also fools the reviewer on many *plausible* reports could bias the model within the gate's tolerance | `test_poisoning_by_mass_reports_is_rejected` |
| 23 | Abuse scan/report endpoints | 429 | sliding-window rate limits | per-IP limits are bypassable by distributed clients | `test_rate_limits` |
| 24 | Sticker pasted over a legitimate **unsigned** code | `SUSPICIOUS` for imperfect covers | sticker check + link check | **A perfectly fitted sticker is close to indistinguishable from a genuine sticker.** Recall for exact-fit/larger covers is low (`docs/evaluation.md`); only signing the *original* code makes that attack detectable | `docs/results/cv_metrics.json` |

## Design decisions worth defending

* **Why Ed25519?** 64-byte signatures (RSA-2048: 256) keep the printed code sparse and easy to scan; deterministic signing removes ECDSA nonce-reuse failures; fast verification; strong security level; a mature, audited implementation (`cryptography`).
* **Why a binary token?** ~140 characters versus ~290 for JSON: fewer modules means a larger, more robust printed code.
* **Why verify the signature first?** So a forged token cannot choose a gentler verdict by pretending to be expired.
* **Why can a photo never BLOCK on its own?** Visual evidence is probabilistic and, on simulated data, has a measurable false-positive rate; a wrong BLOCK is costly, so it only escalates to SUSPICIOUS unless another independent layer agrees.
* **Why not just a blocklist?** It is reactive: it misses zero-day links and cannot see a sticker over a clean link.

## Privacy

Photos are analysed in memory and not stored. Reports store the link, a SHA-256 fingerprint, the user's label and optional note - no photo, no identity. Scan telemetry stores only a payload hash, scores and timing. History in the browser stays in the browser.
