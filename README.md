# FENC

**FENC** is an experimental browser-based client-side file protection prototype built around the **FENC v3 encrypted-container format**.

> **Development status:** experimental development prototype. No numbered software release or production release has been issued. The `v3` identifier refers to the encrypted-container format, not to an application release version. The public GitHub Pages deployment is a fixed research artifact.

## Live prototype

**GitHub Pages:** https://omar-zeyane.github.io/FENC/

## Current capabilities

- Client-side file encryption and decryption in the browser
- AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, and an optional **experimental** Cascade composition
- Password-based protection with Argon2id or PBKDF2
- RSA-OAEP and ECDH key management with X25519 or P-256
- Multi-recipient encrypted containers
- Authenticated encrypted metadata and sequential authenticated chunks
- Cryptographic binding of the serialized fixed header and key block
- Explicit chunk-count guard below uint32 counter exhaustion
- Writer/parser chunk-size bounds of **1 KiB–128 MiB**
- RSA-PSS / ECDSA digital signatures
- Shamir secret sharing
- Optional PNG steganography workflow
- Limited alternate-content (`Decoy`) workflow; **no plausible-deniability or forensic-resistance guarantee is claimed**

## Final research artifact

The repository's `index.html` is the frozen hardened research artifact associated with the current paper.

```text
SHA-256: 0860c6cdad4c48232e5318b6c9003ea70ed2db8165680db836e893adbe8b3fdb
Git blob SHA: 0b1e2f544872fb73f4d32d16fbc40ba80317b1dc
Size: 544,996 bytes
```

The application writer and parser enforce a maximum of **16,777,216 chunks**, well below exhaustion of the 32-bit chunk counter used in authenticated ordering/nonces.

Nonce uniqueness is scoped to a content-key domain. FENC establishes fresh file-level key material for each normal encryption workflow. A repeated 64-bit per-file nonce prefix across independently keyed containers is therefore not, by itself, same-key nonce reuse. Reusing one master key across multiple containers is not a supported workflow.

## Reproducing the reported validation

Requirements: **Node.js 22.16.0** (or a compatible Node 22 environment with Web Crypto, File, and Blob support).

Run from the repository root:

```bash
node tests/fenc_regression_harness.js index.html
node tests/fenc_edge_validation.js index.html
node tests/fenc_parser_fuzz.js index.html 10000
```

Published results:

- Baseline regression/security/counter harness: **32/32 passed**
  - Regression set: **18/18**
  - Security-relevant targeted subset: **13/13**
  - Counter-limit guard: **1/1**
- Edge-case harness: **13/13 passed**
- Random serialized-container mutations: **10,000/10,000 rejected**
- Unexpected accepts: **0**
- Harness exceptions: **0**
- Structured malformed-container cases: **17/17 rejected**

Reports are preserved under `tests/`:
- `FENC_Final_Validation_Report.txt`
- `FENC_Edge_Validation_Report.txt`
- `FENC_Parser_Fuzz_Report.txt`

The mutation campaign is negative testing, not formal verification, exhaustive parser proof, coverage-guided fuzzing, or an independent security audit.

## Evaluation scope

The final paper removes the earlier pre-hardening primitive-only throughput table from publication evidence. A controlled cross-browser, end-to-end performance study with documented hardware and statistical treatment is left to future work.

Cross-browser validation has **not** been claimed from the Node.js harnesses. Chrome/Chromium, Edge, Firefox, large-file stress testing, and multi-gigabyte end-to-end I/O remain explicit future validation work.

## Security scope

FENC is a research/development prototype, not an independently audited production cryptographic product. Its security claims are limited to the threat model and validation documented in the associated research work. Endpoint compromise, malicious browser extensions, live-memory inspection, strict timing/side-channel resistance, freshness/anti-replay guarantees, and forensic plausible deniability are outside the primary protection claims.

The optional Cascade mode is retained only as an experimental engineering composition. FENC does **not** claim that it is stronger than a single well-configured AEAD construction.

## Authors

Graduation-project research prototype developed at the Faculty of Information Technology, Elmergib University, Libya.

- Omar Hasan Alzayani
- Supervisor: Bashir Mujber

## License

No open-source license is granted yet. All rights are reserved until a license is selected explicitly.
