# FENC

**FENC** is an experimental browser-based client-side file protection prototype built around the **FENC v3 encrypted-container format**.

> **Development status:** experimental development prototype. No numbered software release or production release has been issued. The `v3` identifier refers to the encrypted-container format, not to an application release version. The public GitHub Pages deployment is a fixed research artifact.

## Live prototype

**GitHub Pages:** https://omar-zeyane.github.io/FENC/

## Current capabilities

- Client-side file encryption and decryption in the browser
- AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, and an optional experimental Cascade composition
- Password-based protection with Argon2id or PBKDF2
- RSA-OAEP and ECDH key management with X25519 or P-256
- Multi-recipient encrypted containers
- Authenticated encrypted metadata and sequential authenticated chunks
- Cryptographic binding of the serialized fixed header and key block
- Explicit chunk-count guard below uint32 counter exhaustion
- RSA-PSS / ECDSA digital signatures
- Shamir secret sharing
- Optional PNG steganography workflow
- Limited alternate-content (`decoy`) workflow; no plausible-deniability guarantee is claimed

## Final research artifact

The repository's `index.html` is the frozen hardened research artifact associated with the current paper.

```text
SHA-256: 2c1e0b679f412a4d8f68aae3a097188b8bae729d43c0773df7069ca511e46de9
Git blob SHA: 68a89fa900c9ed21f46bdd803baebe649bde12fa
Size: 544,539 bytes
```

The application writer and parser enforce a maximum of **16,777,216 chunks**, well below exhaustion of the 32-bit chunk counter used in authenticated ordering/nonces.

Nonce uniqueness is scoped to a content-key domain. FENC establishes a fresh key domain for each encryption workflow; therefore, a repeated 64-bit per-file nonce prefix across independently keyed containers is not by itself nonce reuse under the same key. Security still depends on a trustworthy random-number generator and on keys not being externally forced into reuse.

## Reproducing the reported validation

Requirements: **Node.js 22.16.0** (or a compatible Node 22 environment with Web Crypto, File, and Blob support).

Run from the repository root:

```bash
node tests/fenc_regression_harness.js index.html
node tests/fenc_boundary_harness.js index.html
node tests/fenc_parser_fuzz.js index.html 0xF3E0C123
```

Published results:

- Baseline regression/security/counter harness: **32/32 passed**
  - Regression set: **18/18**
  - Security-relevant targeted subset: **13/13**
  - Existing counter-limit guard: **1/1**
- Additional boundary/edge-case harness: **5/5 passed**
- Combined functional/targeted/counter/boundary checks: **37/37 passed**
- Deterministic malformed-container campaign: **10,000/10,000 rejected as expected**
- Unexpected accepts in the mutation campaign: **0**

Reports are preserved under `tests/`, including `FENC_Final_Validation_Report.txt`, `FENC_Boundary_Validation_Report.txt`, and `FENC_Parser_Fuzz_Report.txt`.

The mutation campaign includes single-byte mutations, truncations, trailing-byte extensions, arbitrary random blobs, and FENC-looking malformed structures. It is negative testing, not formal verification, coverage-guided exhaustive fuzzing, or an independent security audit.

## Evaluation scope

The final paper does **not** use the earlier pre-hardening primitive-only throughput observation as publication evidence. A controlled cross-browser, end-to-end performance study with documented hardware and statistical treatment is left to future work.

## Security scope

FENC is a research/development prototype, not an independently audited production cryptographic product. Its security claims are limited to the threat model and validation documented in the associated research work. Endpoint compromise, malicious browser extensions, live-memory inspection, strict timing/side-channel resistance, freshness/anti-replay guarantees, and forensic plausible deniability are outside the primary protection claims.

The optional Cascade mode is retained as an experimental composition/engineering option; FENC does not claim that it is stronger than a single well-vetted AEAD construction.

## Authors

Graduation-project research prototype developed at the Faculty of Information Technology, Elmergib University, Libya.

- Omar Hasan Alzayani
- Supervisor: Bashir Mujber

## License

No open-source license is granted yet. All rights are reserved until a license is selected explicitly.
