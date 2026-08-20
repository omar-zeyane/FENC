# FENC

**FENC** is an experimental browser-based client-side file protection prototype built around the **FENC v3 encrypted-container format**.

> **Development status:** experimental development prototype. No numbered software release or production release has been issued. The `v3` identifier refers to the encrypted-container format, not to an application release version. The public GitHub Pages deployment is a fixed research artifact.

## Live prototype

**GitHub Pages:** https://omar-zeyane.github.io/FENC/

## Current capabilities

- Client-side file encryption and decryption in the browser
- AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, and optional cascade mode
- Password-based protection with Argon2id or PBKDF2
- RSA-OAEP and ECDH key management with X25519 or P-256
- Multi-recipient encrypted containers
- Authenticated encrypted metadata and sequential authenticated chunks
- Cryptographic binding of the serialized fixed header and key block
- Explicit chunk-count guard below uint32 counter exhaustion
- RSA-PSS / ECDSA digital signatures
- Shamir secret sharing
- Optional PNG steganography workflow
- Built-in validation and performance-testing utilities

## Final research artifact

The repository's `index.html` is the final hardened research artifact associated with the current paper.

```text
SHA-256: 2c1e0b679f412a4d8f68aae3a097188b8bae729d43c0773df7069ca511e46de9
Git blob SHA: 68a89fa900c9ed21f46bdd803baebe649bde12fa
Size: 544,539 bytes
```

The application writer and parser enforce a maximum of **16,777,216 chunks**, well below exhaustion of the 32-bit chunk counter used in authenticated ordering/nonces.

## Reproducing the reported validation

Requirements: **Node.js 22.16.0** (or a compatible Node 22 environment with Web Crypto, File, and Blob support).

Run from the repository root:

```bash
node tests/fenc_regression_harness.js index.html
```

The published validation run reports:

- Regression suite: **18/18 passed**
- Security-relevant targeted subset: **13/13 passed**
- Explicit counter-limit guard: **1/1 passed**
- Overall: **32/32 passed**

The exact console output is preserved in `tests/FENC_Final_Validation_Report.txt`.

## Security scope

FENC is a research/development prototype, not an independently audited production cryptographic product. Its security claims are limited to the threat model and validation documented in the associated research work. Endpoint compromise, malicious browser extensions, live-memory inspection, strict timing/side-channel resistance, and freshness/anti-replay guarantees are outside the primary protection claims.

## Authors

Graduation-project research prototype developed at the Faculty of Information Technology, Elmergib University, Libya.

- Omar Hasan Alzayani
- Supervisor: Bashir Mujber

## License

No open-source license is granted yet. All rights are reserved until a license is selected explicitly.
