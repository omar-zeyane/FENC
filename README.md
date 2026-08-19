# FENC

**FENC** is an experimental browser-based client-side file protection prototype built around the **FENC v3 encrypted-container format**.

> **Development status:** experimental development prototype. No public or production application release has been issued. The `v3` identifier refers to the encrypted-container format, not to an application release version.

## Current capabilities

- Client-side file encryption and decryption in the browser
- AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, and optional cascade mode
- Password-based protection with Argon2id or PBKDF2
- RSA-OAEP and ECDH-based key management
- Multi-recipient encrypted containers
- Authenticated encrypted metadata and sequential authenticated chunks
- Header/key-block binding in the current hardened experimental artifact
- RSA-PSS / ECDSA digital signatures
- Shamir secret sharing
- Optional PNG steganography workflow
- Built-in validation and performance-testing utilities

## Research artifact

The repository's `index.html` is the hardened experimental research artifact used for the current reproducibility record.

SHA-256:

```text
945737b4b799240b84d588affdbbf116d0b354d5b92ee4dddc06af73c34b303a
```

Git blob SHA:

```text
073aef1dadfb3ff9a5e8fcd4bea6a55e5b34fb96
```

File size: **544,088 bytes**.

These identifiers are recorded so reviewers and future users can verify that they are using the exact experimental artifact associated with the paper.

## Running the prototype

The project is a self-contained HTML application. Download `index.html` and open it in a modern browser. When GitHub Pages is enabled for this repository, the same file can be served directly from the repository's Pages site.

## Security scope

FENC is a research/development prototype, not an independently audited production cryptographic product. Its security claims are limited to the threat model and validation documented in the associated research work. Endpoint compromise, malicious browser extensions, live-memory inspection, timing/side-channel resistance, and freshness/anti-replay guarantees are outside the primary protection claims.

## Authors

Graduation-project research prototype developed at the Faculty of Information Technology, Elmergib University, Libya.

- Omar Hasan Alzayani
- Supervisor: Bashir Mujber

## License

No open-source license is granted yet. All rights are reserved until a license is selected explicitly.
