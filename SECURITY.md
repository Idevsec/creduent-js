# Security Policy

We take the security of this SDK and the cryptographic integrity of the Creduent Protocol seriously.

---

## Supported Versions

Only the latest release of Creduent JS/TS SDK is actively supported with security patches and enhancements.

| Version | Supported |
| ------- | --------- |
| 1.x     | Yes       |
| < 1.0.0 | No        |

---

## Security Guarantees & Verification Integrity

Creduent JS/TS SDK implements strict safety and cryptographic validation measures:
*   **Decentralized, Local Verification:** Signature verification does not rely on third-party remote calls to confirm validity. Ed25519 signature checks are performed locally inside the runtime context.
*   **Zero-Dependency Scope:** Minimal dependency surface area reduces vulnerability risks due to supply-chain attacks.

---

## Reporting a Vulnerability

If you discover a security vulnerability within the Creduent JS/TS SDK (e.g., signature bypasses, JCS sorting flaws, or cryptographic exceptions leading to verification bypasses), please report it responsibly:

1. Do NOT open a public GitHub issue detailing the vulnerability.
2. Email your findings and a proof-of-concept (PoC) directly to the maintainers or security contacts at `security@idevsec.com`.
3. Allow the maintainers time to analyze, reproduce, and release a patch before disclosing details publicly.
