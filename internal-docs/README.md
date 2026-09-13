# Internal Documentation

This directory contains internal documentation for maintainers of the httpsign library.

## Contents

- **FUZZ.md** — Fuzz suite playbook: targets, local/CI commands, how to read metrics and corpus layout.
- **JWX.md** — Optional jwx / foreign-JWS: cut over to jwx v4 on Go 1.27+ as **httpsign `v0.6.0`**, with **ML-DSA PQ signatures**.
- **JWS-ALG-POLICY.md** — Foreign-JWS alg allowlist + infer-alg `NewJWSVerifier` (ships in **`v0.6.1`**).
- **RELEASE-v0.6.0.md** — Shipped **v0.6.0** release notes (archive).
- **RELEASE-v0.6.1.md** — Shipped **v0.6.1** release notes (archive).

## Purpose

Internal documentation includes:
- Dependency migration plans
- Technical decision records
- Maintenance guides

This documentation is not meant for end users of the library. For user-facing documentation, see the main README.md.
