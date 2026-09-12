# Internal Documentation

This directory contains internal documentation for maintainers of the httpsign library.

## Contents

- **JWX.md** — Optional jwx / foreign-JWS: cut over to jwx v4.5.0+ on Go 1.27+ as **httpsign `v0.6.0`**, with **ML-DSA PQ signatures** as an explicit goal. Gate met 2026-08-26.
- **JWS-ALG-POLICY.md** — Proposed foreign-JWS alg allowlist; preferred infer-alg `NewJWSVerifier` / escape `WithAlg` (on-demand keys).
- **RELEASE-v0.6.0.md** — Draft GitHub release text and upgrade guide for **v0.6.0** (copy Summary into the release when tagging).

## Purpose

Internal documentation includes:
- Dependency migration plans
- Technical decision records
- Maintenance guides

This documentation is not meant for end users of the library. For user-facing documentation, see the main README.md.
