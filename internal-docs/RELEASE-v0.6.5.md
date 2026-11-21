# Release notes: httpsign v0.6.5 (shipped)

Published GitHub release for tag `v0.6.5`. Kept here for maintainers; do not treat as a draft for retagging.

---

## Summary

Native IANA ML-DSA HTTP Signature Algorithms (`ml-dsa-44` / `65` / `87`) via Go’s `crypto/mldsa`, plus a GREASE-style regression test for unrecognized signature metadata parameters.

### Native ML-DSA (`ml-dsa-44` / `65` / `87`) — [#52](https://github.com/yaronf/httpsign/pull/52) / [#51](https://github.com/yaronf/httpsign/issues/51)

`NewMLDSA44Signer` / `NewMLDSA44Verifier` (and the `-65` / `-87` pairs) implement the [HTTP Signature Algorithms](https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml) registered from [C2SP httpsig-pq](https://c2sp.org/httpsig-pq@v1.0.1). They take `*mldsa.PrivateKey` / `*mldsa.PublicKey`, emit the IANA `alg` values, and use hedged `Sign`. Conformance vectors are vendored from httpsig-pq@v1.0.1.

Prefer these constructors when you need an HTTP `alg` parameter. Foreign JWS (`NewJWSSigner` / `NewJWSVerifier*`) still uses JOSE algorithm names and cannot emit HTTP `alg`.

ML-DSA signatures are large (about 3.2–6.2 KiB Base64 before field overhead); raise intermediary header limits if needed.

### GREASE: unrecognized signature metadata params — [#54](https://github.com/yaronf/httpsign/pull/54) / [#53](https://github.com/yaronf/httpsign/issues/53)

`TestGreaseSignatureMetadataParams` checks that verification still succeeds when `Signature-Input` carries unrecognized metadata parameters (and that they remain available via `CustomParams`). Unknown **component** parameters are unchanged: they still fail verification (RFC 9421).

## Upgrade notes

| Area | Before | After |
|------|--------|--------|
| IANA ML-DSA HTTP algs | Foreign JWS only (JOSE names, no HTTP `alg`) | Native `NewMLDSA{44,65,87}{Signer,Verifier}` with IANA `alg` |
| Metadata “grease” | Covered only by `AddCustomParam` round-trips | Explicit GREASE regression test |

No breaking changes for existing signers/verifiers. Peers that need IANA `ml-dsa-*` on the wire should use the native constructors on both sides.

## PRs in this release

- [#52](https://github.com/yaronf/httpsign/pull/52) — native ML-DSA HTTP Signature Algorithms
- [#54](https://github.com/yaronf/httpsign/pull/54) — GREASE tests for signature metadata must-ignore params
