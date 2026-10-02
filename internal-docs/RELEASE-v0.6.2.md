# Release notes: httpsign v0.6.2 (shipped)

Published GitHub release for tag `v0.6.2`. Kept here for maintainers; do not treat as a draft for retagging.

---

## Summary

**Additive compatibility restore** for foreign JWS (native signers unchanged). Builds on **v0.6.1**.

### Highlights

- **`crypto.Signer` (HSM/KMS)** accepted again for foreign JWS **RSA / ECDSA / Ed25519 / ML-DSA** on both `NewJWSSigner` and `NewJWSVerifierWithAlg` (and verify paths that share `validateJWSKeyAlg`).
- Validation uses `Public()` shape + existing curve / ML-DSA parameter-set checks; panics from `Public()` are recovered as construction errors.
- **ML-DSA note:** default jwx still signs only with `*mldsa.PrivateKey`. Opaque ML-DSA Signers need a custom [`jws.RegisterSigner`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jws#RegisterSigner). ML-DSA stays foreign-JWS only (not a native RFC 9421 algorithm).
- **JWK** still rejected in raw constructors (`NewJWSSignerFromJWK` / preferred `NewJWSVerifier`).

### Upgrade from v0.6.1

| You use | Action |
|---------|--------|
| **Native only / raw stdlib JWS keys** | No change. |
| **Opaque `crypto.Signer` for RS\*/PS\*/ES\*/EdDSA** | Works again (was rejected at construction in v0.6.0–v0.6.1). |
| **Opaque `crypto.Signer` for ML-DSA** | Construction accepted; register a custom jwx ML-DSA signer for Sign, or keep using raw `*mldsa.PrivateKey`. |
| **JWK in `NewJWSSigner`** | Unchanged — use `NewJWSSignerFromJWK`. |

### Backward compatibility

This partially rolls back v0.6’s “raw stdlib only” foreign-JWS key policy. Callers already using raw keys are unaffected. Same caveat as jwx: external `crypto.Signer` makes alg/key misuse harder to catch than in-process stdlib types.

Fixes [#34](https://github.com/yaronf/httpsign/issues/34).

Thanks to [@ilya-korotya](https://github.com/ilya-korotya) for reporting the regression and for the draft fix in [#35](https://github.com/yaronf/httpsign/pull/35).
