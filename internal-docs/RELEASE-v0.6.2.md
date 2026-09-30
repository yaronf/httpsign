# Release notes: httpsign v0.6.2 (draft)

Maintainer draft for the next patch after **v0.6.1**. Tag only when ready.

---

## Summary

**Additive compatibility restore** for foreign JWS (native signers unchanged). Builds on **v0.6.1**.

### Highlights

- **`crypto.Signer` (HSM/KMS)** accepted again for classical foreign JWS **RSA / ECDSA / Ed25519** on both `NewJWSSigner` and `NewJWSVerifierWithAlg` (and verify paths that share `validateJWSKeyAlg`).
- Validation uses `Public()` shape + existing curve/length checks; panics from `Public()` are recovered as construction errors.
- **ML-DSA** still requires raw `crypto/mldsa` keys (no opaque Signer).
- **JWK** still rejected in raw constructors (`NewJWSSignerFromJWK` / preferred `NewJWSVerifier`).

### Upgrade from v0.6.1

| You use | Action |
|---------|--------|
| **Native only / raw stdlib JWS keys** | No change. |
| **Opaque `crypto.Signer` for RS\*/PS\*/ES\*/EdDSA** | Works again (was rejected at construction in v0.6.0–v0.6.1). |
| **ML-DSA / JWK in `NewJWSSigner`** | Unchanged — raw ML-DSA; use FromJWK for JWKs. |

### Backward compatibility

This partially rolls back v0.6’s “raw stdlib only” foreign-JWS key policy for classical algorithms only. Callers already using raw keys are unaffected. Same caveat as jwx: external `crypto.Signer` makes alg/key misuse harder to catch than in-process stdlib types.

Fixes [#34](https://github.com/yaronf/httpsign/issues/34).

Thanks to [@ilya-korotya](https://github.com/ilya-korotya) for reporting the regression and for the draft fix in [#35](https://github.com/yaronf/httpsign/pull/35).
