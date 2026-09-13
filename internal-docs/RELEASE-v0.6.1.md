# Release notes draft: httpsign v0.6.1

Copy the **Summary** section below into the GitHub release when tagging `v0.6.1`.

---

## Summary

**Breaking for foreign-JWS verify callers** (native signers/verifiers unchanged). Builds on **v0.6.0** (Go 1.27+, jwx v4, ML-DSA).

### Highlights

- **Preferred verify API:** `NewJWSVerifier(allowed, key, …)` infers the JWS algorithm from `jwk.Key`, `*ecdsa.PublicKey`, or `*mldsa.PublicKey`.
- **`NewJWSSignerFromJWK`:** infer alg from a **private** `jwk.Key` and sign (symmetric with preferred verify for JWK-stored keys).
- **Escape hatch:** `NewJWSVerifierWithAlg(allowed, alg, key, …)` when alg cannot be inferred (raw RSA/HMAC) or the store already chose alg. Today’s `NewJWSVerifier(alg, key, …)` migrates here.
- **`JWSAlgAllowlist`:** both verify constructors take an allowlist (`nil` skips policy for tests/lazy use). Prefer a non-nil allowlist when `keyid` can select among keys.
- **`NewJWSSigner`:** nil config defaults to `SignAlg(false)`; configs with `SignAlg(true)` are rejected.
- **`Fields.AddRequestComponent`:** convenience for required associated-request components (`;req`), equivalent to `AddHeaderExt(name, false, false, true, false)`.
- **Details by tag:** `RequestDetailsByTag` / `ResponseDetailsByTag` (strict) and `*DetailsListByTag` (lenient) locate signatures by the `tag` parameter; `MessageDetails.Label` holds the dictionary member name for `Verify*`. Sentinels: `ErrSignatureTagNotFound` / `ErrSignatureTagAmbiguous`.
- **jwx** bump to **≥ v4.5.0** (if not already on the release branch).

### Upgrade from v0.6.0

| You use | Action |
|---------|--------|
| **Native only** | No API changes. |
| **`NewJWSVerifier(alg, key, …)`** | Prefer `NewJWSVerifier(allowed, key, …)` when the key is inferrable; else `NewJWSVerifierWithAlg(allowed, alg, key, …)`. |
| **`NewJWSSigner`** | Omit config or keep `SignAlg(false)`; `SignAlg(true)` now errors. Prefer `NewJWSSignerFromJWK` when the private key is a JWK. |
| **HTTP `SetAllowedAlgs`** | Unchanged — Signature-Input `alg` only, not JWS `jwa`. |
| **Response `;req` fields** | Prefer `AddRequestComponent("@method")` (etc.) over `AddHeaderExt(..., false, false, true, false)`. |
| **Locate signature by `tag`** | Prefer `RequestDetailsByTag` / `ResponseDetailsByTag`, then `Verify*` on `details.Label` (see below). |

```go
allowed, _ := httpsign.NewJWSAlgAllowlist(jwa.ES256(), jwa.MLDSA65())
verifier, err := httpsign.NewJWSVerifier(allowed, pubKey, verifyConfig, fields)
// or:
verifier, err := httpsign.NewJWSVerifierWithAlg(allowed, jwa.RS256(), rsaPub, verifyConfig, fields)
```

**Details by tag** (when the dictionary label is not semantic):

```go
details, err := httpsign.RequestDetailsByTag(req, "app")
if err != nil {
	return err // includes ErrSignatureTagNotFound / ErrSignatureTagAmbiguous
}
// use details.KeyID to obtain verifier, then:
err = httpsign.VerifyRequest(details.Label, *verifier, req)
```

**ML-DSA:**

```go
priv, _ := mldsa.GenerateKey(mldsa.MLDSA65())
pub := priv.Public().(*mldsa.PublicKey)
allowed, _ := httpsign.NewJWSAlgAllowlist(jwa.MLDSA65())
signer, _ := httpsign.NewJWSSigner(jwa.MLDSA65(), priv, nil, fields)
// or, when the private key is a JWK:
// signer, _ := httpsign.NewJWSSignerFromJWK(privJWK, nil, fields)
verifier, _ := httpsign.NewJWSVerifier(allowed, pub, httpsign.NewVerifyConfig(), fields)
```

Design notes: [internal-docs/JWS-ALG-POLICY.md](./JWS-ALG-POLICY.md).
