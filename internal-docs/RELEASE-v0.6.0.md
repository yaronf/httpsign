# Release notes draft: httpsign v0.6.0

Copy the **Summary** section below into the GitHub release when tagging `v0.6.0`.

---

## Summary

**Breaking release:** requires **Go 1.27+** and replaces dual `jwx/v2` + `jwx/v3` foreign-JWS support with a single **`github.com/lestrrat-go/jwx/v4`** dependency (≥ v4.4.0).

### Highlights

- **One foreign-JWS API:** `NewJWSSigner` / `NewJWSVerifier` only (`NewJWSSignerV3`, `NewJWSVerifierV3`, and the old v2-typed overloads are removed).
- **Post-quantum (ML-DSA):** sign and verify HTTP messages with `crypto/mldsa` keys and `jwa.MLDSA44()` / `MLDSA65()` / `MLDSA87()` through the same constructors (Go 1.27 stdlib; no extra modules).
- **Constructor hardening:** foreign JWS keys are validated at `NewJWS*` time (algorithm family, ECDSA curve bind per RFC 7518, HMAC minimum length, private key for signers / public key for verifiers). `jwa.NoSignature()` is rejected.
- **Native algorithms unchanged** in API shape (HMAC-SHA256, RSA, RSA-PSS, P-256/P-384, Ed25519); only the Go toolchain floor moves to 1.27.

### Upgrade from v0.5.x

| You use | Action |
|---------|--------|
| **Native signers/verifiers only** | Bump Go to **1.27+** and upgrade httpsign. No API changes. |
| **`NewJWSSignerV3` / `NewJWSVerifierV3`** | Rename to `NewJWSSigner` / `NewJWSVerifier`; change `github.com/lestrrat-go/jwx/v3/jwa` → `.../jwx/v4/jwa`. |
| **`NewJWSSigner` / `NewJWSVerifier` (v2)** | Same as above: v4 import path and algorithm values (e.g. `jwa.ES256()`). |
| **Foreign JWS signing** | Keep `SignConfig.SignAlg(false)` — RFC 9421 has no `alg` parameter for arbitrary JWS algorithms. |
| **Foreign JWS verifying** | `VerifyConfig.SetAllowedAlgs` filters the HTTP **Signature** `alg` parameter if present; it does **not** select the JWS algorithm (that comes from `NewJWSVerifier`). |

**jwx v4 algorithm values** are functions, not string constants:

```go
import "github.com/lestrrat-go/jwx/v4/jwa"

signer, err := httpsign.NewJWSSigner(jwa.ES256(), privKey, config.SignAlg(false), fields)
verifier, err := httpsign.NewJWSVerifier(jwa.ES256(), &privKey.PublicKey, verifyConfig, fields)
```

**ML-DSA example** (RFC 9421 does not register HTTP-sig algorithm names for ML-DSA; use foreign JWS with `SignAlg(false)`):

```go
priv, _ := mldsa.GenerateKey(mldsa.MLDSA65())
pub := priv.Public().(*mldsa.PublicKey)
config := httpsign.NewSignConfig().SignAlg(false)

signer, _ := httpsign.NewJWSSigner(jwa.MLDSA65(), priv, config, fields)
verifier, _ := httpsign.NewJWSVerifier(jwa.MLDSA65(), pub, httpsign.NewVerifyConfig(), fields)
```

HMAC keys for foreign JWS must be `[]byte` (not `string`), at least 32/48/64 bytes for HS256/384/512 per RFC 7518.

### Toolchain

- **Go:** 1.27.0+ (`encoding/json/v2` in stdlib; no `GOEXPERIMENT=jsonv2`).
- **jwx:** v4.4.0+ only; v2 and v3 are no longer pulled transitively.

### Upstream references

- [jwx v4 MIGRATION.md](https://github.com/lestrrat-go/jwx/blob/v4.4.0/MIGRATION.md)
- [jwx v4 Changes-v4.md](https://github.com/lestrrat-go/jwx/blob/v4.4.0/Changes-v4.md)

### Also in v0.6.0 (non-breaking behavior fixes)

- `SetVerifyDateWithin` now correctly reads the HTTP `Date` header (lowercase key in parsed messages).
- Defensive checks for malformed ECDSA keys, empty header value lists, and nil client/signer/verifier config.