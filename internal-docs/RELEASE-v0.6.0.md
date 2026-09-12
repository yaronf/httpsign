# Release notes: httpsign v0.6.0 (shipped)

Published GitHub release for tag `v0.6.0`. Kept here for maintainers; do not treat as a draft for retagging.

---

## Summary

**Breaking release:** requires **Go 1.27+** and replaces dual `jwx/v2` + `jwx/v3` foreign-JWS support with a single **`github.com/lestrrat-go/jwx/v4`** dependency (≥ v4.4.0 at ship time).

### Highlights

- **One foreign-JWS API:** `NewJWSSigner` / `NewJWSVerifier` only (`NewJWSSignerV3`, `NewJWSVerifierV3`, and the old v2-typed overloads are removed).
- **Post-quantum (ML-DSA):** sign and verify HTTP messages with `crypto/mldsa` keys and `jwa.MLDSA44()` / `MLDSA65()` / `MLDSA87()` through the same constructors (Go 1.27 stdlib; no extra modules).
- **Constructor hardening:** foreign JWS keys are validated at `NewJWS*` time.
- **Native algorithms unchanged** in API shape (HMAC-SHA256, RSA, RSA-PSS, P-256/P-384, Ed25519); only the Go toolchain floor moves to 1.27.

### Upgrade from v0.5.x

| You use | Action |
|---------|--------|
| **Native signers/verifiers only** | Bump Go to **1.27+** and upgrade httpsign. No API changes. |
| **`NewJWSSignerV3` / `NewJWSVerifierV3`** | Rename to `NewJWSSigner` / `NewJWSVerifier`; change `github.com/lestrrat-go/jwx/v3/jwa` → `.../jwx/v4/jwa`. |
| **`NewJWSSigner` / `NewJWSVerifier` (v2)** | Same as above: v4 import path and algorithm values (e.g. `jwa.ES256()`). |
| **Foreign JWS signing** | Keep `SignConfig.SignAlg(false)` — RFC 9421 has no `alg` parameter for arbitrary JWS algorithms. |
| **Foreign JWS verifying** | `VerifyConfig.SetAllowedAlgs` filters the HTTP **Signature** `alg` parameter if present; it does **not** select the JWS algorithm (that comes from `NewJWSVerifier`). |

```go
import "github.com/lestrrat-go/jwx/v4/jwa"

signer, err := httpsign.NewJWSSigner(jwa.ES256(), privKey, config.SignAlg(false), fields)
verifier, err := httpsign.NewJWSVerifier(jwa.ES256(), &privKey.PublicKey, verifyConfig, fields)
```

**Follow-on:** foreign-JWS allowlist + infer-alg verify API ships in **[v0.6.1](./RELEASE-v0.6.1.md)**.
