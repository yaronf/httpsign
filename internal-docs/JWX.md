# jwx / foreign JWS plan (maintainers)

Single source of truth for optional jwx-backed JWS support in httpsign.

## Role in httpsign

jwx is used only for **optional “foreign” JWS** signing and verification. **Native** algorithms (HMAC-SHA256, RSA, RSASSA-PSS, P-256/P-384, Ed25519) do **not** use jwx.

**On `jwx-v4-cutover` / for `v0.6.0`:** single dependency `github.com/lestrrat-go/jwx/v4` (**≥ v4.4.0**); public API is `NewJWSSigner` / `NewJWSVerifier` only (v2 and `*V3` removed). Go floor **1.27.0**. ML-DSA via the same constructors.

**Previously (≤ v0.5.x):** `go.mod` pulled both `jwx/v2` and `jwx/v3`, with `NewJWSSigner`/`NewJWSVerifier` (v2) and `NewJWSSignerV3`/`NewJWSVerifierV3` (v3).

---

## Explicit goals

1. **Drop dual jwx support** — cut over to **jwx v4 only** on **Go 1.27+**, released as **`v0.6.0`**. Details in the next sections.
2. **PQ signatures** — make **ML-DSA (FIPS 204)** usable for RFC 9421 HTTP Message Signatures through httpsign’s foreign-JWS path (and document it), in **`v0.6.0`** or a fast follow (`v0.6.x` / `v0.7.0` only if PQ slips).

### PQ signatures (goal detail)

Go 1.27 adds stdlib [`crypto/mldsa`](https://pkg.go.dev/crypto/mldsa). jwx v4 registers **ML-DSA-44 / ML-DSA-65 / ML-DSA-87** natively when built with Go 1.27+ (`jwa.MLDSA44()`, `MLDSA65()`, `MLDSA87()`; `*mldsa.PrivateKey` / `*mldsa.PublicKey` work with `jws.Signer` / `jws.Verifier`). The companion [`github.com/jwx-go/mldsa/v4`](https://github.com/jwx-go/mldsa) is **not** required on our Go floor.

**In scope for httpsign**

- After the v4 cutover, `NewJWSSigner` / `NewJWSVerifier` must accept ML-DSA algs + `crypto/mldsa` keys the same way they accept classical JWS algs (no special `GOEXPERIMENT`, no optional build tags).
- Round-trip tests: sign and verify an HTTP request (or signature base) with at least one parameter set (prefer **ML-DSA-65** as the default demo; cover 44/87 if cheap).
- README / release notes: call out PQ via foreign JWS; note that RFC 9421 does not assign HTTP-sig algorithm identifiers for ML-DSA — callers use the JWS/`alg` story (or omit `alg` per profile) as with other foreign algorithms.
- Reject `NoSignature` and other unsafe algs unchanged.

**Out of scope (for now)**

- **Native** `NewMLDSASigner`-style constructors that bypass jwx (revisit only if foreign-JWS overhead or API clarity demands it).
- **Hybrid composite** signatures ([`jwx-go/compsig`](https://github.com/jwx-go/compsig), draft-ietf-jose-pq-composite-sigs) — track as a follow-on once the draft and companion stabilize.
- **ML-KEM / JWE / HPKE** — encryption, not HTTP message signatures.

**Why fold PQ into this work:** the Go 1.27 + jwx v4 cutover is exactly what unlocks stdlib ML-DSA without experiments or extra modules. Shipping `v0.6.0` without exercising PQ would leave the main benefit of the floor unused.

---

## Status (2026-08-26): cutover implemented on branch `jwx-v4-cutover`

Ship as **`v0.6.0`** when merged. Dual v2+v3 is removed on this branch.

| Gate | Status |
|------|--------|
| Go **1.27.0** stable on [go.dev/dl](https://go.dev/dl/) | **Met** (released 2026-08-19) |
| `encoding/json/v2` in stdlib (no `GOEXPERIMENT=jsonv2`) | **Met** — see [Go 1.27 notes](https://go.dev/doc/go1.27) |
| jwx v4 mature | **Met** — pinned **`v4.4.0`** |
| Smoke / full tests under `GOTOOLCHAIN=go1.27.0` | **Met** on cutover branch |
| Stdlib **`crypto/mldsa`** + jwx native ML-DSA (PQ goal) | **Met** — `TestForeignSignerMLDSA` (44/65/87) |

### Why this was deferred (history)

- On Go 1.26, jwx v4 required `GOEXPERIMENT=jsonv2` on every httpsign build — rejected for a library.
- Dual v2+v3 was an interim; we deliberately avoided a “deprecate v2 → use V3” step that would bounce callers twice.
- **Agreed (2026-07):** all-in on jwx v4 after Go 1.27 stable, as a **breaking** httpsign release.
- **Agreed (2026-08-26):** Go 1.27 is out; **start the cutover** and ship it as **`v0.6.0`** (not `v1.0.0`).

---

## Decision: all-in on jwx v4 (`v0.6.0`)

Cut over to **`github.com/lestrrat-go/jwx/v4` only**, pin **≥ v4.4.0**, drop v2 and v3 in **`v0.6.0`**.

### What the cutover does

- Raise `go` / toolchain / CI to **Go 1.27.0+**.
- Drop `jwx/v2` and `jwx/v3` from `go.mod`.
- Single constructor pair on v4 types: **`NewJWSSigner` / `NewJWSVerifier`** (remove `*V3`; retire the v2-typed overloads).
- Follow upstream [MIGRATION.md](https://github.com/lestrrat-go/jwx/blob/v4.4.0/MIGRATION.md) and optionally [jwxmigrate](https://github.com/jwx-go/jwxmigrate) (`jwxmigrate/v4`).
- Re-run foreign-JWS tests (classical + **ML-DSA**); note behavioral tightenings in [Changes-v4.md](https://github.com/lestrrat-go/jwx/blob/v4.4.0/Changes-v4.md) if any affect jwa/jws-only use.
- Update `CLAUDE.md` / README snippets that still recommend dual v2/v3 or `*V3`; document PQ via foreign JWS.
- Tag and release **`v0.6.0`**.

### Deprecation / messaging

- **No** mid-stream “prefer V3” deprecation before `v0.6.0`.
- In `v0.6.0`: remove v2 constructors and `*V3` together; release notes document the caller steps below.
- Optional: if a short transition branch is needed for review only, both old APIs may carry `// Deprecated:` pointing at the v4-backed `NewJWS*` — never ship “V3 is the stable end state.”

### Customer impact

| Caller | Change |
|--------|--------|
| **Native algorithms only** | Go **1.27+** floor; otherwise unaffected |
| **`NewJWSSignerV3` / `NewJWSVerifierV3`** | Bump to **`v0.6.0`**; import `jwx/v3/jwa` → `jwx/v4/jwa`; rename to `NewJWSSigner` / `NewJWSVerifier` (v4 `jwa` uses function forms like `jwa.ES256()`) |
| **`NewJWSSigner` / `NewJWSVerifier` (v2)** | Same release: switch to v4 imports + v4 algorithm values; no separate `*V3` step |

No change to key types or httpsign `SignConfig` / `VerifyConfig` / `Fields` for classical callers. **PQ callers** bring `crypto/mldsa` keys and `jwa.MLDSA*()` through the same `NewJWS*` constructors. ES256K / Ed448 companions, custom jwx signers, and JWKS fetch remain niche; composite PQ is a later follow-on (see Explicit goals).

### Toolchain after cutover

| Item | Requirement |
|------|-------------|
| Go | **1.27.0+** in `go.mod` / CI |
| golangci-lint | **≥ v2.13** (built with Go 1.27; v2.12.x fails with go.mod `1.27.0`) |
| `GOEXPERIMENT=jsonv2` | Not required; do not set |
| `GOEXPERIMENT=nojsonv2` | Avoid in CI |

Upstream still allows Go 1.26 + `GOEXPERIMENT=jsonv2` for jwx v4; **httpsign will not support that** — floor is 1.27 so consumers never need the experiment.

---

## Implementation checklist (do now)

Scoped to httpsign’s use of **jwa** + **jws** only (no JWT/JWE/JWK fetch in library glue). Upstream detail: [MIGRATION.md (v4.4.0)](https://github.com/lestrrat-go/jwx/blob/v4.4.0/MIGRATION.md).

### Code / deps

- [x] `go.mod`: Go 1.27.0+; require `github.com/lestrrat-go/jwx/v4` (**≥ v4.4.0**); remove v2 and v3.
- [x] Rewrite imports `jwx/v2|v3` → `jwx/v4`; collapse constructors; update `sign()` / `verify()` dispatch for v4 `jws.Signer` / `jws.Verifier` (renamed from v3 `Signer2` / `Verifier2`; parameter order matches today’s V3 path: key before payload).
- [x] Confirm factory APIs (`SignerFor` / `VerifierFor`) and `NoSignature` rejection still work.
- [x] Drop v2↔v3 cross-compat tests; keep round-trip tests on the single v4 path.
- [x] **PQ:** foreign-JWS round-trips with `crypto/mldsa` + `jwa.MLDSA44/65/87()`; document in README/release notes.
- [ ] Run `jwxmigrate --fix` if helpful; fix remaining compile/test failures by hand. *(done by hand; migrate tool optional)*
- [x] CI (`test.yml`, `lint.yml`, CodeQL): Go **1.27**; do not set `jsonv2` / `nojsonv2`.
- [x] Lint: bump **golangci-lint ≥ v2.13** (v2.12.2 is built with go1.26 → fails on go.mod 1.27.0).
- [x] Docs: README / `CLAUDE.md` / this file — remove dual-version guidance; **`v0.6.0`** release notes with caller steps + PQ; link upstream Changes-v4 if relevant.
- [x] Hardening: constructor `jws.AlgorithmsForKey` check; reject `NoSignature`; HMAC keys must be `[]byte`; document `SetAllowedAlgs` vs JWS alg.
- [ ] Tag **`v0.6.0`** and publish. *(after merge)*

### Upstream items likely N/A or low priority

| Topic | httpsign |
|-------|----------|
| JWK `Import` generics, `ParseFS`, custom field registration | Unlikely / N/A |
| HTTP JWKS → `jwkfetch` | N/A in core; document if examples ever use `jku` |
| ES256K / Ed448 / asmbase64 companions | Only if we expose or test those algs |
| `jwx-go/mldsa/v4` companion | **N/A on Go 1.27+** (native in jwx); do not add the module |
| Composite PQ (`jwx-go/compsig`) | Follow-on after pure ML-DSA; draft-dependent |
| ML-KEM / HPKE | N/A (not signatures) |
| Custom `Signer`/`Verifier` with `Algorithm()` | We embed upstream implementations only — re-check types after rename |
| Detached payload `io.Reader` | Orthogonal (we sign the RFC 9421 base string as `[]byte`) |
