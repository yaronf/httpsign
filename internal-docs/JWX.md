# jwx / foreign JWS plan (maintainers)

Single source of truth for optional jwx-backed JWS support in httpsign.

## Role in httpsign

jwx is used only for **optional “foreign” JWS** signing and verification (`NewJWSSigner` / `NewJWSVerifier` on jwx v2, and `NewJWSSignerV3` / `NewJWSVerifierV3` on jwx v3). **Native** algorithms (HMAC-SHA256, RSA, RSASSA-PSS, P-256/P-384, Ed25519) do **not** use jwx.

Today `go.mod` pulls both `github.com/lestrrat-go/jwx/v2` and `.../jwx/v3`. `crypto.go` dispatches on the embedded foreign signer/verifier interfaces (v2 vs v3 parameter order differs).

## Current policy (until Go 1.27)

- Stay on the dual v2+v3 paths.
- Bump **within `jwx/v3`** (patch/minor) if needed for fixes.
- Do **not** adopt jwx v4 on Go 1.24 / 1.26 + `GOEXPERIMENT=jsonv2`.
- Do **not** deprecate only the v2 constructors (“use V3”) — that would send callers to V3 and then remove V3 in the next major.

## Decision: all-in on jwx v4 after Go 1.27 stable

**Agreed (2026-07):** once **Go 1.27.0** (stable, not RC) is out, cut over httpsign to **`github.com/lestrrat-go/jwx/v4` only** (pin **v4.2.0+**) as an **httpsign major**.

### Why wait for 1.27

- **Go 1.26:** `encoding/json/v2` still needs `GOEXPERIMENT=jsonv2`; jwx v4 would force that on every httpsign build.
- **Go 1.27:** `encoding/json/v2` / `jsontext` are stdlib packages; `encoding/json` is backed by v2. Opt-out is `GOEXPERIMENT=nojsonv2` (temporary). See [go1.27 notes](https://go.dev/doc/go1.27), [golang/go#71497](https://github.com/golang/go/issues/71497), [golang/go#76406](https://github.com/golang/go/issues/76406).
- jwx **v4.2.0** (2026-07-24) is mature enough; the gate is the Go toolchain, not jwx.

### Trigger to implement

1. Go **1.27.0** available on `go.dev/dl`.
2. Confirm `go get github.com/lestrrat-go/jwx/v4@v4.2.0` (or newer) builds **without** `GOEXPERIMENT=jsonv2` under Go 1.27.
3. Ship the cutover as an httpsign **major**.

### What the cutover does

- Drop `jwx/v2` and `jwx/v3` from `go.mod`.
- Single constructor pair on v4 types (preferred names: `NewJWSSigner` / `NewJWSVerifier`; remove `*V3`).
- Update CI / `go` directive to **1.27.0+**.
- Follow upstream [MIGRATION.md](https://github.com/lestrrat-go/jwx/blob/v4.2.0/MIGRATION.md) and optionally [jwxmigrate](https://github.com/jwx-go/jwxmigrate).
- Re-run foreign-JWS tests; note v4 behavioral tightenings in [Changes-v4.md](https://github.com/lestrrat-go/jwx/blob/v4.2.0/Changes-v4.md).

### Deprecation / messaging

- **No** mid-stream v2→V3-only deprecation.
- Either remove v2 and `*V3` together in the major with a short migration note, **or** add `// Deprecated:` on **both** only when announcing that major (pointing at the new v4-backed constructors) — never “prefer V3” as a stable end state.

### Customer impact (v3 → v4)

Typical callers of `NewJWSSignerV3` / `NewJWSVerifierV3` only pass a `jwa` algorithm, a key, and httpsign config/fields. Expected change:

1. Go **1.27+**
2. httpsign **major**
3. Import `jwx/v3/jwa` → `jwx/v4/jwa`
4. Rename `NewJWS*V3` → `NewJWS*` (if we collapse names)

No change to key types or httpsign signing/verify config. **Native-algorithm users** are unaffected aside from the Go version floor. Exotic jwx features (ES256K companions, custom jwx signers, JWKS fetch) are out of scope for most httpsign users.

### Toolchain after cutover

| Item | Requirement |
|------|-------------|
| Go | **1.27.0+** in `go.mod` / CI |
| `GOEXPERIMENT=jsonv2` | Not required on Go 1.27+ |
| `GOEXPERIMENT=nojsonv2` | Avoid in CI |

---

## Implementation checklist (when Go 1.27 is out)

Scoped to httpsign’s use of **jwa** + **jws** only (no JWT/JWE/JWK fetch in library glue). Full upstream detail: [MIGRATION.md](https://github.com/lestrrat-go/jwx/blob/v4.2.0/MIGRATION.md).

### Code / deps

- [ ] `go.mod`: Go 1.27.0+; require `github.com/lestrrat-go/jwx/v4` (≥ v4.2.0); remove v2 and v3.
- [ ] Rewrite imports `jwx/v2|v3` → `jwx/v4`; collapse constructors; update `sign()` / `verify()` dispatch for v4 `jws.Signer` / `jws.Verifier` (ex-`Signer2` / `Verifier2`).
- [ ] Confirm factory APIs (`SignerFor` / `VerifierFor` or v4 equivalents) and `NoSignature` rejection still work.
- [ ] Run `jwxmigrate` if helpful; fix remaining compile/test failures by hand.
- [ ] CI: Go 1.27; do not set `jsonv2` / `nojsonv2` experiments.
- [ ] Release notes: httpsign major; document caller steps above; link upstream Changes-v4 if relevant.

### Upstream items likely N/A or low priority

| Topic | httpsign |
|-------|----------|
| JWK `Import` generics, `ParseFS`, custom field registration | Unlikely / N/A |
| HTTP JWKS → `jwkfetch` | N/A in core; document if examples ever use `jku` |
| ES256K / Ed448 / asmbase64 companions | Only if we expose or test those algs |
| Custom `Signer`/`Verifier` with `Algorithm()` | We embed upstream implementations only — re-check types after rename |
| Detached payload `io.Reader` | Orthogonal (we sign the RFC 9421 base string as `[]byte`) |
