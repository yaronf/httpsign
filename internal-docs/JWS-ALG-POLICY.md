# Plan: Foreign JWS algorithm policy (httpsign 0.6.x)

Status: implemented (on branch; target **v0.6.1**)  
Scope: **jwx / foreign-JWS API only** — no changes to native signers/verifiers, HTTP `SetAllowedAlgs` / `applyPolicyAlgs`, or generic verify/handler behavior except where a foreign `Verifier` is in use.  
Release target: **v0.6.1** (`v0.6.0` already shipped the jwx v4 / ML-DSA cutover). Breaking foreign-JWS verify API is acceptable.

Related discussion: on-demand key lookup (no in-library key set); JWK sugar; allowlist of JWS algs separate from HTTP Message Signatures `alg`.

---



## Goals

1. Split foreign verify into **exactly two** constructors; **both** take a JWS allowlist — library enforces policy.
2. Keep **keys on-demand** in the app (`fetchVerifier` / store lookup) — the library must not collect keys into a registry.
3. **Preferred API** is alg inference: `NewJWSVerifier(allowed, key, …)` on a finite key-type list (incl. `jwk.Key`). Escape hatch: `NewJWSVerifierWithAlg(allowed, alg, key, …)`. **Document** the inference table; migrate docs/examples to the preferred form.
4. Avoid algorithm confusion: never “try multiple JWS algs until verify succeeds.”
5. Do **not** overload `VerifyConfig.SetAllowedAlgs` (that remains HTTP `Signature-Input` `alg` only).
6. **Hardened known algs + passthrough:** keep `validateJWSKeyAlg` for HS/RS/PS/ES/EdDSA/ML-DSA; other/new `jwa` values passthrough to jwx. No closed “supported crypto” matrix — but **do** document the extraction table.

---



## Non-goals

- Changing native `NewHMACSHA256Verifier`, RSA/PSS/P-256/P-384/Ed25519 constructors.
- Changing semantics of `SetAllowedAlgs` / `applyPolicyAlgs`.
- Preloaded `JWSVerifierSet` / kid→key maps inside httpsign.
- Inferring alg from raw RSA or HMAC key bytes alone.
- HTTP JWKS fetch / `jku` in core.
- Silently rejecting HTTP `Signature-Input` `alg` on foreign verify (needs a config flag if done later).
- Documenting a closed httpsign-supported set of foreign JWS **crypto** algorithms (hardening/extraction tables ≠ interop claim).

---



## Proposed API



### 1. Allowlist type (jwx-only)

```go
// JWSAlgAllowlist is a non-empty set of permitted jwa signature algorithms.
type JWSAlgAllowlist struct { /* unexported set */ }

func NewJWSAlgAllowlist(algs ...jwa.SignatureAlgorithm) (*JWSAlgAllowlist, error)
func (a *JWSAlgAllowlist) Contains(alg jwa.SignatureAlgorithm) bool
```

- Reject empty allowlist, unregistered algs (`LookupSignatureAlgorithm`), and `jwa.NoSignature()` at construction (canonical registry names only).
- Do **not** filter allowlist membership to “algs we harden.” Any non-`none` `jwa` value may appear; unknown algs still work if jwx + key accept them.
- **`nil` allowlist:** constructors accept `allowed == nil` as “no alg policy” (lazy / tests / pinned single-key demos). Non-nil empty set is not representable via `NewJWSAlgAllowlist` (construction rejects empty). Docs: prefer a real allowlist whenever `keyid` (or similar) can select among keys. 



### 2. Two verify constructors only (both take allowlist)

**Naming:** the short name is the path we want callers on. Infer alg from key material by default; explicit alg is the longer escape hatch.

**Threat model:** the key **store** may be trusted, but an untrusted signed message can still steer the receiver (e.g. via `keyid`) toward a store entry whose alg is outside app policy. So production callers should pass a non-nil allowlist even when the store also returns an alg.

| Path | API | Role |
| ---- | --- | ---- |
| **Preferred** — infer alg | `NewJWSVerifier(allowed, key, …)` | Extract alg from key; allowlist; construct |
| Escape — alg known | `NewJWSVerifierWithAlg(allowed, alg, key, …)` | When inference is impossible (raw RSA/HMAC) or store already chose alg |

```go
// Preferred (breaking rename of today’s arity: alg moves to inference or WithAlg).
NewJWSVerifier(allowed *JWSAlgAllowlist, key any, config *VerifyConfig, fields Fields) (*Verifier, error)

// Escape hatch (today’s NewJWSVerifier(alg, key, …) migrates here + allowlist).
NewJWSVerifierWithAlg(allowed *JWSAlgAllowlist, alg jwa.SignatureAlgorithm, key any, config *VerifyConfig, fields Fields) (*Verifier, error)

NewJWSSigner(alg jwa.SignatureAlgorithm, key any, config *SignConfig, fields Fields) (*Signer, error) // no allowlist (outbound)
NewJWSSignerFromJWK(key jwk.Key, config *SignConfig, fields Fields) (*Signer, error)                 // infer from private JWK
```

**Migration:** `NewJWSVerifier(alg, key, cfg, fields)` → `NewJWSVerifierWithAlg(allowed, alg, key, cfg, fields)`, or preferably `NewJWSVerifier(allowed, key, …)` when the key type is inferrable.

**`NewJWSVerifier` (infer):**

1. Type-switch on **finite documented list** (see §4); extract alg.
2. If `allowed != nil` and `alg ∉ allowed` → error. If `allowed == nil`, skip alg policy (lazy path).
3. Convert key as needed; call shared construct path (`validateJWSKeyAlg` → `jws.VerifierFor`).
4. Unknown type → error pointing at `NewJWSVerifierWithAlg`.

**`NewJWSVerifierWithAlg`:**

1. Same nil/allowlist rule on the provided `alg`.
2. Resolve alg via jwx registry (`LookupSignatureAlgorithm`); reject empty / unregistered / `none`. Nil key rejected.
3. Existing **`validateJWSKeyAlg`**; default “unsupported” → fall through to **`jws.VerifierFor(alg)`** (jwx).
4. Reject raw `jwk.Key` here — use preferred `NewJWSVerifier` (or convert).

**`NewJWSSigner`:** hardening + passthrough; **no** allowlist; force `SignAlg(false)`. Reject raw `jwk.Key` — use `NewJWSSignerFromJWK`.

**`NewJWSSignerFromJWK`:** require a **private** JWK (symmetric `oct` OK); resolve alg with the same table / EdDSA↔Ed25519 rules as verify; export raw **private** material; then `NewJWSSigner`.

Do **not** put the JWS allowlist on `VerifyConfig`.

**Honesty about crypto quality:** hardening ≠ interop. No closed “supported algorithms” docs matrix.

### 3. On-demand examples

**Preferred — key material only** (inferrable types; no raw RSA):

```go
allowed, _ := httpsign.NewJWSAlgAllowlist(jwa.ES256(), jwa.MLDSA65())

config.SetFetchVerifier(func(r *http.Request) (string, *httpsign.Verifier) {
    key := store.LookupKey(kid) // jwk.Key (with alg or EC/OKP crv), *ecdsa.PublicKey, or *mldsa.PublicKey
    v, err := httpsign.NewJWSVerifier(allowed, key, verifyCfg, fields)
    …
})
```

**Store returns alg + key** (use WithAlg — needed for raw RSA/HMAC; still allowlist — kid may steer which entry):

```go
allowed, _ := httpsign.NewJWSAlgAllowlist(jwa.ES256(), jwa.RS256(), jwa.MLDSA65())

config.SetFetchVerifier(func(r *http.Request) (string, *httpsign.Verifier) {
    alg, key := store.Lookup(kid)
    v, err := httpsign.NewJWSVerifierWithAlg(allowed, alg, key, verifyCfg, fields)
    …
})
```

### 4. Inference table for `NewJWSVerifier` (document this; lead docs here)

**Docs stance:** lead with `NewJWSVerifier(allowed, key, …)`. Pass a real allowlist when key selection is attacker-influenced; `nil` is allowed for lazy/simple cases. Use `WithAlg` only when inference cannot work.

**Finite `key` types** (anything else → error → use `WithAlg`):

| `key` type | How alg is chosen |
| ---------- | ----------------- |
| `jwk.Key` with `alg` | Use JWK `alg` |
| `jwk.Key` EC/OKP without `alg` | `crv` → ES256/384/512 or **EdDSAEd25519** (RFC 9864); legacy JWK `alg` `"EdDSA"` agrees with that mapping |
| `jwk.Key` RSA/`oct`/AKP without `alg` | Error (RSA/HMAC ambiguous; AKP requires `alg` per RFC 9964) |
| `*ecdsa.PublicKey` | Curve → ES256/384/512 |
| `*mldsa.PublicKey` | `Parameters()` → ML-DSA-44/65/87 |
| `*rsa.PublicKey`, `[]byte`, … | Error — `NewJWSVerifierWithAlg(allowed, alg, …)` or a JWK with `alg` |

If JWK has both `alg` and a structural mapping and they **disagree** → error. Legacy `"EdDSA"` and RFC 9864 `"Ed25519"` are **not** a disagreement (same Ed25519 crypto). `JWSAlgAllowlist.Contains` treats those two names as equivalent.

After JWK → raw key for ML-DSA: cross-check `Parameters()` vs claimed `alg`.

**Practical note:** RSA on the preferred path only via `jwk.Key` **with** `alg`. ECDSA and ML-DSA work from JWK or raw public key.

`JWSAlgAllowlist`: `NewJWSAlgAllowlist` / `Contains` only — no constructor methods on the type.

### 5. HTTP `alg` on foreign verify — **out of scope**

Do **not** newly reject `Signature-Input` `alg` for foreign verifiers in this work. That would be an arbitrary break without a config flag. If we want the stricter behavior later, ship it with an explicit `VerifyConfig` switch in the same change — not as a silent default.

(Foreign **sign** still forces `SignAlg(false)` so we stop *emitting* HTTP `alg` from JWS signers; that is separate and already in §2.)

---



## Open issues (track; do not forget)

Separate from this JWS-alg work, but open on the repo and easy to lose in the `v0.6.x` shuffle:

| Issue | Title | Notes |
| ----- | ----- | ----- |
| [#20](https://github.com/yaronf/httpsign/issues/20) | Add select-by-tag helpers for signature labels | WIMSE / `tag`-based selection; not foreign-JWS |
| [#21](https://github.com/yaronf/httpsign/issues/21) | Add convenience helper for associated-request derived components | `AddRequestComponent` for `;req`; not foreign-JWS |

Also parked **inside** this plan (not GitHub issues yet):

- **§5** — optional reject of HTTP `Signature-Input` `alg` on foreign verify: only with an explicit config flag, same change; otherwise leave alone.

---



## Exact breaking changes


| Change                                                                                   | Who breaks                                                              | Migration                                                                                          |
| ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `NewJWSVerifier` becomes infer-alg `(allowed, key, …)`; old form → `WithAlg`             | Every foreign verify call site                                          | Prefer `NewJWSVerifier(allowed, key, …)`; else `NewJWSVerifierWithAlg(allowed, alg, key, …)`      |
| `NewJWSSigner` rejects configs that would sign HTTP `alg` / defaults to `SignAlg(false)` | Callers who passed `SignAlg(true)` or relied on default `true` with JWS | Pass `SignAlg(false)` or omit and use new default                                                  |
| Default case of `validateJWSKeyAlg` becomes passthrough                                  | Callers who relied on “unsupported alg” errors for unknown jwa          | Rare; unknown algs now reach jwx                                                                   |


**Not broken:**

- `NewJWSSigner` arity (no allowlist)  
- Native constructors; `SetAllowedAlgs`; `fetchVerifier` shape; `Verifier`/`Signer` types  

**Additive:** `JWSAlgAllowlist`, `NewJWSVerifierWithAlg`.

---



## Implementation sketch


| Area                        | Work                                                                                          |
| --------------------------- | --------------------------------------------------------------------------------------------- |
| `crypto.go`                 | `NewJWSVerifier` = infer; `NewJWSVerifierWithAlg`; force `SignAlg(false)` on JWS sign |
| `jwskey.go`                 | Keep hardening; default → passthrough to jwx                                          |
| `jwsallow.go` / `jwsjwk.go` | Allowlist; inference type-switch (JWK + ECDSA + ML-DSA)                               |
| Tests                       | Prefer-path + WithAlg; allowlist nil/deny; SignAlg enforcement                        |
| Docs                        | Lead with infer `NewJWSVerifier`; WithAlg as escape; kid-steering + inference table   |


Dependency: already on `jwx/v4`; may need `jwx/v4/jwk` import (acceptable in jwx space).

---



## Testing plan

1. Unit: nil allowlist accepts; non-nil deny; infer path + WithAlg.
2. Unit: JWK with/without `alg`; EC/OKP/`*ecdsa`/`*mldsa`; RSA/`oct`/AKP without `alg` → error; ML-DSA Parameters cross-check.
3. Round-trip: `NewJWSSigner` + preferred `NewJWSVerifier(allowed, key, …)` (classical + ML-DSA).
4. Integration: `SetFetchVerifier` + allowlist (kid would otherwise select disallowed alg → construct fails).
5. Regression: native `SetAllowedAlgs` tests unchanged.

---



## Doc / release notes bullets

- **Preferred:** `NewJWSVerifier(allowed, key, …)` (infer alg). **Escape:** `NewJWSVerifierWithAlg(allowed, alg, key, …)`. `allowed == nil` skips alg policy (lazy).  
- Store may be trusted; **key selection** (e.g. `keyid`) is not — use a non-nil allowlist in that case.  
- Finite infer types: `jwk.Key`, `*ecdsa.PublicKey`, `*mldsa.PublicKey`.  
- `SignAlg(false)` on foreign sign. No new HTTP `alg` reject on verify (§5).  
- Keys on-demand. `SetAllowedAlgs` remains HTTP-only.  
- Don’t forget [#20](https://github.com/yaronf/httpsign/issues/20), [#21](https://github.com/yaronf/httpsign/issues/21).

---



## Decision summary


| Topic             | Decision                                                                 |
| ----------------- | ------------------------------------------------------------------------ |
| Key storage       | On-demand in app only                                                    |
| Verify APIs       | **Preferred** `NewJWSVerifier(allowed, key)` infer; escape `WithAlg`     |
| Threat model      | Store trusted; **selection** (kid) not — always policy-check alg         |
| HTTP alg on verify | **Skip** — no silent reject; flag+behavior only as a later paired change |
| Dropped           | No `FromKey` / `FromJWK` names — short name *is* infer                   |
| Allowlist         | Both verify constructors; `nil` = no policy (lazy); non-nil enforces     |
| Infer types       | Finite: `jwk.Key`, `*ecdsa.PublicKey`, `*mldsa.PublicKey`                |
| Sign              | No allowlist                                                             |
| Hardening         | Keep `validateJWSKeyAlg`; unknown alg → jwx passthrough                  |
| Docs              | Lead with infer path; document table + kid-steering                      |
| Multi-alg verify  | No try-all                                                               |
| Outside jwx       | Unchanged                                                                |
| Don't forget      | [#20](https://github.com/yaronf/httpsign/issues/20), [#21](https://github.com/yaronf/httpsign/issues/21); §5 only with config flag |


