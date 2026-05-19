# jwx migration summary (maintainers)

Short form of [JWX_V3_MIGRATION_PLAN.md](./JWX_V3_MIGRATION_PLAN.md), agreed direction for later **jwx v4**, and a **checklist aligned to upstream [MIGRATION.md](https://github.com/lestrrat-go/jwx/blob/v4.0.0/MIGRATION.md)** (v4.0.0 tag).

## Role of jwx in httpsign

jwx is used only for **optional “foreign” JWS** signing and verification (`NewJWS*` / `NewJWS*V3`). **Native** algorithms (HMAC-SHA256, RSA, RSASSA-PSS, P-256/P-384, Ed25519) do **not** use jwx.

## What we did: v2 → v3 (backward compatible)

| Item | Choice |
|------|--------|
| **Strategy** | Keep v2 APIs; add parallel **`NewJWSSignerV3` / `NewJWSVerifierV3`** using `jwx/v3`. |
| **Breaking change** | No — existing `NewJWSSigner` / `NewJWSVerifier` (v2) unchanged. |
| **Implementation** | `crypto.go` dispatches v2 `jws.Signer` / `Verifier` vs v3 `Signer2` / `Verifier2` (different `Sign` / `Verify` parameter order). |
| **Trade-off** | Two dependencies and two code paths until a future cleanup release. |

See [JWX_V3_IMPLEMENTATION_SUMMARY.md](./JWX_V3_IMPLEMENTATION_SUMMARY.md) for what landed in the tree.

## Near-term maintenance

- Prefer **bumping within `jwx/v3`** (e.g. patch/minor) for fixes without adopting v4.
- **`jwx/v3` remains tagged** alongside v4 (e.g. v3.1.0 shipped with v4.0.0); there is **no** published EOL date for v3 — treat **v4** as the long-term main line when we are ready.

## Future: v4 (not scheduled — prerequisites first)

**When:** No fixed date. Reasonable approach: wait until **v4 has had some `v4.0.x` releases** and upstream issue volume is acceptable; **do not** treat **`v4.1.0`** as a special “stability gate” (semver minor is not “safer” than patch for this).

**What “all-in v4” would mean for httpsign**

- Drop **`jwx/v2` and `jwx/v3`**; depend only on **`github.com/lestrrat-go/jwx/v4`** for JWS helpers.
- **Major version** of httpsign and a **migration note** for callers (types and imports change).
- Follow upstream **[MIGRATION.md](https://github.com/lestrrat-go/jwx/blob/v4.0.0/MIGRATION.md)** and optional **[jwxmigrate](https://github.com/jwx-go/jwxmigrate)** for mechanical rewrites.

**Toolchain (required for jwx v4 — cannot be avoided in app code)**

- **Go 1.26+** (as declared by the v4 module).
- **`GOEXPERIMENT=jsonv2`** — jwx v4 uses **`encoding/json/v2`**; the flag applies to the **whole build** that compiles jwx, not something callers can “opt out of” locally.
- There is **no** announced calendar or Go version for **ending** the `jsonv2` experiment; watch [golang/go#71497](https://github.com/golang/go/issues/71497) and Go release notes.

**Interop / testing**

- Re-run cross-peer tests after upgrade; v4 tightens some JWS behavior (e.g. `crit`, base64 strictness, `kid` consistency on sign) per upstream **[Changes-v4.md](https://github.com/lestrrat-go/jwx/blob/v4.0.0/Changes-v4.md)** (full breaking list) alongside **[MIGRATION.md](https://github.com/lestrrat-go/jwx/blob/v4.0.0/MIGRATION.md)** (recipes and manual-review patterns).

---

## v4 upstream docs checklist (from MIGRATION.md)

The following mirrors **[MIGRATION.md](https://github.com/lestrrat-go/jwx/blob/v4.0.0/MIGRATION.md)** (tag **v4.0.0**). Use it when executing an httpsign → jwx v4 migration; **“httpsign scope”** reflects current code paths (`crypto.go` / tests: **jwa** + **jws** only, no JWT/JWE/JWK fetch in library glue).

### Prerequisites (MIGRATION.md § Prerequisites)

| Item | Notes |
|------|--------|
| Go **1.26.0+** | Required by v4 module. |
| **`GOEXPERIMENT=jsonv2`** | Required for builds that compile jwx v4. |
| `go.mod` → **`github.com/lestrrat-go/jwx/v4`** | Pin desired **v4.x.x** after stabilization pass. |
| Run **`jwxmigrate`** | `go install github.com/jwx-go/jwxmigrate@latest` then `jwxmigrate --fix ./...` then `jwxmigrate ./...` per upstream workflow. |

### Quick Reference table (MIGRATION.md § Quick Reference)

Skim the full **v3 → v4** mapping table in MIGRATION.md for any symbol you import. For httpsign, the rows most likely to matter first are:

- **`.../jwx/v3/...` → `.../jwx/v4/...`** (all packages you touch).
- **`jws.Signer2` / `jws.Verifier2` → `jws.Signer` / `jws.Verifier`** (interface renames; our `crypto.go` type-assertions must follow v4 types).
- **`jws.RegisterSigner` / `RegisterVerifier`** — typed **`Signer`** / **`Verifier`** parameters only.
- **`jws.WithVerifyAuto(f, fetchOpts...)` → `jws.WithVerifyAuto(f)`** — not used in httpsign today; relevant if callers ever combine jwx high-level verify with **jku** (see Recipe 6 / manual review #3).
- **`jwx.DecoderSettings(...)` → `jwx.Settings(...)`** — if we ever set decoder options.
- **Removed build tags** `jwx_goccy`, `jwx_es256k`, `jwx_asmbase64` — replace with companion modules (**§ Build System Changes**).

### Migration Recipes (MIGRATION.md § Migration Recipes)

| Recipe | § in MIGRATION.md | httpsign scope | Action |
|--------|-------------------|----------------|--------|
| **1** | Update import paths | **Yes** | `v2`/`v3` → `v4` for `jwa`, `jws`; drop old majors when going all-in. |
| **2** | Field access `Get` → `Get[T]` / `Field` | **Unlikely** | Grep for `.Get(` on jwx types in this repo; fix if any. |
| **3** | JWK `Import` generics | **Unlikely** | Only if tests or helpers import raw keys via `jwk`. |
| **4** | `ReadFile` → `ParseFS` | **Low** | Only if tests read JWT/JWK/JWS from disk; prefer `ParseFS` for new code. |
| **5** | Custom `Signer`/`Verifier` (no `Algorithm()` on signer) | **Review** | We embed **upstream jws signer/verifier** implementations from factory APIs (v3: **`SignerFor` / `VerifierFor`**); confirm v4 equivalents, method signatures, and **`sign()` / `verify()`** dispatch still match. |
| **6** | HTTP JWKS (`jwk.Fetch`, `Cache`, whitelist) → **`jwkfetch`** | **N/A** (library glue) | Document for **consumers** if we ever add examples that verify via **jku**. |
| **7** | Custom field registration (generic `Register*`) | **N/A** | — |
| **8** | JWK probe fields (`RegisterProbeField`) | **N/A** | — |
| **9** | ES256K / Ed448 / asm base64 | **Conditional** | Add **`github.com/jwx-go/es256k/v4`**, **`ed448/v4`**, **`asmbase64/v4`** only if we expose or test those algorithms. |
| **10** | Custom key importer | **N/A** | — |
| **11** | Iterating sets / token claims | **N/A** | — |
| **12** | JWE package | **N/A** | — |
| **13** | JWT validation errors (`errors.Is` → struct sentinels) | **N/A** | — |

### Patterns requiring manual review (MIGRATION.md § Patterns Requiring Manual Review)

| # | Topic | httpsign |
|---|--------|----------|
| 1 | Custom **`Signer2`/`Verifier2`** with **`Algorithm()`** | We do not ship custom jwx signers; **re-check** after v4 API rename that we only hold upstream-implemented **`Signer`** / **`Verifier`**. |
| 2 | Complex **`jwk.Cache`** / httprc options | **N/A** today. |
| 3 | **`jws.WithVerifyAuto` / `jwt.WithVerifyAuto`** and **jku** whitelist semantics | **N/A** in `httpsign` core; **critical** if any example or future API wires auto-JWKS without **`jwkfetch.WithWhitelist`**. |
| 4 | **`json.Number`** / **`jwx.WithUseNumber`** | **Verify** if we set global jwx settings anywhere. |
| 5 | Matching **error strings** from crypto/signing | **Review tests**; errors may surface earlier (e.g. at **`WithKey`** validation). |
| 6 | **`Settings()` returns `error`** | **Grep** `jws.Settings`, `jwx.Settings`, `jwt.Settings`, `jwk.Settings`, `jwe.Settings` and handle errors. |
| 7 | **`jws.HeaderFilter`** / **`transform`** / **`jwt.TokenFilter`** | **N/A** unless new code adds filters. |

### Build system changes (MIGRATION.md § Build System Changes)

- Bump **`go`** directive to **1.26.0** (or newer patch) in **`go.mod`**.
- Ensure **CI and local builds** export **`GOEXPERIMENT=jsonv2`** (or equivalent in CI env).
- Remove obsolete **`-tags=jwx_*`** from scripts; add **companion** modules if ES256K / asm base64 needed.

### Optional follow-ups (MIGRATION.md § New Capabilities Worth Adopting)

- **Detached payload via `io.Reader`** (`jws.WithDetachedPayloadReader`) — useful for large bodies; **orthogonal** to current httpsign design (we sign/verify a **byte slice** from the RFC 9421 base string). Revisit only if product requirements change.

---

## Doc map

| Document | Use |
|----------|-----|
| [JWX_V3_MIGRATION_PLAN.md](./JWX_V3_MIGRATION_PLAN.md) | Full v2→v3 plan, phases, tests, timelines. |
| [JWX_V3_IMPLEMENTATION_SUMMARY.md](./JWX_V3_IMPLEMENTATION_SUMMARY.md) | What was implemented. |
| [JWX_V3_RESEARCH_FINDINGS.md](./JWX_V3_RESEARCH_FINDINGS.md) | Research notes. |
| **This file** | Summary, v4 direction, and **MIGRATION.md-aligned checklist** (recipes, manual review, build). |
