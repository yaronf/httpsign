# jwx migration summary (maintainers)

Short form of [JWX_V3_MIGRATION_PLAN.md](./JWX_V3_MIGRATION_PLAN.md) plus agreed direction for later **jwx v4**.

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

- Re-run cross-peer tests after upgrade; v4 tightens some JWS behavior (e.g. `crit`, base64 strictness, `kid` consistency on sign) per upstream **Changes-v4.md**.

## Doc map

| Document | Use |
|----------|-----|
| [JWX_V3_MIGRATION_PLAN.md](./JWX_V3_MIGRATION_PLAN.md) | Full v2→v3 plan, phases, tests, timelines. |
| [JWX_V3_IMPLEMENTATION_SUMMARY.md](./JWX_V3_IMPLEMENTATION_SUMMARY.md) | What was implemented. |
| [JWX_V3_RESEARCH_FINDINGS.md](./JWX_V3_RESEARCH_FINDINGS.md) | Research notes. |
| **This file** | One-page summary + v4 direction. |
