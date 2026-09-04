# Fuzz testing playbook

Maintainer notes for the Go native fuzz suite in [`fuzz_test.go`](../fuzz_test.go).

## Targets

Names must not be substrings of each other: `go test -fuzz=` is a **regexp** and must match exactly one function.

| Target | Role |
|--------|------|
| `FuzzVerifyRequest` | Panic-oriented verify of mutated `Signature-Input` / `Signature` via `VerifyRequest` |
| `FuzzVerifyViaMessage` | Same inputs through `NewMessage` + `Message.Verify` |
| `FuzzSignAndVerifyHMAC` | HMAC sign → verify round-trip; fails only if verify fails after a successful sign |
| `FuzzHMACViaMessage` | Same round-trip with `Message.Verify` |
| `FuzzNewMessage` | `MessageConfig` / `NewMessage` (request, response, associated request, trailers) |

Message twins are **kept on purpose**: they exercise Message construction and header maps as a separate panic surface from the `net/http` helpers.

Foreign JWS / ML-DSA is **out of scope** for this suite (separate crypto surface; less likely to find interesting bugs than SFV / Signature-Input parsing). Note as a follow-on if needed.

## Local commands

Seed-only (no mutation), useful for coverage:

```bash
go test -run=FuzzVerifyRequest -coverprofile=cov-verify.out .
go test -run=FuzzSignAndVerifyHMAC -coverprofile=cov-hmac.out .
go tool cover -func=cov-verify.out
go tool cover -func=cov-hmac.out
```

Mutating fuzz (fixed budget):

```bash
go test -run='^$' -fuzz=FuzzVerifyRequest -fuzztime=30s .
go test -run='^$' -fuzz=FuzzVerifyViaMessage -fuzztime=30s .
go test -run='^$' -fuzz=FuzzSignAndVerifyHMAC -fuzztime=30s .
go test -run='^$' -fuzz=FuzzHMACViaMessage -fuzztime=30s .
go test -run='^$' -fuzz=FuzzNewMessage -fuzztime=30s .
```

CI uses a shorter per-target budget (`-fuzztime=15s`); see `.github/workflows/test.yml`.

## Interpreting metrics

From each fuzz run, note:

- **execs/sec** — throughput (machine-dependent).
- **new interesting / total** — corpus growth. Steady growth early is healthy; a long plateau with high execs/sec usually means the harness is stable, not that coverage is complete.
- **crash / FAIL** — treat as a bug (or a harness false positive: asserts on expected errors).

### Coverage focus

Interpret coverprofiles primarily on the surface the fuzz inputs hit:

- `signatures.go`, `httpparse.go`, `fields.go`, `digest.go`
- `message.go` for Message targets

Package-wide `%` is optional secondary context only. It is diluted by client/handler wrappers, algorithm constructors, RFC vector tests, and JWS glue that these harnesses do not aim to exercise.

## Corpus layout

- Committed seeds: `f.Add(...)` in `fuzz_test.go`, plus optional files under `testdata/fuzz/<Target>/`.
- Go’s fuzz cache (interesting inputs found while fuzzing) lives under the module cache / `$GOCACHE`; it is **not** the same as `testdata/fuzz/`.
- Prefer committing **minimized** corpus files that improve seed coverage on the SFV / parse / digest surface. Do not bulk-commit huge cache dumps.
- `.gitignore` ignores local `testdata/fuzz/FuzzSignAndVerifyHMAC/` noise; keep intentional seeds for other targets tracked.

## Baseline (2026-09-04, ~30s each, 8 workers)

| Target | Execs (~30s) | New interesting (total) | Crash |
|--------|--------------|-------------------------|-------|
| `FuzzVerifyRequest` | ~723k | 207 (212) | no |
| `FuzzVerifyViaMessage` | ~880k | 239 (243) | no |
| `FuzzSignAndVerifyHMAC` | ~1.0M | 193 (194) | no |
| `FuzzHMACViaMessage` | ~1.0M | 149 (150) | no |
| `FuzzNewMessage` | ~664k | 280 (286) | no |

Seed coverage (no mutation), rough mean of per-function statement % on the focus files:

| Profile | signatures | httpparse | fields | digest | message | package |
|---------|------------|-----------|--------|--------|---------|---------|
| `FuzzVerifyRequest` (pre-seed expand) | ~25% | ~66% | ~12% | ~11% | ~66% | 17.5% |
| `FuzzVerifyRequest` (after SFV seeds) | ~25% | ~66% | ~18% | ~11% | ~66% | 18.5% |
| `FuzzSignAndVerifyHMAC` (after digest-bearing seeds + `ValidateContentDigestHeader`) | ~44% | ~74% | ~40% | `ValidateContentDigestHeader` ~71%, `validateSchemes` ~80% | ~66% | 30.8% |

Gaps that seeds now push harder: truncated/malformed SFV, `;tr` / `;bs` / `;sf`, `@query-param`, `content-digest`, trailers, response + associated-request configs.

## Harness conventions

- **Panic-oriented** (`FuzzVerifyRequest`, `FuzzVerifyViaMessage`): discard expected verify/setup errors; return early on nil/`NewMessage` failure; never `t.Error` on bad signatures.
- **Round-trip** (HMAC targets): return early on nil request, signer/verifier setup failure, or `SignRequest` error; `t.Fatalf` only if verify fails after a successful sign.
- **FuzzNewMessage**: invalid configs return; structural invariants (headers present for request/response) may fail the input.

## CI

The `fuzz` job in `.github/workflows/test.yml` runs each target with `-run='^$' -fuzztime=15s` sequentially on Go 1.27. It fails on crash or failing corpus. This is a **smoke**, not a long soak; longer nightly budgets can be added later.

## Checklist (after library changes that touch parse/sign/verify)

1. `go test -list 'Fuzz' .` — five names, no substring collisions.
2. `go test -run='^Fuzz' .` — seeds pass.
3. Optional: 30s fuzz on the targets you touched.
4. If you add corpus files, re-check seed cover on the focus files.
