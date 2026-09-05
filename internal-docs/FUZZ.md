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

Seed coverage (no mutation; `f.Add` + committed `testdata` only), rough mean of per-function statement % on the focus files:

| Profile | signatures | httpparse | fields | digest | message | package |
|---------|------------|-----------|--------|--------|---------|---------|
| `FuzzVerifyRequest` (pre-seed expand) | ~25% | ~66% | ~12% | ~11% | ~66% | 17.5% |
| `FuzzVerifyRequest` (after SFV seeds) | ~25% | ~66% | ~18% | ~11% | ~66% | 18.5% |
| `FuzzSignAndVerifyHMAC` (after digest-bearing seeds + `ValidateContentDigestHeader`) | ~44% | ~74% | ~40% | `ValidateContentDigestHeader` ~71%, `validateSchemes` ~80% | ~66% | 30.8% |

Gaps that seeds now push harder: truncated/malformed SFV, `;tr` / `;bs` / `;sf`, `@query-param`, `content-digest`, trailers, response + associated-request configs.

## Soak (2026-09-05, SFV-weighted ~8h fuzz-time)

Budgets: `FuzzVerifyRequest` 2h, `FuzzVerifyViaMessage` 2h, `FuzzNewMessage` 90m, `FuzzSignAndVerifyHMAC` 75m, `FuzzHMACViaMessage` 75m. Host sleep paused progress overnight; after sleep was disabled, remaining fuzz-time finished on schedule (~22:30 local).

| Target | Result | Execs | New interesting (total) |
|--------|--------|------:|-------------------------|
| `FuzzVerifyRequest` | PASS | 220M | 866 (1121) |
| `FuzzVerifyViaMessage` | PASS | 201M | 826 (1118) |
| `FuzzNewMessage` | PASS | 151M | 315 (612) |
| `FuzzSignAndVerifyHMAC` | PASS | 158M | 471 (676) |
| `FuzzHMACViaMessage` | PASS | 144M | 461 (629) |

**Crashes:** none.

Interesting-input growth continued through the long runs (especially verify / HMAC), with plateaus late in each budget — expected, not a signal to stop early on a short quiet window.

### Post-soak corpus coverage

`go test -fuzz` does not write a coverprofile while mutating. Coverage after a soak is measured by **replaying** the cached corpus:

1. Interesting inputs live under `$GOCACHE/fuzz/github.com/yaronf/httpsign/<Target>/` (not under `testdata/fuzz/` unless copied).
2. Stage those files into `testdata/fuzz/<Target>/` temporarily (hardlinks are fine).
3. `go test -run='^FuzzXxx$' -coverprofile=... .` then exercises the soak corpus as ordinary seeds.
4. Remove the staged files afterward; do **not** bulk-commit the cache dump.

2026-09-05 replay (cache entry counts ≈ soak “total interesting”), mean per-function % on focus files / package total:

| Target | Cache entries | signatures | httpparse | fields | digest | message | package |
|--------|--------------:|-----------:|----------:|-------:|-------:|--------:|--------:|
| `FuzzVerifyRequest` | ~1108 | 26.7% | 67.9% | 19.6% | 10.7% | 65.5% | 21.2% |
| `FuzzVerifyViaMessage` | ~1111 | 21.7% | 67.9% | 19.6% | 10.7% | 70.8% | 20.7% |
| `FuzzSignAndVerifyHMAC` | ~673 | 44.5% | 76.7% | 39.5% | 41.8% | 65.5% | 33.4% |
| `FuzzHMACViaMessage` | ~626 | 42.0% | 76.5% | 39.5% | 41.8% | 70.8% | 34.1% |
| `FuzzNewMessage` | ~604 | 23.5% | 74.7% | 21.3% | 0.0% | 76.5% | 22.2% |

Compared with seed-only baselines, package totals rose a few points (e.g. verify ~18.5%→21.2%, HMAC ~30.8%→33–34%). Most soak “interesting” finds refine edges already near existing coverage rather than opening large new statement regions — still valuable for crash hunting.

## Harness conventions

- **Panic-oriented** (`FuzzVerifyRequest`, `FuzzVerifyViaMessage`): discard expected verify/setup errors; return early on nil/`NewMessage` failure; never `t.Error` on bad signatures.
- **Round-trip** (HMAC targets): return early on nil request, signer/verifier setup failure, or `SignRequest` error; `t.Fatalf` only if verify fails after a successful sign.
- **FuzzNewMessage**: invalid configs return; structural invariants (headers present for request/response) may fail the input.

## CI

The `fuzz` job in `.github/workflows/test.yml` runs each target with `-run='^$' -fuzztime=15s` sequentially on Go 1.27. It fails on crash or failing corpus. This is a **smoke**, not a long soak.

For occasional long soaks (hours), use the weighted budgets in the soak section above; keep the machine from sleeping so wall clock ≈ fuzz-time. Optional follow-on: a scheduled nightly job with a larger `-fuzztime`.

## Checklist (after library changes that touch parse/sign/verify)

1. `go test -list 'Fuzz' .` — five names, no substring collisions.
2. `go test -run='^Fuzz' .` — seeds pass.
3. Optional: 30s fuzz on the targets you touched.
4. If you add corpus files, re-check seed cover on the focus files.
