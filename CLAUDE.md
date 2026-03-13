# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build ./...

# Test all
go test ./...

# Run a single test
go test -run TestFunctionName ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...

# Fuzz testing
go test -fuzz=FuzzXxx -fuzztime=30s ./...
```

No Makefile — standard Go tooling only. Linting is not configured in CI; use `go vet ./...` locally.

## Architecture

This is a **single-package library** (`github.com/yaronf/httpsign`) implementing **RFC 9421** (HTTP Message Signatures). All code lives in the root package with no sub-packages.

### Layer model

```
client.go / handler.go     ← High-level HTTP integration (wrap http.Client / http.Handler)
    │
signatures.go              ← Mid-level API: SignRequest, SignResponse, VerifyRequest, VerifyResponse
    │
message.go / httpparse.go  ← RFC 9421 message canonicalization and signature base string construction
    │
crypto.go / ecdsa.go       ← Signer / Verifier types and algorithm implementations
    │
fields.go / digest.go      ← Component field abstraction + Content-Digest header support
```

### Key types

- **`Signer` / `Verifier`** (`crypto.go`) — hold algorithm, key, and signing config. Created via `NewXxxSigner` / `NewXxxVerifier` constructors (HMAC-SHA256, RSA, RSA-PSS, P-256, P-384, Ed25519, JWS).
- **`SignConfig` / `VerifyConfig`** (`config.go`) — builder-style configuration for signature metadata (keyID, nonce, tag, expiry, clock tolerance). Constructed via `NewSignConfig()` / `NewVerifyConfig()` with method chaining.
- **`Fields`** (`fields.go`) — specifies which HTTP components (headers, derived components) to include in the signature. Use the `Fields("header1", "@method", ...)` helper or `NewFields()` for complex cases.
- **`Message` / `MessageDetails`** (`message.go`) — internal canonicalized request/response representation. `MessageDetails` is the public output of `RequestDetails` / `ResponseDetails`.
- **`HandlerConfig` / `ClientConfig`** (`config.go`) — configures server-side and client-side HTTP wrappers.

### JWX dual-version support

The library supports both `lestrrat-go/jwx/v2` (kept for backward compatibility) and `lestrrat-go/jwx/v3` (recommended for new code). Use `NewJWSSignerV3` / `NewJWSVerifierV3` for new integrations.

### Content-Digest

`digest.go` provides `GenerateContentDigestHeader` and `ValidateContentDigestHeader`. When `@content-digest` is listed in `Fields`, the library automatically generates/validates the header. Supported schemes: `sha-256`, `sha-512`.

### Testing conventions

- `signatures_test.go` contains the full RFC 9421 test vector suite (134 KB) — do not modify without understanding the spec.
- `fuzz_test.go` has fuzz entry points; seed corpus lives in `testdata/fuzz/`.
- `http2_test.go` and `trailer_test.go` cover HTTP/2 and trailer-header edge cases.
- Tests use `github.com/stretchr/testify` assertions and `github.com/andreyvit/diff` for readable diffs.

## Known limitations (from README)

- `Accept-Signature` header is unimplemented.
- Response `Content-Type` is only signed when explicitly set on the response — this is intentional (more secure than net/http default behavior).
