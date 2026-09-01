A Golang implementation of HTTP Message Signatures, as defined by
[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)
(the former [draft-ietf-httpbis-message-signatures](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures)).

This is a nearly feature-complete implementation of the RFC, including all test vectors.

### Usage

The library provides natural integration points with Go HTTP clients and servers, as well as direct usage of the
_sign_ and _verify_ functions.

Below is what a basic client-side integration looks like. Additional examples are available
in the [API reference](https://pkg.go.dev/github.com/yaronf/httpsign).

```cgo
	// Create a signer and a wrapped HTTP client
	signer, _ := httpsign.NewRSAPSSSigner(*prvKey, httpsign.NewSignConfig(),
		httpsign.Headers("@request-target", "content-digest")) // The Content-Digest header will be auto-generated
	client := httpsign.NewDefaultClient(httpsign.NewClientConfig().SetSignatureName("sig1").SetSigner(signer)) // sign requests, don't verify responses

	// Send an HTTP POST, get response -- signing happens behind the scenes
	body := `{"hello": "world"}`
	res, _ := client.Post(ts.URL, "application/json", bufio.NewReader(strings.NewReader(body)))
	
	// Read the response
	serverText, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
```

### Upgrading from v0.5.x

**v0.6.0** is a breaking release for foreign-JWS users and raises the Go floor to **1.27+**.

| Caller | Change |
|--------|--------|
| Native algorithms only (RSA, ECDSA, Ed25519, HMAC) | Upgrade Go to 1.27+; no API changes. |
| `NewJWSSignerV3` / `NewJWSVerifierV3` | Use `NewJWSSigner` / `NewJWSVerifier` with `github.com/lestrrat-go/jwx/v4/jwa`. |
| `NewJWSSigner` / `NewJWSVerifier` (jwx v2) | Same: v4 import path; algorithms are functions (`jwa.ES256()`, not string constants). |

Foreign JWS signing must use `SignConfig.SignAlg(false)` — RFC 9421 does not define an HTTP `alg` value for arbitrary JWS algorithms. Verification policy `SetAllowedAlgs` applies to the optional HTTP `alg` signature parameter in the message, not to the JWS algorithm passed to `NewJWSVerifier`.

Full migration notes: [internal-docs/RELEASE-v0.6.0.md](internal-docs/RELEASE-v0.6.0.md) (maintainers: paste **Summary** into the GitHub release).

### Foreign JWS and ML-DSA

Optional algorithms beyond the native set use [`lestrrat-go/jwx/v4`](https://github.com/lestrrat-go/jwx) (≥ v4.4.0) via `NewJWSSigner` / `NewJWSVerifier`. Requires **Go 1.27+** (stdlib `encoding/json/v2`; no `GOEXPERIMENT`).

**ML-DSA (FIPS 204)** is supported through the same constructors with `crypto/mldsa` keys and `jwa.MLDSA44()` / `MLDSA65()` / `MLDSA87()`. RFC 9421 does not assign HTTP Message Signatures algorithm identifiers for ML-DSA; treat it like other foreign JWS algorithms (`SignAlg(false)`, JWS `alg` in the JWS layer only if your profile requires it).

```go
priv, _ := mldsa.GenerateKey(mldsa.MLDSA65())
pub := priv.Public().(*mldsa.PublicKey)
signer, _ := httpsign.NewJWSSigner(jwa.MLDSA65(), priv,
    httpsign.NewSignConfig().SignAlg(false), fields)
verifier, _ := httpsign.NewJWSVerifier(jwa.MLDSA65(), pub, httpsign.NewVerifyConfig(), fields)
```

HMAC keys must be `[]byte` (minimum length per RFC 7518).

### Notes and Missing Features
* Requires **Go 1.27+**.
* The `Accept-Signature` header is unimplemented.
* In responses, when using the "wrapped handler" feature, the `Content-Type` header is only signed if set explicitly by the server. This is different, but arguably more secure, than the normal `net.http` behavior.
* **Behind a TLS-terminating reverse proxy:** The `@scheme` derived component defaults to `req.TLS != nil`. Behind nginx, Envoy, AWS ALB, etc., `req.TLS` is nil, so `@scheme` becomes `"http"` even for HTTPS traffic. Use `SetSchemeFromRequest` on `SignConfig` and `VerifyConfig` to derive the scheme from `X-Forwarded-Proto` or similar headers.
* **Nonce-based replay prevention:** The signer can include a nonce via `SetNonce`; the verifier does not track seen nonces by default. Use `SetNonceValidator` on `VerifyConfig` to implement replay prevention—the callback must check uniqueness (e.g. via a cache or database) and return an error for duplicates.
* **Replay window:** Without nonce validation, `SetNotOlderThan` (default 10s) is the only replay defense. For sensitive operations, reduce this value or use `SetNonceValidator`. See the method docstrings for details.

### Contributing
Contributions to this project are welcome, both as issues and pull requests.

[![Go Reference](https://pkg.go.dev/badge/github.com/yaronf/httpsign.svg)](https://pkg.go.dev/github.com/yaronf/httpsign)
[![Test](https://github.com/yaronf/httpsign/actions/workflows/test.yml/badge.svg)](https://github.com/yaronf/httpsign/actions/workflows/test.yml)
[![Lint](https://github.com/yaronf/httpsign/actions/workflows/lint.yml/badge.svg)](https://github.com/yaronf/httpsign/actions/workflows/lint.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/yaronf/httpsign)
