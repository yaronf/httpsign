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

### Upgrading

**v0.6.0** (shipped) raised the Go floor to **1.27+** and cut foreign JWS over to **jwx v4** + ML-DSA. See [internal-docs/RELEASE-v0.6.0.md](internal-docs/RELEASE-v0.6.0.md).

**v0.6.1** breaks foreign-JWS **verify** again: prefer `NewJWSVerifier(allowed, key, …)` (infer alg); use `NewJWSVerifierWithAlg` when needed; pass a `JWSAlgAllowlist` (`nil` skips policy). `NewJWSSigner` defaults to / requires `SignAlg(false)`; use `NewJWSSignerFromJWK` when the private key is a JWK.

| Caller | Change in v0.6.1 |
|--------|------------------|
| Native algorithms only | None. |
| `NewJWSVerifier(alg, key, …)` (v0.6.0) | Prefer `NewJWSVerifier(allowed, key, …)`; else `NewJWSVerifierWithAlg(allowed, alg, key, …)`. |
| `NewJWSSigner` | Nil config ⇒ `SignAlg(false)`; `SignAlg(true)` errors. Prefer `NewJWSSignerFromJWK` for private JWKs. |

Pass a non-nil allowlist when `keyid` can select among keys. `SetAllowedAlgs` still only filters Signature-Input `alg`, not JWS `jwa`.

Full notes: [internal-docs/RELEASE-v0.6.1.md](internal-docs/RELEASE-v0.6.1.md).

### Foreign JWS and ML-DSA

Optional algorithms beyond the native set use [`lestrrat-go/jwx/v4`](https://github.com/lestrrat-go/jwx) (≥ v4.5.0) via `NewJWSSigner` / `NewJWSSignerFromJWK` / `NewJWSVerifier`.

**ML-DSA (FIPS 204)** works through the same path with `crypto/mldsa` keys. Prefer inferring the alg from the public key:

```go
priv, _ := mldsa.GenerateKey(mldsa.MLDSA65())
pub := priv.Public().(*mldsa.PublicKey)
signer, _ := httpsign.NewJWSSigner(jwa.MLDSA65(), priv, nil, fields) // SignAlg(false) by default
allowed, _ := httpsign.NewJWSAlgAllowlist(jwa.MLDSA65())
verifier, _ := httpsign.NewJWSVerifier(allowed, pub, httpsign.NewVerifyConfig(), fields)
```

HMAC keys must be `[]byte` (minimum length per RFC 7518). Raw RSA verify needs `NewJWSVerifierWithAlg` (or a JWK that carries `alg`).

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
