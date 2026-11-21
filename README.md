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

### Native ML-DSA (IANA `ml-dsa-44` / `65` / `87`)

Native constructors `NewMLDSA44Signer` / `NewMLDSA44Verifier` (and the `-65` / `-87` pairs) implement the [HTTP Signature Algorithms](https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml) registered from [C2SP httpsig-pq](https://c2sp.org/httpsig-pq@v1.0.1), using Go’s `crypto/mldsa`. They take `*mldsa.PrivateKey` / `*mldsa.PublicKey` and emit the IANA `alg` values (e.g. `;alg="ml-dsa-44"`). ML-DSA signatures are large (about 3.2–6.2 KiB Base64 before field overhead); raise intermediary header limits if needed.

### Foreign JWS (including JOSE ML-DSA)

Optional algorithms beyond the native set use [`lestrrat-go/jwx/v4`](https://github.com/lestrrat-go/jwx) via `NewJWSSigner` / `NewJWSSignerFromJWK` / `NewJWSVerifier` / `NewJWSVerifierWithAlg` (including ML-DSA with `crypto/mldsa`). That path uses JOSE algorithm names and cannot emit an HTTP `alg` parameter. Prefer the native ML-DSA constructors above when you need IANA `ml-dsa-*`. See the [API reference](https://pkg.go.dev/github.com/yaronf/httpsign) for constructors, allowlists, `crypto.Signer` (HSM/KMS) keys, and examples.

### Notes and Missing Features
* Requires **Go 1.27+**.
* The `Accept-Signature` header is unimplemented.
* In responses, when using the "wrapped handler" feature, the `Content-Type` header is only signed if set explicitly by the server. This is different, but arguably more secure, than the normal `net.http` behavior.
* **Behind a TLS-terminating reverse proxy:** The `@scheme` derived component defaults to `req.TLS != nil`. Behind nginx, Envoy, AWS ALB, etc., `req.TLS` is nil, so `@scheme` becomes `"http"` even for HTTPS traffic. Use `SetSchemeFromRequest` on `SignConfig` and `VerifyConfig` to derive the scheme from `X-Forwarded-Proto` or similar headers.
* **Nonce-based replay prevention:** The signer can include a nonce via `SetNonce`; the verifier does not track seen nonces by default. Use `SetNonceValidator` on `VerifyConfig` to implement replay prevention—the callback must check uniqueness (e.g. via a cache or database) and return an error for duplicates.
* **Replay window:** Without nonce validation, `SetNotOlderThan` (default 10s) is the only replay defense. For sensitive operations, reduce this value or use `SetNonceValidator`. See the method docstrings for details.
* Changelogs: [GitHub releases](https://github.com/yaronf/httpsign/releases).

### Contributing
Contributions to this project are welcome, both as issues and pull requests.

[![Go Reference](https://pkg.go.dev/badge/github.com/yaronf/httpsign.svg)](https://pkg.go.dev/github.com/yaronf/httpsign)
[![Test](https://github.com/yaronf/httpsign/actions/workflows/test.yml/badge.svg)](https://github.com/yaronf/httpsign/actions/workflows/test.yml)
[![Lint](https://github.com/yaronf/httpsign/actions/workflows/lint.yml/badge.svg)](https://github.com/yaronf/httpsign/actions/workflows/lint.yml)
