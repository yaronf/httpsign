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
### Notes and Missing Features
* The `Accept-Signature` header is unimplemented.
* In responses, when using the "wrapped handler" feature, the `Content-Type` header is only signed if set explicitly by the server. This is different, but arguably more secure, than the normal `net.http` behavior.
* **Behind a TLS-terminating reverse proxy:** The `@scheme` derived component defaults to `req.TLS != nil`. Behind nginx, Envoy, AWS ALB, etc., `req.TLS` is nil, so `@scheme` becomes `"http"` even for HTTPS traffic. Use `SetSchemeFromRequest` on `SignConfig` and `VerifyConfig` to derive the scheme from `X-Forwarded-Proto` or similar headers.
* **Nonce-based replay prevention:** The signer can include a nonce via `SetNonce`; the verifier does not track seen nonces by default. Use `SetNonceValidator` on `VerifyConfig` to implement replay prevention—the callback must check uniqueness (e.g. via a cache or database) and return an error for duplicates.

### Contributing
Contributions to this project are welcome, both as issues and pull requests.

[![Go Reference](https://pkg.go.dev/badge/github.com/yaronf/httpsign.svg)](https://pkg.go.dev/github.com/yaronf/httpsign)
[![Test](https://github.com/yaronf/httpsign/actions/workflows/test.yml/badge.svg)](https://github.com/yaronf/httpsign/actions/workflows/test.yml)
[![GoReportCard example](https://goreportcard.com/badge/github.com/yaronf/httpsign)](https://goreportcard.com/report/github.com/yaronf/httpsign)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/yaronf/httpsign)
