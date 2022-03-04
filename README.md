HTTP Message Signatures, implementing [draft-ietf-httpbis-message-signatures-08](https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-08.html).

This is a nearly feature-complete implementation of draft -08, including all test vectors.

The code follows the latest version of the draft, which may be the [Editor's Copy](https://httpwg.org/http-extensions/draft-ietf-httpbis-message-signatures.html) rather than the published draft.

### Usage

The library provides natural integration with Go HTTP clients and servers, as well as direct usage of the
sign and verify functions.

The simplest client-side usage is as follows:

```cgo
	// Create a signer and a wrapped HTTP client
	signer, _ := httpsign.NewRSAPSSSigner("key1", *prvKey,
		httpsign.NewSignConfig(),
		httpsign.Headers("@request-target"))
	client := httpsign.NewDefaultClient("sig1", signer, nil, nil) // sign requests, don't verify responses

	// Send an HTTP POST, get response -- signing and verification happen behind the scenes
	body := `{"hello": "world"}`
	res, err := client.Post(ts.URL, "application/json", bufio.NewReader(strings.NewReader(body)))
	if err != nil {
		// handle error
	}

	// Read the response
	serverText, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
```
### Notes and Missing Features
* The `Accept-Signature` header is unimplemented.
* Inclusion of `Signature` and `Signature-Input` as trailers is optional and is not yet implemented.
* Extracting derived components from the "related request". See [related issue](https://github.com/httpwg/http-extensions/issues/1905).
* In responses, when using the "wrapped handler" feature, the `Content-Type` header is only signed if set explicitly by the server. This is different, but arguably more secure, than the normal `net.http` behavior.

[![Go Reference](https://pkg.go.dev/badge/github.com/yaronf/httpsign.svg)](https://pkg.go.dev/github.com/yaronf/httpsign)
[![Test](https://github.com/yaronf/httpsign/actions/workflows/test.yml/badge.svg)](https://github.com/yaronf/httpsign/actions/workflows/test.yml)
[![GoReportCard example](https://goreportcard.com/badge/github.com/yaronf/httpsign)](https://goreportcard.com/report/github.com/yaronf/httpsign)
