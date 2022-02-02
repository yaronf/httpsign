HTTP Message Signatures, implementing [draft-ietf-httpbis-message-signatures-08](https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-08.html).

This is a nearly feature-complete implementation of draft -08, including all test vectors.

### Notes and Missing Features
* The `Accept-Signature` header.
* Inclusion of `Signature` and `Signature-Input` as trailers is optional and is not yet implemented.
* Extracting derived components from the "related request". See [related issue](https://github.com/httpwg/http-extensions/issues/1905).
* In responses, when using the "wrapped handler" feature, the `Content-Type` header is only signed if set explicitly by the server. This is different, but arguably more secure, than the normal `net.http` behavior.
* Test vectors are still verified to -07, update to -08 is pending.

[![Go Reference](https://pkg.go.dev/badge/github.com/yaronf/httpsign.svg)](https://pkg.go.dev/github.com/yaronf/httpsign)
[![Test](https://github.com/yaronf/httpsign/actions/workflows/test.yml/badge.svg)](https://github.com/yaronf/httpsign/actions/workflows/test.yml)
[![GoReportCard example](https://goreportcard.com/badge/github.com/yaronf/httpsign)](https://goreportcard.com/report/github.com/yaronf/httpsign)
