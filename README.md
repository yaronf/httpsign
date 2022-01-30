HTTP Message Signatures, implementing [draft-ietf-httpbis-message-signatures-07](https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-07.html).

### Notes And Missing Features
* The `Accept-Signature` header.
* Inclusion of `Signature` and `Signature-Input` as trailers is optional and is not yet implemented.
* Extracting specialty components from the "related request".
* In responses, the `Content-Type` header is only signed if set explicitly by the server. This is different, but arguably more secure, than the normal net.http behavior.
* Multiple Signatures (Sec. 4.3).
* The `sf` parameter, and in particular behavior when it is *not* given.

[![Go Reference](https://pkg.go.dev/badge/github.com/yaronf/httpsign.svg)](https://pkg.go.dev/github.com/yaronf/httpsign)
[![Test](https://github.com/yaronf/httpsign/actions/workflows/test.yml/badge.svg)](https://github.com/yaronf/httpsign/actions/workflows/test.yml)
[![GoReportCard example](https://goreportcard.com/badge/github.com/yaronf/httpsign)](https://goreportcard.com/report/github.com/yaronf/httpsign)
