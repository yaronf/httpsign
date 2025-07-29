package httpsign_test

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"github.com/yaronf/httpsign"
)

func ExampleMessage_Verify() {
	config := httpsign.NewVerifyConfig().SetKeyID("my-shared-secret").SetVerifyCreated(false) // for testing only
	verifier, _ := httpsign.NewHMACSHA256Verifier(bytes.Repeat([]byte{0x77}, 64), config,
		httpsign.Headers("@authority", "Date", "@method"))
	reqStr := `GET /foo HTTP/1.1
Host: example.org
Date: Tue, 20 Apr 2021 02:07:55 GMT
Cache-Control: max-age=60
Signature-Input: sig77=("@authority" "date" "@method");alg="hmac-sha256";keyid="my-shared-secret"
Signature:       sig77=:3e9KqLP62NHfHY5OMG4036+U6tvBowZF35ALzTjpsf0=:

`
	req, _ := http.ReadRequest(bufio.NewReader(strings.NewReader(reqStr)))

	// Using WithRequest
	msgWithRequest, _ := httpsign.NewMessage(httpsign.NewMessageConfig().WithRequest(req))
	_, err1 := msgWithRequest.Verify("sig77", *verifier)

	// Using constituent parts
	msgWithConstituents, _ := httpsign.NewMessage(httpsign.NewMessageConfig().
		WithMethod(req.Method).
		WithURL(req.URL).
		WithHeaders(req.Header).
		WithTrailers(req.Trailer).
		WithBody(&req.Body).
		WithAuthority(req.Host).
		WithScheme(req.URL.Scheme))

	_, err2 := msgWithConstituents.Verify("sig77", *verifier)

	fmt.Printf("WithRequest: %t\n", err1 == nil)
	fmt.Printf("Constituents: %t", err2 == nil)
	// Output:
	// WithRequest: true
	// Constituents: true
}
