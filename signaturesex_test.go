package httpsign_test

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/yaronf/httpsign"
	"net/http"
	"strings"
)

func ExampleSignRequest() {
	config := httpsign.NewSignConfig().SignCreated(false).SetNonce("BADCAB").SetKeyID("my-shared-secret") // SignCreated should be "true" to protect against replay attacks
	fields := httpsign.Headers("@authority", "Date", "@method")
	signer, _ := httpsign.NewHMACSHA256Signer(bytes.Repeat([]byte{0x77}, 64), config, fields)
	reqStr := `GET /foo HTTP/1.1
Host: example.org
Date: Tue, 20 Apr 2021 02:07:55 GMT
Cache-Control: max-age=60

`
	req, _ := http.ReadRequest(bufio.NewReader(strings.NewReader(reqStr)))
	signatureInput, signature, _ := httpsign.SignRequest("sig77", *signer, req)
	fmt.Printf("Signature-Input: %s\n", signatureInput)
	fmt.Printf("Signature:       %s", signature)
	// Output: Signature-Input: sig77=("@authority" "date" "@method");nonce="BADCAB";alg="hmac-sha256";keyid="my-shared-secret"
	//Signature:       sig77=:BBxhfE6GoDVcohZvc+pT448u7GAK7EjJYTu+i26YZW0=:
}

func ExampleVerifyRequest() {
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
	err := httpsign.VerifyRequest("sig77", *verifier, req)
	fmt.Printf("verified: %t", err == nil)
	// Output: verified: true
}
