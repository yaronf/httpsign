package httpsign_test

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/yaronf/httpsign"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ExampleClient_Get() {
	// Note: client/server examples may fail in the Go Playground, https://github.com/golang/go/issues/45855
	// Set up a test server
	simpleHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "Hey client, you sent a signature with these parameters: %s\n",
			r.Header.Get("Signature-Input"))
	}
	ts := httptest.NewServer(http.HandlerFunc(simpleHandler))
	defer ts.Close()

	// Client code starts here
	// Create a signer and a wrapped HTTP client (we set SignCreated to false to make the response deterministic,
	// don't do that in production.)
	signer, _ := httpsign.NewHMACSHA256Signer("key1", bytes.Repeat([]byte{1}, 64),
		httpsign.NewSignConfig().SignCreated(false), httpsign.Headers("@method"))
	client := httpsign.NewDefaultClient(httpsign.NewClientConfig().SetSignatureName("sig22").SetSigner(signer)) // sign, don't verify

	// Send an HTTP GET, get response -- signing and verification happen behind the scenes
	res, _ := client.Get(ts.URL)

	// Read the response
	serverText, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()

	fmt.Println("Server sent: ", string(serverText))
	// Output: Server sent:  Hey client, you sent a signature with these parameters: sig22=("@method");alg="hmac-sha256";keyid="key1"
}

var rsaPrvKey = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDIPoeuHmZXXqz+
NCeAIXUh+nMu4lOtp6okWU0RKy9t40xwDh1CNT8sxfZcDe/IXuc7KV5OKx2bMVlv
1MugLUdSRwQFvWWQSHR5yborPrAjqKYqWh6gOgBKVekhrq+vl1PeFx96TXlIMGQ6
Bt8Qmh5QW9BmsF8hYVC3996Q+x+BI9P0U3DUKGLf5yuacRyTyPY3CjGLjg7iNpU1
seb4JUz8UkfuM+MP1JjlR0LWumYbeIGimdkPARhbMOYfjKNhU1NvhS+bCv69t7YU
SgvPdTX660QnxEDTcQTMASRRXKnvBinK8z8VZdtEJLBj9kFK9GOs+CdbwL3TyTka
8LxAtKw5AgMBAAECggEBAKcW9mSmXUN+bt/XaTaTtIfb0o1GsghvpZubIKG45WTO
jBPc0zFR+RtFPONnhbQu7MgDJvwXIidDsJuOdzN7VM4lEAgyGDOjIf4WBFDdiGDY
837XoEKW43Mj6NsARv1ASu1BYjTNvOwt5RQ+c5gI4k6vrmBhv5+88nvwSzmzMoCw
h3ZLz4DfyOoBu7dqlnw9EttZuW7k1SXXW/cC5Sh90j8gZmYlNN76O1LsiCxZowCj
Ys5Qdm5tcNuV8jK3XIFE4uYyBRHx5+haNjgKeM8n8IEEPYhzqcYIAYWGRHSkTvGy
DxAb8AJBwuFCsFQz0oXyzVd8Mqz8RbqC7N50LdncCWECgYEA9zE9u/x8r7/De25U
FcDDLt63qkqDmSn1PMkwf1DdOj734fYWd8Ay2R5E43NJMQalcR7Q7++O5KOQOFUl
mpd79U9LO3b9FE0vR8xG81wushKy3xhHQdB2ucKliGwcYvcfgjWUoD7aKfrlHmNA
olj1/21tJQGotEGg9NpiinJaiT0CgYEAz2ENkkEH3ZXtMKr3DXoqLNU+er4pHzm1
cRxzpCNqNwZBlv0pxeIo6izH4TIrBPdIqSApUpZ0N+NgA0bjj0527GATGkGDgo+b
TZFAhOhg7bfUyLsbgL/zycnyQwDWw2fo5ei9Bb2pPqfeQgrgYE+ag+ucJrhJNymv
3gG6Vmdwhq0CgYEAr6rwwl2Ghqdy1o7rdqIMk4x3Xa+iogBtZYtcyb2/2hrRsmVe
Ri/yctXOAw3038BnZmKN/VVzaQzL+xyXoqswzn5Raqr+46SOiymi6mOCU85yC5WH
XkA1f4HSfYbHDZWtcK1/N/oytE628Md8MWOjPqiXPgtVxvQ03I0uJlFqAckCgYB6
w/yxwTez0MaqkftRCiofglnLdfmIF7S28l3vJFwDmPuJM/PfxoPsJXhqczWOagmk
vXpY/uJsF3nGVtfuBUhXpISKfZAp4XPR1pQ4WgzPjY01C7c7X+clZRy616tL4J66
RC5qUJ35joz/0cqEmXtibz9wmJYXRuFq7uDtt6ygvQKBgQCMopIJCcH5+DmbXmyw
J8fxjxp8YpkEoFMtloaJ7lWHkiCUSWYCbGlvG1Nb1CoVqOuMffGXAZKAU9cw7YA2
cJQuDUjlA0haDD4W3IibLGbANw414qqpqRmo5kM6aMpnShGsvxpp/0+XKrfcwgiC
Ufa6y08wtZ/O7ZCBBbJTY90uqA==
-----END PRIVATE KEY-----
`

func parseRsaPrivateKeyFromPemStr(pemString string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, fmt.Errorf("cannot decode PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return k.(*rsa.PrivateKey), nil
}

// This code is used in the README file
func TestClientUsage(t *testing.T) {
	// Note: client/server examples may fail in the Go Playground, https://github.com/golang/go/issues/45855
	// Set up a test server
	simpleHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "Hey client, you sent a signature with these parameters: %s\n",
			r.Header.Get("Signature-Input"))
	}
	ts := httptest.NewServer(http.HandlerFunc(simpleHandler))
	defer ts.Close()

	prvKey, err := parseRsaPrivateKeyFromPemStr(rsaPrvKey)
	if err != nil {
		t.Errorf("could not read private key")
	}

	// Client code starts here
	// Create a signer and a wrapped HTTP client
	signer, _ := httpsign.NewRSAPSSSigner("key1", *prvKey,
		httpsign.NewSignConfig(),
		httpsign.Headers("@request-target", "Content-Digest")) // The Content-Digest header will be auto-generated
	client := httpsign.NewDefaultClient(httpsign.NewClientConfig().SetSignatureName("sig1").SetSigner(signer)) // sign requests, don't verify responses

	// Send an HTTP POST, get response -- signing and verification happen behind the scenes
	body := `{"hello": "world"}`
	res, err := client.Post(ts.URL, "application/json", bufio.NewReader(strings.NewReader(body)))
	if err != nil {
		// handle error
	}

	// Read the response
	serverText, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()

	fmt.Println("Server sent: ", string(serverText))
	// Output: Server sent:  Hey client, you sent a signature with these parameters: sig22=("@method");alg="hmac-sha256";keyid="key1"
}
