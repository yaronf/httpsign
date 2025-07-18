package httpsign

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var rawPost1 = `POST /foo HTTP/1.1
Content-Type: text/plain
Transfer-Encoding: chunked
Trailer: Expires, Hdr

4
HTTP
7
Message
a
Signatures
0
Expires: Wed, 9 Nov 2022 07:28:00 GMT
Hdr: zoom

`

var rawPost2 = `POST /foo HTTP/1.1
Content-Type: text/plain
Transfer-Encoding: chunked
Trailer: Expires, Hdr

4
HTTP
7
Message
a
Signatures
0
Expires: Wed, 9 Nov 2022 07:28:00 GMT
Hdr: zoom
`

var rawHeaders1 = `POST /foo HTTP/1.1
Content-Type: text/plain
Transfer-Encoding: chunked
Trailer: Expires, Hdr

`

var longReq1 = rawHeaders1 + "5000\r\n" + strings.Repeat("x", 0x5000) + "\r\n0\r\n" + "Hdr: zoomba\r\n\r\n"

func TestTrailer_Get(t *testing.T) {
	fetchVerifier := func(r *http.Request) (string, *Verifier) {
		sigName := "sig1"
		verifier, _ := NewHMACSHA256Verifier(bytes.Repeat([]byte{1}, 64), NewVerifyConfig().SetKeyID("key1"),
			*NewFields().AddHeader("@method").
				AddHeaderExt("hdr", false, false, false, true))
		return sigName, verifier
	}

	fetchSigner := func(res http.Response, r *http.Request) (string, *Signer) {
		sigName := "sig1"
		signer, _ := NewHMACSHA256Signer(bytes.Repeat([]byte{0}, 64), NewSignConfig().SetKeyID("key"),
			Headers("@status", "bar", "date", "Content-Digest"))
		return sigName, signer
	}

	simpleHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("bar", "baz and baz again")
		_, _ = fmt.Fprintln(w, "Hello, client")
		_, _ = fmt.Fprintln(w, "Hello again")
	}
	config := NewHandlerConfig().SetFetchVerifier(fetchVerifier).
		SetFetchSigner(fetchSigner).SetDigestSchemesSend([]string{DigestSha256}).SetDigestSchemesRecv([]string{DigestSha256})
	ts := httptest.NewServer(WrapHandler(http.HandlerFunc(simpleHandler), *config))
	defer ts.Close()

	c := &Client{config: ClientConfig{
		signatureName: "sig1",
		signer: func() *Signer {
			signer, _ := NewHMACSHA256Signer(bytes.Repeat([]byte{1}, 64), NewSignConfig().SetKeyID("key1"),
				*NewFields().AddHeader("@method").
					AddHeaderExt("hdr", false, false, false, true))
			return signer
		}(),
		verifier:      nil,
		fetchVerifier: nil,
	},
		client: *http.DefaultClient,
	}

	req := readRequestChunked(rawPost1)

	req.RequestURI = "" // otherwise Do will complain
	u, err := url.Parse(ts.URL + "/")
	if err != nil {
		panic(err)
	}
	req.URL = u

	res, err := c.Do(req)
	var gotRes string
	if res != nil {
		gotRes = res.Status
	}
	if err != nil {
		t.Errorf("Get() error = %v", err)
		return
	}
	if gotRes != "200 OK" {
		t.Errorf("Get() gotRes = %v", gotRes)
	}

	req2 := readRequest(longReq1)
	req2.RequestURI = "" // otherwise Do will complain
	req2.URL = u

	res, err = c.Do(req2)
	if res != nil {
		gotRes = res.Status
	}
	if err != nil {
		t.Errorf("Get() error = %v", err)
		return
	}
	if gotRes != "200 OK" {
		t.Errorf("Get() gotRes = %v", gotRes)
	}
}

func TestTrailer_SigFields(t *testing.T) {
	config := NewSignConfig().SignAlg(false).setFakeCreated(1618884475).SetKeyID("test-shared-secret")
	fields := Headers("@authority", "@method", "content-type")
	signatureName := "sig1"
	key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
	signer, _ := NewHMACSHA256Signer(key, config, fields)
	req := readRequest(rawPost2)
	sigInput, sig, err := SignRequest(signatureName, *signer, req)
	assert.NoError(t, err, "signature failed")
	// Add signature correctly
	signedMessage := rawPost2 + "Signature: " + sig + "\n" + "Signature-Input: " + sigInput + "\n\n"
	signedMessage = strings.Replace(signedMessage, "Trailer: Expires, Hdr", "Trailer: Expires, Hdr, Signature, Signature-Input",
		1)
	req2 := readRequestChunked(signedMessage)
	verifier, err := NewHMACSHA256Verifier(key, NewVerifyConfig().SetVerifyCreated(false).SetKeyID("test-shared-secret"), fields)
	assert.NoError(t, err, "could not generate Verifier")
	err = VerifyRequest(signatureName, *verifier, req2)
	assert.NoError(t, err, "verification error")

	// Missing Signature-Input
	signedMessage = rawPost2 + "Signature: " + sig + "\n\n"
	signedMessage = strings.Replace(signedMessage, "Trailer: Expires, Hdr", "Trailer: Expires, Hdr, Signature, Signature-Input",
		1)
	req2 = readRequestChunked(signedMessage)
	verifier, err = NewHMACSHA256Verifier(key, NewVerifyConfig().SetVerifyCreated(false).SetKeyID("test-shared-secret"), fields)
	assert.NoError(t, err, "could not generate Verifier")
	err = VerifyRequest(signatureName, *verifier, req2)
	assert.Error(t, err, "verification error")

	// Missing Signature
	signedMessage = rawPost2 + "Signature-Input: " + sigInput + "\n\n"
	signedMessage = strings.Replace(signedMessage, "Trailer: Expires, Hdr", "Trailer: Expires, Hdr, Signature, Signature-Input",
		1)
	req2 = readRequestChunked(signedMessage)
	verifier, err = NewHMACSHA256Verifier(key, NewVerifyConfig().SetVerifyCreated(false).SetKeyID("test-shared-secret"), fields)
	assert.NoError(t, err, "could not generate Verifier")
	err = VerifyRequest(signatureName, *verifier, req2)
	assert.Error(t, err, "verification error")
}
