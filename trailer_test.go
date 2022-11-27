package httpsign

import (
	"bytes"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

var rawPost1 = "POST /foo HTTP/1.1\nContent-Type: text/plain\nTransfer-Encoding: chunked\nTrailer: Expires\n\n4\nHTTP\r\n7\r\nMessage\r\na\r\nSignatures\r\n0\r\nExpires: Wed, 9 Nov 2022 07:28:00 GMT\r\n\r\n"

// This identical representation fails, see https://github.com/golang/go/issues/56835
var rawPost2 = `POST /foo HTTP/1.1
Content-Type: text/plain
Transfer-Encoding: chunked
Trailer: Expires

4
HTTP
7
Message
a
Signatures
0
Expires: Wed, 9 Nov 2022 07:28:00 GMT

`

func TestTrailer_Get(t *testing.T) {
	ts := makeTestServer()
	defer ts.Close()

	c := &Client{config: ClientConfig{
		signatureName: "sig1",
		signer: func() *Signer {
			signer, _ := NewHMACSHA256Signer("key1", bytes.Repeat([]byte{1}, 64), NewSignConfig(),
				Headers("@method", "hdr"))
			return signer
		}(),
		verifier:      nil,
		fetchVerifier: nil,
	},
		client: *http.DefaultClient,
	}
	req := readRequest(rawPost1)

	req.RequestURI = "" // otherwise Do will complain
	u, err := url.Parse(ts.URL + "/foo")
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
	if !reflect.DeepEqual(gotRes, "200 OK") {
		t.Errorf("Get() gotRes = %v", gotRes)
	}

	t.Errorf("No trailer support")
}
