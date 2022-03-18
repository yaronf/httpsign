package httpsign

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// digest draft, B.1
var resdigest1 = `HTTP/1.1 200 OK
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:

{"hello": "world"}`

// digest draft, B.3
var resdigest2 = `HTTP/1.1 206 Partial Content
Content-Type: application/json
Content-Range: bytes 1-7/18
Content-Digest: sha-256=:Wqdirjg/u3J688ejbUlApbjECpiUUtIwT8lY/z81Tno=:

"hello"`

func TestMessages(t *testing.T) {
	res1 := readResponse(resdigest1)
	d, err := GenerateContentDigest(&res1.Body, DigestSha256)
	assert.NoError(t, err, "should not fail to generate digest")
	assert.Equal(t, "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:", d)
	h := res1.Header.Get("Content-Digest")
	assert.Equal(t, h, d)

	res2 := readResponse(resdigest2)
	d, err = GenerateContentDigest(&res2.Body, DigestSha256)
	assert.NoError(t, err, "should not fail to generate digest")
	h = res2.Header.Get("Content-Digest")
	assert.Equal(t, h, d)
}
