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

var resdigest3 = `HTTP/1.1 206 Partial Content
Content-Type: application/json
Content-Range: bytes 1-7/18
Content-Digest: sha-256=:Wqdirjg/u3J688ejbUlApbjECpiUUtIwT8lY/z81Tno=:

"hello!!"`

var resdigest5 = `HTTP/1.1 206 Partial Content
Content-Type: application/json
Content-Range: bytes 1-7/18
Content-Digest: sha-256=:Wqdirjg/u3J688ejbUlApbjECpiUUtIwT8lY/z81Tno=:, sha-512=:A8pplr4vsk4xdLkJruCXWp6+i+dy/3pSW5HW5ke1jDWS70Dv6Fstf1jS+XEcLqEVhW3i925IPlf/4tnpnvAQDw==:

"hello"`

var resdigest6 = `HTTP/1.1 200 OK
Content-Type: application/json
Content-Digest: sha-256=:X47E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:

{"hello": "world"}`

func TestMessages(t *testing.T) {
	res1 := readResponse(resdigest1)
	d, err := GenerateContentDigestHeader(&res1.Body, []string{DigestSha256})
	assert.NoError(t, err, "should not fail to generate digest")
	assert.Equal(t, "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:", d)
	h := res1.Header.Get("Content-Digest")
	assert.Equal(t, h, d)

	res2 := readResponse(resdigest2)
	d, err = GenerateContentDigestHeader(&res2.Body, []string{DigestSha256})
	assert.NoError(t, err, "should not fail to generate digest")
	h = res2.Header.Get("Content-Digest")
	assert.Equal(t, h, d)

	res3 := readResponse(resdigest3)
	d, err = GenerateContentDigestHeader(&res3.Body, []string{DigestSha256})
	assert.NoError(t, err, "should not fail to generate digest")
	h = res3.Header.Get("Content-Digest")
	assert.NotEqual(t, h, d)

	res4 := readResponse(resdigest3)
	d, err = GenerateContentDigestHeader(&res4.Body, []string{DigestSha256, "sha-999"})
	assert.Error(t, err, "bad digest scheme")

	res5 := readResponse(resdigest5)
	d, err = GenerateContentDigestHeader(&res5.Body, []string{DigestSha256, DigestSha512})
	assert.NoError(t, err, "should not fail to generate digest")
	h = res5.Header.Get("Content-Digest")
	assert.Equal(t, h, d)
}

func TestValidateContentDigestHeader(t *testing.T) {
	res1 := readResponse(resdigest1)
	hdr := res1.Header.Values("Content-Digest")
	err := ValidateContentDigestHeader(hdr, &res1.Body, []string{DigestSha256})
	assert.NoError(t, err, "should not fail")

	err = ValidateContentDigestHeader(hdr, &res1.Body, []string{})
	assert.Error(t, err, "empty list of accepted schemes")

	err = ValidateContentDigestHeader(hdr, &res1.Body, []string{"kuku"})
	assert.Error(t, err, "unknown scheme in list of accepted schemes")

	hdr = []string{"123"}
	err = ValidateContentDigestHeader(hdr, &res1.Body, []string{DigestSha256})
	assert.Error(t, err, "bad received header")

	hdr = res1.Header.Values("Content-Digest")
	err = ValidateContentDigestHeader(hdr, &res1.Body, []string{DigestSha512})
	assert.Error(t, err, "no acceptable scheme")

	res6 := readResponse(resdigest6)
	hdr = res6.Header.Values("Content-Digest")
	err = ValidateContentDigestHeader(hdr, &res6.Body, []string{DigestSha256})
	assert.Error(t, err, "digest mismatch")

	// Response taken from the draft,see https://github.com/httpwg/http-extensions/pull/2049
	res7 := readResponse(httpres4)
	hdr = res7.Header.Values("Content-Digest")
	err = ValidateContentDigestHeader(hdr, &res7.Body, []string{DigestSha512})
	assert.NoError(t, err, "digest mismatch?")
}
