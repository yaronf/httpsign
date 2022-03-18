package httpsign

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"io/ioutil"
)

// Constants define the hash algorithm to be used for the digest
const (
	DigestSha256 = "sha-256"
	DigestSha512 = "sha-512"
)

// GenerateContentDigest generates a digest of the message body according to the given scheme (DigestSha256 or
// DigestSha512). Side effect: the message body is fully read, and replaced by a static buffer
// containing the body contents.
func GenerateContentDigest(body *io.ReadCloser, scheme string) (string, error) {
	buff := &bytes.Buffer{}
	if body != nil {
		_, err := buff.ReadFrom(*body)
		if err != nil {
			return "", err
		}

		defer (*body).Close()

		*body = ioutil.NopCloser(bytes.NewReader(buff.Bytes()))
	}
	raw, err := rawDigest(buff.String(), scheme)
	if err != nil {
		return "", err
	}
	return scheme + "=" + encodeBytes(raw), nil
}

func rawDigest(s string, scheme string) ([]byte, error) {
	switch scheme {
	case DigestSha256:
		s := sha256.Sum256([]byte(s))
		return s[:], nil
	case DigestSha512:
		s := sha512.Sum512([]byte(s))
		return s[:], nil
	default:
		return nil, fmt.Errorf("unknown digest scheme")
	}
}
