package httpsign

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/dunglas/httpsfv"
	"io"
	"io/ioutil"
)

// Constants define the hash algorithm to be used for the digest
const (
	DigestSha256 = "sha-256"
	DigestSha512 = "sha-512"
)

// GenerateContentDigestHeader generates a digest of the message body according to the given scheme(s)
// (currently supporting DigestSha256 and DigestSha512).
// Side effect: the message body is fully read, and replaced by a static buffer
// containing the body contents.
func GenerateContentDigestHeader(body *io.ReadCloser, schemes []string) (string, error) {
	if len(schemes) == 0 {
		return "", fmt.Errorf("received empty list of digest schemes")
	}
	err := validateSchemes(schemes)
	if err != nil {
		return "", err
	}
	buff, err := duplicateBody(body)
	if err != nil {
		return "", err
	}
	dict := httpsfv.NewDictionary()
	for _, scheme := range schemes {
		raw, err := rawDigest(buff.String(), scheme)
		if err != nil { // When sending, must recognize all schemes
			return "", err
		}
		i := httpsfv.NewItem(raw)
		dict.Add(scheme, httpsfv.Member(i))
	}
	return httpsfv.Marshal(dict)
}

func duplicateBody(body *io.ReadCloser) (*bytes.Buffer, error) {
	buff := &bytes.Buffer{}
	if body != nil {
		_, err := buff.ReadFrom(*body)
		if err != nil {
			return nil, err
		}

		_ = (*body).Close()

		*body = ioutil.NopCloser(bytes.NewReader(buff.Bytes()))
	}
	return buff, nil
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

func validateSchemes(schemes []string) error {
	valid := map[string]bool{DigestSha256: true, DigestSha512: true}
	for _, s := range schemes {
		if !valid[s] {
			return fmt.Errorf("invalid scheme: s")
		}
	}
	return nil
}

func ValidateContentDigestHeader(received []string, body *io.ReadCloser, accepted []string) error {
	if len(accepted) == 0 {
		return fmt.Errorf("received no digest schemes to accept")
	}
	err := validateSchemes(accepted)
	if err != nil {
		return err
	}
	receivedDict, err := httpsfv.UnmarshalDictionary(received)
	if err != nil {
		return fmt.Errorf("received Content-Digest header: %w", err)
	}
	buff, err := duplicateBody(body)
	if err != nil {
		return err
	}
	var ok bool
found:
	for _, a := range accepted {
		for _, r := range receivedDict.Names() {
			if a == r {
				ok = true
				break found
			}
		}
	}
	if !ok {
		return fmt.Errorf("no acceptable digest scheme found in Content-Digest header")
	}
	// But regardless of the list of accepted schemes, all included digest values (if recognized) must be correct
	for _, scheme := range receivedDict.Names() {
		raw, err := rawDigest(buff.String(), scheme)
		if err != nil {
			continue // unknown schemes are ignored
		}
		m, _ := receivedDict.Get(scheme)
		i, ok := m.(httpsfv.Item)
		if !ok {
			return fmt.Errorf("received Content-Digest header is malformed")
		}
		b, ok := i.Value.([]byte)
		if !ok {
			return fmt.Errorf("non-byte string in received Content-Digest header")
		}
		if !bytes.Equal(raw, b) {
			return fmt.Errorf("digest mismatch for scheme %s", scheme)
		}
	}
	return nil
}
