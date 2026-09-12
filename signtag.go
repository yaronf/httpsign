package httpsign

import (
	"errors"
	"fmt"
	"net/http"
)

// ErrSignatureTagNotFound is returned by *DetailsByTag when no signature
// carries the requested tag parameter.
var ErrSignatureTagNotFound = errors.New("no signature with the given tag")

// ErrSignatureTagAmbiguous is returned by *DetailsByTag when more than one
// signature carries the requested tag parameter.
var ErrSignatureTagAmbiguous = errors.New("multiple signatures with the given tag")

// RequestDetailsByTag returns MessageDetails for the unique Signature whose
// Signature-Input tag equals tag. Matching uses parsed headers only (not trailers)
// and does not cryptographically verify. Returns ErrSignatureTagNotFound or
// ErrSignatureTagAmbiguous when the match count is not exactly one.
// Use details.Label with VerifyRequest after obtaining a Verifier (e.g. via details.KeyID).
func RequestDetailsByTag(req *http.Request, tag string) (*MessageDetails, error) {
	if req == nil {
		return nil, fmt.Errorf("nil request")
	}
	all, err := signatureDetailsListFromHeaders(req.Header)
	if err != nil {
		return nil, err
	}
	return detailsByTag(all, tag)
}

// ResponseDetailsByTag returns MessageDetails for the unique Signature whose
// Signature-Input tag equals tag. Matching uses parsed headers only (not trailers)
// and does not cryptographically verify. Returns ErrSignatureTagNotFound or
// ErrSignatureTagAmbiguous when the match count is not exactly one.
// Use details.Label with VerifyResponse after obtaining a Verifier (e.g. via details.KeyID).
func ResponseDetailsByTag(res *http.Response, tag string) (*MessageDetails, error) {
	if res == nil {
		return nil, fmt.Errorf("nil response")
	}
	all, err := signatureDetailsListFromHeaders(res.Header)
	if err != nil {
		return nil, err
	}
	return detailsByTag(all, tag)
}

// RequestDetailsListByTag returns MessageDetails for every Signature whose
// Signature-Input tag equals tag (possibly empty). Matching uses parsed headers
// only (not trailers) and does not cryptographically verify. Each result has Label set.
func RequestDetailsListByTag(req *http.Request, tag string) ([]*MessageDetails, error) {
	if req == nil {
		return nil, fmt.Errorf("nil request")
	}
	all, err := signatureDetailsListFromHeaders(req.Header)
	if err != nil {
		return nil, err
	}
	return detailsListByTag(all, tag), nil
}

// ResponseDetailsListByTag returns MessageDetails for every Signature whose
// Signature-Input tag equals tag (possibly empty). Matching uses parsed headers
// only (not trailers) and does not cryptographically verify. Each result has Label set.
func ResponseDetailsListByTag(res *http.Response, tag string) ([]*MessageDetails, error) {
	if res == nil {
		return nil, fmt.Errorf("nil response")
	}
	all, err := signatureDetailsListFromHeaders(res.Header)
	if err != nil {
		return nil, err
	}
	return detailsListByTag(all, tag), nil
}

func detailsListByTag(all []*MessageDetails, tag string) []*MessageDetails {
	var found []*MessageDetails
	for _, details := range all {
		if details.Tag != nil && *details.Tag == tag {
			found = append(found, details)
		}
	}
	return found
}

func detailsByTag(all []*MessageDetails, tag string) (*MessageDetails, error) {
	var match *MessageDetails
	n := 0
	for _, details := range all {
		if details.Tag == nil || *details.Tag != tag {
			continue
		}
		n++
		if n > 1 {
			return nil, fmt.Errorf("%w: %q", ErrSignatureTagAmbiguous, tag)
		}
		match = details
	}
	if n == 0 {
		return nil, fmt.Errorf("%w: %q", ErrSignatureTagNotFound, tag)
	}
	return match, nil
}
