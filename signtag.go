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
	names, err := RequestSignatureNames(req, false)
	if err != nil {
		return nil, err
	}
	return detailsByTag(names, tag, func(name string) (*MessageDetails, error) {
		return RequestDetails(name, req)
	})
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
	names, err := ResponseSignatureNames(res, false)
	if err != nil {
		return nil, err
	}
	return detailsByTag(names, tag, func(name string) (*MessageDetails, error) {
		return ResponseDetails(name, res)
	})
}

// RequestDetailsListByTag returns MessageDetails for every Signature whose
// Signature-Input tag equals tag (possibly empty). Matching uses parsed headers
// only (not trailers) and does not cryptographically verify. Each result has Label set.
func RequestDetailsListByTag(req *http.Request, tag string) ([]*MessageDetails, error) {
	if req == nil {
		return nil, fmt.Errorf("nil request")
	}
	names, err := RequestSignatureNames(req, false)
	if err != nil {
		return nil, err
	}
	return detailsListByTag(names, tag, func(name string) (*MessageDetails, error) {
		return RequestDetails(name, req)
	})
}

// ResponseDetailsListByTag returns MessageDetails for every Signature whose
// Signature-Input tag equals tag (possibly empty). Matching uses parsed headers
// only (not trailers) and does not cryptographically verify. Each result has Label set.
func ResponseDetailsListByTag(res *http.Response, tag string) ([]*MessageDetails, error) {
	if res == nil {
		return nil, fmt.Errorf("nil response")
	}
	names, err := ResponseSignatureNames(res, false)
	if err != nil {
		return nil, err
	}
	return detailsListByTag(names, tag, func(name string) (*MessageDetails, error) {
		return ResponseDetails(name, res)
	})
}

func detailsListByTag(names []string, tag string, detailsFn func(string) (*MessageDetails, error)) ([]*MessageDetails, error) {
	var found []*MessageDetails
	for _, name := range names {
		details, err := detailsFn(name)
		if err != nil {
			return nil, fmt.Errorf("details for %q: %w", name, err)
		}
		if details.Tag != nil && *details.Tag == tag {
			found = append(found, details)
		}
	}
	return found, nil
}

func detailsByTag(names []string, tag string, detailsFn func(string) (*MessageDetails, error)) (*MessageDetails, error) {
	var match *MessageDetails
	n := 0
	for _, name := range names {
		details, err := detailsFn(name)
		if err != nil {
			return nil, fmt.Errorf("details for %q: %w", name, err)
		}
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
