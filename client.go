package httpsign

import (
	"fmt"
	"io"
	"net/http"
)

// Client represents an HTTP client that optionally signs requests and optionally verifies responses.
// The signer may be nil to avoid signing, and so forth.
// The fetchVerifier callback allows to generate a verifier based on the particular response.
// Either verifier or fetchVerifier may be specified, but not both.
// The client embeds an http.Client, which may be http.DefaultClient or any other.
type Client struct {
	sigName       string
	signer        *Signer
	verifier      *Verifier
	fetchVerifier func(res *http.Response, req *http.Request) (sigName string, verifier *Verifier)
	http.Client
}

// NewClient constructs a new client, with the flexibility of including a custom http.Client.
func NewClient(sigName string, signer *Signer, verifier *Verifier, fetchVerifier func(res *http.Response, req *http.Request) (sigName string, verifier *Verifier), client http.Client) *Client {
	return &Client{sigName: sigName, signer: signer, verifier: verifier, fetchVerifier: fetchVerifier, Client: client}
}

// NewDefaultClient constructs a new client, based on the http.DefaultClient.
func NewDefaultClient(sigName string, signer *Signer, verifier *Verifier, fetchVerifier func(res *http.Response, req *http.Request) (sigName string, verifier *Verifier)) *Client {
	return NewClient(sigName, signer, verifier, fetchVerifier, *http.DefaultClient)
}

func validateClient(c *Client) error {
	if c == nil {
		return fmt.Errorf("nil client")
	}
	if c.verifier != nil && c.fetchVerifier != nil {
		return fmt.Errorf("at most one of \"verifier\" and \"fetchVerifier\" must be set")
	}
	return nil
}

// Do sends an http.Request, with optional signing and/or verification. Errors may be produced by any of
// these operations.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if err := validateClient(c); err != nil {
		return nil, err
	}
	if c.signer != nil {
		sigInput, sig, err := SignRequest(c.sigName, *c.signer, req)
		if err != nil {
			return nil, fmt.Errorf("failed to sign request: %v", err)
		}
		req.Header.Add("Signature", sig)
		req.Header.Add("Signature-Input", sigInput)
	}

	// Send the request, receive response
	res, err := c.Client.Do(req)
	if err != nil {
		return res, err
	}

	if c.verifier != nil {
		err := VerifyResponse(c.sigName, *c.verifier, res)
		if err != nil {
			return nil, err
		}
	} else if c.fetchVerifier != nil {
		sigName, verifier := c.fetchVerifier(res, req)
		if err != nil {
			return nil, err
		}
		err := VerifyResponse(sigName, *verifier, res)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

// Get sends an HTTP GET, a wrapper for Do.
func (c *Client) Get(url string) (res *http.Response, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Head sends an HTTP HEAD, a wrapper for Do.
func (c *Client) Head(url string) (res *http.Response, err error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post sends an HTTP POST, a wrapper for Do.
func (c *Client) Post(url, contentType string, body io.Reader) (res *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}
