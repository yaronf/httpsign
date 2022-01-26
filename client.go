package httpsign

import (
	"fmt"
	"io"
	"net/http"
)

// Client represents an HTTP client that optionally signs requests and optionally verifies responses.
// The Signer may be nil to avoid signing, and so forth.
// The FetchVerifier callback allows to generate a Verifier based on the particular response.
// Either Verifier or FetchVerifier may be specified, but not both.
// The client embeds an http.Client, which may be http.DefaultClient or any other.
type Client struct {
	SignatuerName string
	Signer        *Signer
	Verifier      *Verifier
	FetchVerifier func(res *http.Response, req *http.Request) (sigName string, verifier *Verifier)
	http.Client
}

// NewClient constructs a new client, with the flexibility of including a custom http.Client.
func NewClient(sigName string, signer *Signer, verifier *Verifier, fetchVerifier func(res *http.Response, req *http.Request) (sigName string, verifier *Verifier), client http.Client) *Client {
	return &Client{SignatuerName: sigName, Signer: signer, Verifier: verifier, FetchVerifier: fetchVerifier, Client: client}
}

// NewDefaultClient constructs a new client, based on the http.DefaultClient.
func NewDefaultClient(sigName string, signer *Signer, verifier *Verifier, fetchVerifier func(res *http.Response, req *http.Request) (sigName string, verifier *Verifier)) *Client {
	return NewClient(sigName, signer, verifier, fetchVerifier, *http.DefaultClient)
}

func validateClient(c *Client) error {
	if c == nil {
		return fmt.Errorf("nil client")
	}
	if c.Verifier != nil && c.FetchVerifier != nil {
		return fmt.Errorf("at most one of \"Verifier\" and \"FetchVerifier\" must be set")
	}
	return nil
}

// Do sends an http.Request, with optional signing and/or verification. Errors may be produced by any of
// these operations.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if err := validateClient(c); err != nil {
		return nil, err
	}
	if c.Signer != nil {
		sigInput, sig, err := SignRequest(c.SignatuerName, *c.Signer, req)
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

	if c.Verifier != nil {
		err := VerifyResponse(c.SignatuerName, *c.Verifier, res)
		if err != nil {
			return nil, err
		}
	} else if c.FetchVerifier != nil {
		sigName, verifier := c.FetchVerifier(res, req)
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
