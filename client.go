package httpsign

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Client represents an HTTP client that optionally signs requests and optionally verifies responses.
// The Signer may be nil to avoid signing. Similarly, if both Verifier and fetchVerifier are nil, no verification takes place.
// The fetchVerifier callback allows to generate a Verifier based on the particular response.
// Either Verifier or fetchVerifier may be specified, but not both.
// The client embeds an http.Client, which in most cases can be http.DefaultClient.
type Client struct {
	config ClientConfig
	client http.Client
}

// NewClient constructs a new client, with the flexibility of including a custom http.Client.
func NewClient(client http.Client, config *ClientConfig) *Client {
	return &Client{config: *config, client: client}
}

// NewDefaultClient constructs a new client, based on the http.DefaultClient.
func NewDefaultClient(config *ClientConfig) *Client {
	return NewClient(*http.DefaultClient, config)
}

func validateClient(c *Client) error {
	if c == nil {
		return fmt.Errorf("nil client")
	}
	if (c.config.signer != nil || c.config.verifier != nil) && c.config.signatureName == "" {
		return fmt.Errorf("empty signature name")
	}
	if c.config.verifier != nil && c.config.fetchVerifier != nil {
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
	conf := c.config
	if conf.signer != nil {
		err := signClientRequest(req, conf)
		if err != nil {
			return nil, err
		}
	}

	// Send the request, receive response
	res, err := c.client.Do(req)
	if err != nil {
		return res, err
	}

	if conf.verifier != nil || conf.fetchVerifier != nil {
		err := verifyClientResponse(req, conf, res)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func verifyClientResponse(req *http.Request, conf ClientConfig, res *http.Response) error {
	var signatureName string
	var verifier *Verifier
	if conf.verifier != nil {
		signatureName = conf.signatureName
		verifier = conf.verifier
	} else if conf.fetchVerifier != nil {
		signatureName, verifier = conf.fetchVerifier(res, req)
		if verifier == nil {
			return fmt.Errorf("fetchVerifier returned a nil verifier")
		}
	}
	receivedContentDigest := res.Header.Get("Content-Digest")
	if conf.computeDigest &&
		res.Body != nil && receivedContentDigest != "" {
		// verify the header even if not explicitly required by verifier field list
		digest, err := GenerateContentDigest(&res.Body, conf.digestScheme)
		if err != nil {
			return err
		}
		if receivedContentDigest != digest {
			return fmt.Errorf("bad Content-Digest received")
		}
	}
	err := VerifyResponse(signatureName, *verifier, res)
	if err != nil {
		return err
	}
	return nil
}

func signClientRequest(req *http.Request, conf ClientConfig) error {
	if conf.computeDigest && conf.signer.fields.hasHeader("Content-Digest") &&
		req.Body != nil && req.Header.Get("Content-Digest") == "" {
		digest, err := GenerateContentDigest(&req.Body, conf.digestScheme)
		if err != nil {
			return err
		}
		req.Header.Add("Content-Digest", digest)
	}
	sigInput, sig, err := SignRequest(conf.signatureName, *conf.signer, req)
	if err != nil {
		return fmt.Errorf("failed to sign request: %v", err)
	}
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)
	return nil
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

// PostForm sends an HTTP POST, with data keys and values URL-encoded as the request body.
func (c *Client) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}
