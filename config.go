package httpsign

import (
	"fmt"
	"net/http"
)

// SignConfig contains additional configuration for the signer.
type SignConfig struct {
	signAlg         bool
	signCreated     bool
	fakeCreated     int64
	requestResponse struct{ name, signature string }
}

// NewSignConfig generates a default configuration.
func NewSignConfig() *SignConfig {
	return &SignConfig{
		signAlg:     true,
		signCreated: true,
		fakeCreated: 0,
	}
}

// SignAlg indicates that an "alg" signature parameters must be generated and signed (default: true).
func (c *SignConfig) SignAlg(b bool) *SignConfig {
	c.signAlg = b
	return c
}

// SignCreated indicates that a "created" signature parameters must be generated and signed (default: true).
func (c *SignConfig) SignCreated(b bool) *SignConfig {
	c.signCreated = b
	return c
}

// setFakeCreated indicates that the specified Unix timestamp must be used instead of the current time
// (default: 0, meaning use current time). Only used for testing.
func (c *SignConfig) setFakeCreated(ts int64) *SignConfig {
	c.fakeCreated = ts
	return c
}

// SetRequestResponse allows the server to indicate signature name and signature that
// it had received from a client and include it in the signature input.
func (c *SignConfig) SetRequestResponse(name, signature string) *SignConfig {
	// TODO RequestResponse
	c.requestResponse = struct{ name, signature string }{name, signature}
	return c
}

// VerifyConfig contains additional configuration for the verifier.
type VerifyConfig struct {
}

// NewVerifyConfig generates a default configuration.
func NewVerifyConfig() *VerifyConfig {
	return &VerifyConfig{
		// TODO populate VerifyConfig
	}
}

// HandlerConfig contains additional configuration for the HTTP message handler wrapper.
type HandlerConfig struct {
	verifyRequest  bool
	signResponse   bool
	reqNotVerified func(w http.ResponseWriter, r *http.Request, err error)
	sigFailed      func(w http.ResponseWriter, r *http.Request, err error)
	fetchVerifier  func(r *http.Request) (sigName string, verifier Verifier)
	fetchSigner    func(res http.Response, r *http.Request) (sigName string, signer Signer)
}

// NewHandlerConfig generates a default configuration. When verification or respectively,
// signing is required, the respective "fetch" callback must be supplied.
func NewHandlerConfig() *HandlerConfig {
	return &HandlerConfig{
		verifyRequest:  true,
		signResponse:   true,
		reqNotVerified: defaultReqNotVerified,
		fetchVerifier:  nil,
		fetchSigner:    nil,
		sigFailed:      defaultSigFailed,
	}
}

// SetVerifyRequest indicates that all incoming requests for this handler must be verified.
func (h *HandlerConfig) SetVerifyRequest(b bool) *HandlerConfig {
	h.verifyRequest = b
	return h
}

// SetSignResponse indicates that all HTTP responses must be signed.
func (h *HandlerConfig) SetSignResponse(b bool) *HandlerConfig {
	h.signResponse = b
	return h
}

func defaultReqNotVerified(w http.ResponseWriter, _ *http.Request, err error) {
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = fmt.Fprintln(w, "Could not verify request signature: "+err.Error())
}

func defaultSigFailed(w http.ResponseWriter, _ *http.Request, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = fmt.Fprintln(w, "Failed to sign response: "+err.Error())
}

// SetReqNotVerified defines a callback to be called when a request fails to verify. The default
// callback sends a 401 status code with an error message that includes the error string.
func (h *HandlerConfig) SetReqNotVerified(f func(w http.ResponseWriter, r *http.Request, err error)) *HandlerConfig {
	h.reqNotVerified = f
	return h
}

// SetFetchVerifier defines a callback that looks at the incoming request and provided
// a Verifier structure. In the simplest case, the signature name is a constant, and the key ID
// and key value are fetched based on the sender's identity, which in turn is gleaned
// from a header or query parameter.
func (h *HandlerConfig) SetFetchVerifier(f func(r *http.Request) (sigName string, verifier Verifier)) *HandlerConfig {
	h.fetchVerifier = f
	return h
}

func (h *HandlerConfig) SetFetchSigner(f func(res http.Response, r *http.Request) (sigName string, signer Signer)) *HandlerConfig {
	h.fetchSigner = f
	return h
}
