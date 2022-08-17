package httpsign

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// SignConfig contains additional configuration for the signer.
type SignConfig struct {
	signAlg     bool
	signCreated bool
	fakeCreated int64
	expires     int64
	nonce       string
	context     string
}

// NewSignConfig generates a default configuration.
func NewSignConfig() *SignConfig {
	return &SignConfig{
		signAlg:     true,
		signCreated: true,
		fakeCreated: 0,
		expires:     0,
		nonce:       "",
		context:     "", // we disallow an empty context
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

// SetExpires adds an "expires" parameter containing an expiration deadline, as Unix time.
// Default: 0 (do not add the parameter).
func (c *SignConfig) SetExpires(expires int64) *SignConfig {
	c.expires = expires
	return c
}

// SetNonce adds a "nonce" string parameter whose content should be unique per signed message.
// Default: empty string (do not add the parameter).
func (c *SignConfig) SetNonce(nonce string) *SignConfig {
	c.nonce = nonce
	return c
}

// SetContext adds a "context" string parameter that defines a per-application or per-protocol signature
// context, to mitigate cross-protocol attacks.
func (c *SignConfig) SetContext(ctx string) *SignConfig {
	c.context = ctx
	return c
}

// VerifyConfig contains additional configuration for the verifier.
type VerifyConfig struct {
	verifyCreated   bool
	notNewerThan    time.Duration
	notOlderThan    time.Duration
	allowedAlgs     []string
	rejectExpired   bool
	verifyKeyID     bool
	dateWithin      time.Duration
	allowedContexts []string
}

// SetNotNewerThan sets the window for messages that appear to be newer than the current time,
// which can only happen if clocks are out of sync. Default: 1,000 ms.
func (v *VerifyConfig) SetNotNewerThan(notNewerThan time.Duration) *VerifyConfig {
	v.notNewerThan = notNewerThan
	return v
}

// SetNotOlderThan sets the window for messages that are older than the current time,
// because of network latency. Default: 10,000 ms.
func (v *VerifyConfig) SetNotOlderThan(notOlderThan time.Duration) *VerifyConfig {
	v.notOlderThan = notOlderThan
	return v
}

// SetVerifyCreated indicates that the "created" parameter must be within some time window,
// defined by NotNewerThan and NotOlderThan. Default: true.
func (v *VerifyConfig) SetVerifyCreated(verifyCreated bool) *VerifyConfig {
	v.verifyCreated = verifyCreated
	return v
}

// SetRejectExpired indicates that expired messages (according to the "expires" parameter) must fail verification.
// Default: true.
func (v *VerifyConfig) SetRejectExpired(rejectExpired bool) *VerifyConfig {
	v.rejectExpired = rejectExpired
	return v
}

// SetAllowedAlgs defines the allowed values of the "alg" parameter.
// This is useful if the actual algorithm used in verification is taken from the message - not a recommended practice.
// Default: an empty list, signifying all values are accepted.
func (v *VerifyConfig) SetAllowedAlgs(allowedAlgs []string) *VerifyConfig {
	v.allowedAlgs = allowedAlgs
	return v
}

// SetVerifyKeyID defines how to verify the keyid parameter, if one exists. If this value is set,
// the signature verifies only if the value is the same as was specified in the Verifier structure.
// Default: true.
func (v *VerifyConfig) SetVerifyKeyID(verify bool) *VerifyConfig {
	v.verifyKeyID = verify
	return v
}

// SetVerifyDateWithin indicates that the Date header should be verified if it exists, and its value
// must be within a certain time duration (positive or negative) of the Created signature parameter.
// This verification is only available if the Created field itself is verified.
// Default: 0, meaning no verification of the Date header.
func (v *VerifyConfig) SetVerifyDateWithin(d time.Duration) *VerifyConfig {
	v.dateWithin = d
	return v
}

// SetAllowedContexts defines the allowed values of the "context" parameter.
// Default: an empty list, signifying all values are accepted.
func (v *VerifyConfig) SetAllowedContexts(allowedCtx []string) *VerifyConfig {
	v.allowedContexts = allowedCtx
	return v
}

// NewVerifyConfig generates a default configuration.
func NewVerifyConfig() *VerifyConfig {
	return &VerifyConfig{
		verifyCreated:   true,
		notNewerThan:    2 * time.Second,
		notOlderThan:    10 * time.Second,
		rejectExpired:   true,
		allowedAlgs:     []string{},
		verifyKeyID:     true,
		dateWithin:      0,   // meaning no constraint
		allowedContexts: nil, // no constraint
	}
}

// HandlerConfig contains additional configuration for the HTTP message handler wrapper.
// Either or both of fetchVerifier and fetchSigner may be nil for the corresponding operation
// to be skipped.
type HandlerConfig struct {
	reqNotVerified func(w http.ResponseWriter,
		r *http.Request, logger *log.Logger, err error)
	fetchVerifier     func(r *http.Request) (sigName string, verifier *Verifier)
	fetchSigner       func(res http.Response, r *http.Request) (sigName string, signer *Signer)
	logger            *log.Logger
	computeDigest     bool
	digestSchemesSend []string
	digestSchemesRecv []string
}

// NewHandlerConfig generates a default configuration. When verification or respectively,
// signing is required, the respective "fetch" callback must be supplied.
func NewHandlerConfig() *HandlerConfig {
	return &HandlerConfig{
		reqNotVerified:    defaultReqNotVerified,
		fetchVerifier:     nil,
		fetchSigner:       nil,
		logger:            log.New(os.Stderr, "httpsign: ", log.LstdFlags|log.Lmsgprefix),
		computeDigest:     true,
		digestSchemesSend: []string{DigestSha256},
		digestSchemesRecv: []string{DigestSha256, DigestSha512},
	}
}

func defaultReqNotVerified(w http.ResponseWriter, _ *http.Request, logger *log.Logger, err error) {
	w.WriteHeader(http.StatusUnauthorized)
	if err == nil { // should not happen
		_, _ = fmt.Fprintf(w, "Unknown error")
	} else {
		if logger != nil {
			logger.Println("Could not verify request signature: " + err.Error())
		}
		_, _ = fmt.Fprintln(w, "Could not verify request signature") // For security reasons, do not print error
	}
}

// SetReqNotVerified defines a callback to be called when a request fails to verify. The default
// callback sends an unsigned 401 status code with a generic error message. For production, you
// probably need to sign it.
func (h *HandlerConfig) SetReqNotVerified(f func(w http.ResponseWriter, r *http.Request, l *log.Logger,
	err error)) *HandlerConfig {
	h.reqNotVerified = f
	return h
}

// SetFetchVerifier defines a callback that looks at the incoming request and provides
// a Verifier structure. In the simplest case, the signature name is a constant, and the key ID
// and key value are fetched based on the sender's identity, which in turn is gleaned
// from a header or query parameter. If a Verifier cannot be determined, the function should return Verifier as nil.
func (h *HandlerConfig) SetFetchVerifier(f func(r *http.Request) (sigName string, verifier *Verifier)) *HandlerConfig {
	h.fetchVerifier = f
	return h
}

// SetFetchSigner defines a callback that looks at the incoming request and the response, just before it is sent,
// and provides
// a Signer structure. In the simplest case, the signature name is a constant, and the key ID
// and key value are fetched based on the sender's identity. To simplify this logic,
// it is recommended to use the request's ctx (Context) member
// to store this information. If a Signer cannot be determined, the function should return Signer as nil.
func (h *HandlerConfig) SetFetchSigner(f func(res http.Response, r *http.Request) (sigName string, signer *Signer)) *HandlerConfig {
	h.fetchSigner = f
	return h
}

// SetLogger defines a logger for cases where an error cannot be returned. The default logger prints to stderr.
// Set to nil to prevent logging.
func (h *HandlerConfig) SetLogger(l *log.Logger) *HandlerConfig {
	h.logger = l
	return h
}

// SetComputeDigest when set to its default value (true), this flag indicates that
// if the Content-Digest header is in the set of covered components but the header itself is missing,
// the header value will be computed
// and added to the message before sending it; conversely in received messages, if Content-Digest is covered, the digest
// will be computed and validated. Setting the flag to false inhibits this behavior.
func (h *HandlerConfig) SetComputeDigest(b bool) *HandlerConfig {
	h.computeDigest = b
	return h
}

// SetDigestSchemesSend defines the scheme(s) (cryptographic hash algorithms) to be used to generate the message digest.
// It only needs to be set if a Content-Digest header is signed. Default: DigestSha256
func (h *HandlerConfig) SetDigestSchemesSend(s []string) *HandlerConfig {
	h.digestSchemesSend = s
	return h
}

// SetDigestSchemesRecv defines the cryptographic algorithms to accept when receiving the
// Content-Digest header. Any recognized algorithm's digest must be correct, but the overall header is valid if at least
// one accepted digest is included. Default: DigestSha256, DigestSha512.
func (h *HandlerConfig) SetDigestSchemesRecv(s []string) *HandlerConfig {
	h.digestSchemesRecv = s
	return h
}

// ClientConfig contains additional configuration for the HTTP client-side wrapper.
// Signing and verification may either be skipped, independently.
type ClientConfig struct {
	signatureName     string
	signer            *Signer
	verifier          *Verifier
	fetchVerifier     func(res *http.Response, req *http.Request) (sigName string, verifier *Verifier)
	computeDigest     bool
	digestSchemesSend []string
	digestSchemesRecv []string
}

// NewClientConfig creates a new, default ClientConfig.
func NewClientConfig() *ClientConfig {
	return &ClientConfig{
		computeDigest:     true,
		digestSchemesSend: []string{DigestSha256},
		digestSchemesRecv: []string{DigestSha256, DigestSha512},
	}
}

// SetSignatureName sets the signature name to be used for signing or verification.
func (c *ClientConfig) SetSignatureName(s string) *ClientConfig {
	c.signatureName = s
	return c
}

// SetSigner defines a signer for outgoing requests.
func (c *ClientConfig) SetSigner(s *Signer) *ClientConfig {
	c.signer = s
	return c
}

// SetVerifier defines a verifier for incoming responses.
func (c *ClientConfig) SetVerifier(v *Verifier) *ClientConfig {
	c.verifier = v
	return c
}

// SetFetchVerifier defines a function that fetches a verifier which may be customized for the incoming response.
func (c *ClientConfig) SetFetchVerifier(fv func(res *http.Response, req *http.Request) (sigName string, verifier *Verifier)) *ClientConfig {
	c.fetchVerifier = fv
	return c
}

// SetComputeDigest when set to its default value (true), this flag indicates that
// if the Content-Digest header is in the set of covered components but the header itself is missing,
// the header value will be computed
// and added to the message before sending it; conversely in received messages, if Content-Digest is covered, the digest
// will be computed and validated. Setting the flag to false inhibits this behavior.
func (c *ClientConfig) SetComputeDigest(b bool) *ClientConfig {
	c.computeDigest = b
	return c
}

// SetDigestSchemesSend defines the cryptographic algorithms to use when generating the
// Content-Digest header. Default: DigestSha256.
func (c *ClientConfig) SetDigestSchemesSend(s []string) *ClientConfig {
	c.digestSchemesSend = s
	return c
}

// SetDigestSchemesRecv defines the cryptographic algorithms to accept when receiving the
// Content-Digest header. Any recognized algorithm's digest must be correct, but the overall header is valid if at least
// one accepted digest is included. Default: DigestSha256, DigestSha512.
func (c *ClientConfig) SetDigestSchemesRecv(s []string) *ClientConfig {
	c.digestSchemesRecv = s
	return c
}
