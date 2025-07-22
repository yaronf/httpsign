package httpsign

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// MessageDetails aggregates the details of a signed message, for a given signature
type MessageDetails struct {
	KeyID   string
	Alg     string
	Fields  Fields
	Created *time.Time
	Expires *time.Time
	Nonce   *string
	Tag     *string
}

// Message represents a parsed HTTP message ready for signature verification.
type Message struct {
	headers  http.Header
	trailers http.Header
	body     *io.ReadCloser

	method     string
	url        *url.URL
	authority  string
	scheme     string
	statusCode *int
	assocReq   *Message
}

// NewMessage constructs a new Message from the provided config.
func NewMessage(config *MessageConfig) (*Message, error) {
	if config == nil {
		config = NewMessageConfig()
	}

	hasRequest := config.method != ""
	hasResponse := config.statusCode != nil

	if !hasRequest && !hasResponse {
		return nil, fmt.Errorf("message config must have either method (for request) or status code (for response)")
	}

	if hasRequest && hasResponse {
		return nil, fmt.Errorf("message config cannot have both request and response fields set")
	}

	if hasRequest {
		if config.headers == nil {
			return nil, fmt.Errorf("request message must have headers")
		}
	}

	if hasResponse {
		if config.headers == nil {
			return nil, fmt.Errorf("response message must have headers")
		}
	}

	var assocReq *Message
	if config.assocReq != nil {
		method := config.assocReq.method
		u := config.assocReq.url
		headers := config.assocReq.headers
		authority := config.assocReq.authority
		scheme := config.assocReq.scheme
		if method == "" || u == nil || headers == nil || authority == "" || scheme == "" {
			return nil, fmt.Errorf("invalid associated request")
		}
		assocReq = &Message{
			method:    method,
			url:       u,
			headers:   headers,
			authority: authority,
			scheme:    scheme,
		}
	}

	return &Message{
		headers:    config.headers,
		trailers:   config.trailers,
		body:       config.body,
		method:     config.method,
		url:        config.url,
		authority:  config.authority,
		scheme:     config.scheme,
		statusCode: config.statusCode,
		assocReq:   assocReq,
	}, nil
}

// MessageConfig configures a Message for signature verification.
type MessageConfig struct {
	method    string
	url       *url.URL
	headers   http.Header
	trailers  http.Header
	body      *io.ReadCloser
	authority string
	scheme    string

	statusCode *int

	assocReq *MessageConfig
}

// NewMessageConfig returns a new MessageConfig.
func NewMessageConfig() *MessageConfig {
	return &MessageConfig{}
}

func (b *MessageConfig) WithMethod(method string) *MessageConfig {
	b.method = method
	return b
}

func (b *MessageConfig) WithURL(u *url.URL) *MessageConfig {
	b.url = u
	return b
}

func (b *MessageConfig) WithHeaders(headers http.Header) *MessageConfig {
	b.headers = headers
	return b
}

func (b *MessageConfig) WithTrailers(trailers http.Header) *MessageConfig {
	b.trailers = trailers
	return b
}

func (b *MessageConfig) WithBody(body *io.ReadCloser) *MessageConfig {
	b.body = body
	return b
}

func (b *MessageConfig) WithAuthority(authority string) *MessageConfig {
	b.authority = authority
	return b
}

func (b *MessageConfig) WithScheme(scheme string) *MessageConfig {
	b.scheme = scheme
	return b
}

func (b *MessageConfig) WithStatusCode(statusCode int) *MessageConfig {
	b.statusCode = &statusCode
	return b
}

func (b *MessageConfig) WithAssociatedRequest(method string, u *url.URL, headers http.Header, authority, scheme string) *MessageConfig {
	b.assocReq = &MessageConfig{
		method:    method,
		url:       u,
		headers:   headers,
		authority: authority,
		scheme:    scheme,
	}
	return b
}

func (b *MessageConfig) WithRequest(req *http.Request) *MessageConfig {
	if req == nil {
		return b
	}

	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}

	return b.
		WithMethod(req.Method).
		WithURL(req.URL).
		WithHeaders(req.Header).
		WithTrailers(req.Trailer).
		WithBody(&req.Body).
		WithAuthority(req.Host).
		WithScheme(scheme)
}

func (b *MessageConfig) WithResponse(res *http.Response, req *http.Request) *MessageConfig {
	if res == nil {
		return b
	}

	b = b.
		WithStatusCode(res.StatusCode).
		WithHeaders(res.Header).
		WithTrailers(res.Trailer).
		WithBody(&res.Body)

	if req != nil {
		scheme := "http"
		if req.TLS != nil {
			scheme = "https"
		}
		b = b.WithAssociatedRequest(req.Method, req.URL, req.Header, req.Host, scheme)
	}

	return b
}

// Verify verifies a signature on this message.
func (m *Message) Verify(signatureName string, verifier Verifier) (*MessageDetails, error) {
	_, psiSig, err := verifyDebug(signatureName, verifier, m)
	if err != nil {
		return nil, err
	}
	return signatureDetails(psiSig)
}
