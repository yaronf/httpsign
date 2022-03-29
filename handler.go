package httpsign

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
)

// WrapHandler wraps a server's HTTP request handler so that the incoming request is verified
// and the response is signed. Both operations are optional.
// Side effects: when signing, the wrapped handler adds a Signature and a Signature-input header. If the
// Content-Digest header is included in the list of signed components, it is generated and added to the response.
// Note: unlike the standard net.http behavior, for the "Content-Type" header to be signed,
// it should be created explicitly.
func WrapHandler(h http.Handler, config HandlerConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.fetchVerifier != nil {
			err := verifyServerRequest(r, config)
			if err != nil {
				config.reqNotVerified(w, r, config.logger, err)
				return
			}
		}
		wrapped := newWrappedResponseWriter(w, r, config) // and this includes response signature
		h.ServeHTTP(wrapped, r)
		if config.fetchSigner != nil {
			err := signServerResponse(wrapped, r, config)
			if err != nil {
				sigFailed(wrapped.ResponseWriter, r, config.logger, err)
				return
			}
		}
		err := finalizeResponseBody(wrapped)
		if err != nil {
			sigFailed(wrapped.ResponseWriter, r, config.logger, err)
			return
		}
	})
}

// This error case is not optional, as it's always a server bug
func sigFailed(w http.ResponseWriter, _ *http.Request, logger *log.Logger, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	if logger != nil {
		logger.Printf("Failed to sign response: %v\n", err)
	}
	_, _ = fmt.Fprintln(w, "Failed to sign response.") // For security reasons, error is not printed
}

func finalizeResponseBody(wrapped *wrappedResponseWriter) error {
	wrapped.ResponseWriter.WriteHeader(wrapped.status)
	if wrapped.body != nil {
		_, err := wrapped.ResponseWriter.Write(wrapped.body.Bytes())
		return err
	}
	return nil
}

func signServerResponse(wrapped *wrappedResponseWriter, r *http.Request, config HandlerConfig) error {
	if wrapped.Header().Get("Date") == "" {
		wrapped.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}

	response := http.Response{
		Status:           strconv.Itoa(wrapped.status),
		StatusCode:       wrapped.status,
		Proto:            r.Proto,
		ProtoMajor:       r.ProtoMajor,
		ProtoMinor:       r.ProtoMinor,
		Header:           wrapped.Header(),
		Body:             nil, // Not required for the signature
		ContentLength:    0,
		TransferEncoding: nil,
		Close:            false,
		Uncompressed:     false,
		Trailer:          nil,
		Request:          r,
		TLS:              nil,
	}
	if config.fetchSigner == nil {
		return fmt.Errorf("could not fetch a Signer")
	}
	sigName, signer := config.fetchSigner(response, r)
	if signer == nil {
		return fmt.Errorf("could not fetch a Signer, check key ID")
	}

	if signer.fields.hasHeader("Content-Digest") &&
		wrapped.body != nil && config.computeDigest && wrapped.Header().Get("Content-Digest") == "" {
		closer := io.NopCloser(bytes.NewReader(wrapped.body.Bytes()))
		digest, err := GenerateContentDigestHeader(&closer, config.digestSchemesSend)
		if err != nil {
			return err
		}
		wrapped.Header().Add("Content-Digest", digest)
	}

	signatureInput, signature, err := SignResponse(sigName, *signer, &response)
	if err != nil {
		return fmt.Errorf("failed to sign the response: %w", err)
	}
	wrapped.Header().Add("Signature-Input", signatureInput)
	wrapped.Header().Add("Signature", signature)
	return nil
}

type wrappedResponseWriter struct {
	http.ResponseWriter
	status      int
	body        *bytes.Buffer
	config      HandlerConfig
	wroteHeader bool
	r           *http.Request
}

func newWrappedResponseWriter(w http.ResponseWriter, r *http.Request, config HandlerConfig) *wrappedResponseWriter {
	return &wrappedResponseWriter{ResponseWriter: w, r: r, config: config}
}

func (w *wrappedResponseWriter) Write(p []byte) (n int, err error) {
	if !w.wroteHeader {
		w.status = http.StatusOK
	}
	w.wroteHeader = true
	if w.body == nil {
		w.body = new(bytes.Buffer)
	}
	return w.body.Write(p)
}

func (w *wrappedResponseWriter) WriteHeader(code int) {
	w.status = code
	w.wroteHeader = true
}

func verifyServerRequest(r *http.Request, config HandlerConfig) error {
	if config.fetchVerifier == nil {
		return fmt.Errorf("could not fetch a Verifier")
	}
	sigName, verifier := config.fetchVerifier(r)
	if verifier == nil {
		return fmt.Errorf("could not fetch a Verifier, check key ID")
	}
	details, err := RequestDetails(sigName, r)
	if err != nil {
		return err
	}
	if config.computeDigest && details.Fields.hasHeader("Content-Digest") { // if Content-Digest is signed
		receivedContentDigest := r.Header.Values("Content-Digest")
		if r.Body == nil && len(receivedContentDigest) > 0 {
			return fmt.Errorf("found Content-Digest but no message body")
		}
		err := ValidateContentDigestHeader(receivedContentDigest, &r.Body, config.digestSchemesRecv)
		if err != nil {
			return err
		}
	}
	return VerifyRequest(sigName, *verifier, r)
}
