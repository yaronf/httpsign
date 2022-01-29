package httpsign

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// WrapHandler wraps a server's HTTP request handler so that the incoming request is verified
// and the response is signed. Both operations are optional. If config is nil, the default
// configuration is applied: requests are verified and responses are signed.
// Note: unlike the standard net.http behavior, if you want the "Content-Type" header to be signed,
// you should specify it explicitly.
func WrapHandler(h http.Handler, config *HandlerConfig) http.Handler {
	if config == nil {
		config = NewHandlerConfig()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.verifyRequest {
			if !verifyServerRequest(w, r, config) {
				return
			}
		}
		wrapped := newWrappedResponseWriter(w, r, config) // and this includes response signature
		h.ServeHTTP(wrapped, r)
		if !wrapped.wroteBody { // Body-less responses are rare but possible
			if config.signResponse {
				_ = signServerResponse(wrapped, r, config) // failures are handled by call
			}
		}

	})
}

// This error case is not optional, as it's always a server bug
func sigFailed(w http.ResponseWriter, _ *http.Request, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = fmt.Fprintln(w, "Failed to sign response: "+err.Error())
}

// This needs to happen exactly at the point when the response headers (other than status!) had been written,
// but not yet the body, so that signature headers can be added.
func signServerResponse(wrapped *wrappedResponseWriter, r *http.Request, config *HandlerConfig) (success bool) {
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
		sigFailed(wrapped.ResponseWriter, r, fmt.Errorf("could not fetch a Signer"))
		return false
	}
	sigName, signer := config.fetchSigner(response, r)
	if signer == nil {
		sigFailed(wrapped.ResponseWriter, r, fmt.Errorf("could not fetch a Signer, check key ID"))
		return false
	}
	signatureInput, signature, err := SignResponse(sigName, *signer, &response)
	if err != nil {
		sigFailed(wrapped.ResponseWriter, r, fmt.Errorf("failed to sign the response: %w", err))
		return false
	}
	wrapped.Header().Add("Signature-Input", signatureInput)
	wrapped.Header().Add("Signature", signature)
	return true
}

type wrappedResponseWriter struct {
	http.ResponseWriter
	status       int
	wroteHeader  bool
	wroteBody    bool
	ignoreWrites bool
	config       *HandlerConfig
	r            *http.Request
}

func newWrappedResponseWriter(w http.ResponseWriter, r *http.Request, config *HandlerConfig) *wrappedResponseWriter {
	return &wrappedResponseWriter{ResponseWriter: w, r: r, config: config}
}

func (w *wrappedResponseWriter) Status() int {
	return w.status
}

func (w *wrappedResponseWriter) Write(p []byte) (n int, err error) {
	if !w.wroteBody {
		w.wroteBody = true
		if w.config.signResponse {
			if !signServerResponse(w, w.r, w.config) {
				w.ignoreWrites = true
				return 0, fmt.Errorf("failed to sign response headers")
			}
		}
		if !w.wroteHeader {
			w.ResponseWriter.WriteHeader(http.StatusOK)
		} else {
			w.ResponseWriter.WriteHeader(w.status)
		}
		w.wroteHeader = true
	}
	w.wroteBody = true
	if !w.ignoreWrites {
		return w.ResponseWriter.Write(p)
	}
	return len(p), nil // write is silently ignored
}

func (w *wrappedResponseWriter) WriteHeader(code int) {
	w.status = code
	w.wroteHeader = true
}

func verifyServerRequest(w http.ResponseWriter, r *http.Request, config *HandlerConfig) bool {
	if config.fetchVerifier == nil {
		config.reqNotVerified(w, r, fmt.Errorf("could not fetch a Verifier"))
		return false
	}
	sigName, verifier := config.fetchVerifier(r)
	if verifier == nil {
		config.reqNotVerified(w, r, fmt.Errorf("could not fetch a Verifier, check key ID"))
		return false
	}
	err := VerifyRequest(sigName, *verifier, r)
	if err != nil {
		config.reqNotVerified(w, r, err)
		return false
	}
	return true
}
