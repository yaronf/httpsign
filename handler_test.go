package httpsign

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_WrapHandler(t *testing.T) {
	fetchVerifier := func(r *http.Request) (string, *Verifier) {
		sigName := "sig1"
		verifier, _ := NewHMACSHA256Verifier("key", bytes.Repeat([]byte{1}, 64), nil,
			Headers("@method"))
		return sigName, verifier
	}

	fetchSigner := func(res http.Response, r *http.Request) (string, *Signer) {
		sigName := "sig1"
		signer, _ := NewHMACSHA256Signer("key", bytes.Repeat([]byte{0}, 64), nil,
			Headers("@status", "bar", "date"))
		return sigName, signer
	}

	simpleHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("bar", "baz and baz again")
		_, _ = fmt.Fprintln(w, "Hello, client")
		_, _ = fmt.Fprintln(w, "Hello again")
	}
	config := NewHandlerConfig().SetFetchVerifier(fetchVerifier).
		SetFetchSigner(fetchSigner)
	ts := httptest.NewServer(WrapHandler(http.HandlerFunc(simpleHandler), *config))
	defer ts.Close()

	signer, err := NewHMACSHA256Signer("key", bytes.Repeat([]byte{1}, 64), nil,
		Headers("@method"))
	assert.NoError(t, err)

	verifier, err := NewHMACSHA256Verifier("key", bytes.Repeat([]byte{0}, 64), NewVerifyConfig(), *NewFields())
	assert.NoError(t, err)
	client := NewDefaultClient("sig1", signer, verifier, nil)
	res, err := client.Get(ts.URL)
	assert.NoError(t, err)
	if res != nil {
		_, err = io.ReadAll(res.Body)
		_ = res.Body.Close()
		assert.NoError(t, err)

		assert.Equal(t, res.Status, "200 OK", "Bad status returned")
	}
}

// test various failures
func TestWrapHandlerServerSigns(t *testing.T) {
	serverSignsTestCase := func(t *testing.T, nilSigner, dontSignResponse, earlyExpires, noSigner, badKey, badAlgs, verifyRequest bool) {
		// Callback to let the server locate its signing key and configuration
		var signConfig *SignConfig
		if !earlyExpires {
			signConfig = nil
		} else {
			signConfig = NewSignConfig().SetExpires(2000)
		}
		fetchSigner := func(res http.Response, r *http.Request) (string, *Signer) {
			sigName := "sig1"
			signer, _ := NewHMACSHA256Signer("key", bytes.Repeat([]byte{0}, 64), signConfig,
				Headers("@status", "bar", "date"))
			return sigName, signer
		}
		badFetchSigner := func(res http.Response, r *http.Request) (string, *Signer) {
			return "just a name", nil
		}

		simpleHandler := func(w http.ResponseWriter, r *http.Request) { // this handler gets wrapped
			w.WriteHeader(200)
			w.Header().Set("bar", "baz me")
			_, _ = fmt.Fprintln(w, "Hello, client")
		}

		// Configure the wrapper and set it up
		var config *HandlerConfig
		if !nilSigner {
			if !noSigner {
				config = NewHandlerConfig().SetFetchSigner(fetchSigner)
			} else {
				config = NewHandlerConfig().SetFetchSigner(badFetchSigner)
			}

		} else {
			config = NewHandlerConfig().SetFetchSigner(nil)

		}
		if dontSignResponse {
			config = config.SetFetchSigner(nil)
		}
		if verifyRequest {
			serverVerifier, _ := NewHMACSHA256Verifier("key", bytes.Repeat([]byte{9}, 64), NewVerifyConfig(), *NewFields())
			config = config.SetFetchVerifier(func(r *http.Request) (sigName string, verifier *Verifier) {
				return "sig333", serverVerifier
			})
		}
		ts := httptest.NewServer(WrapHandler(http.HandlerFunc(simpleHandler), *config))
		defer ts.Close()

		// HTTP client code
		var key []byte
		if !badKey {
			key = bytes.Repeat([]byte{0}, 64)
		} else {
			key = bytes.Repeat([]byte{3}, 64)
		}
		verifyConfig := NewVerifyConfig()
		if badAlgs {
			verifyConfig = verifyConfig.SetAllowedAlgs([]string{"zuzu"})
		}
		verifier, _ := NewHMACSHA256Verifier("key", key, verifyConfig, *NewFields())

		client := NewDefaultClient("sig1", nil, verifier, nil)
		res, err := client.Get(ts.URL)
		if err == nil && res.StatusCode == 200 {
			t.Errorf("Surprise! Server sent 200 OK and signature validation was successful.")
		}
	}
	nilSigner := func(t *testing.T) {
		serverSignsTestCase(t, true, false, false, false, false, false, false)
	}
	dontSignResponse := func(t *testing.T) {
		serverSignsTestCase(t, false, true, false, false, false, false, false)
	}
	earlyExpires := func(t *testing.T) {
		serverSignsTestCase(t, false, false, true, false, false, false, false)
	}
	noSigner := func(t *testing.T) {
		serverSignsTestCase(t, false, false, false, true, false, false, false)
	}
	badKey := func(t *testing.T) {
		serverSignsTestCase(t, false, false, false, false, true, false, false)
	}
	badAlgs := func(t *testing.T) {
		serverSignsTestCase(t, false, false, false, false, false, true, false)
	}
	failVerify := func(t *testing.T) {
		serverSignsTestCase(t, false, false, false, false, false, false, true)
	}
	t.Run("nil Signer", nilSigner)
	t.Run("don't sign response", dontSignResponse)
	t.Run("early expires field", earlyExpires)
	t.Run("bad fetch Signer", noSigner)
	t.Run("wrong verification key", badKey)
	t.Run("failed algorithm check", badAlgs)
	t.Run("failed request verification", failVerify)
}

func TestWrapHandlerServerFails(t *testing.T) { // non-default verify handler
	// Set up a test server
	simpleHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "Hey client, you sent a signature with these parameters: %s\n",
			r.Header.Get("Signature-Input"))
	}
	verifyFailed := func(w http.ResponseWriter, r *http.Request, logger *log.Logger, err error) {
		w.WriteHeader(599)
		if err == nil { // should not happen
			t.Errorf("Test failed, handler received an error: %v", err)
		}
		if logger != nil {
			log.Println("Could not verify request signature: " + err.Error())
		}
		_, _ = fmt.Fprintln(w, "Could not verify request signature")
	}
	fetchVerifier := func(r *http.Request) (string, *Verifier) {
		sigName := "sig1"
		verifier, _ := NewHMACSHA256Verifier("key", bytes.Repeat([]byte{0}, 64), nil,
			Headers("@method"))
		return sigName, verifier
	}
	config := NewHandlerConfig().SetReqNotVerified(verifyFailed).SetFetchVerifier(fetchVerifier)
	ts := httptest.NewServer(WrapHandler(http.HandlerFunc(simpleHandler), *config))
	defer ts.Close()

	// Client code starts here
	// Create a signer and a wrapped HTTP client (we set SignCreated to false to make the response deterministic,
	// don't do that in production.)
	signer, _ := NewHMACSHA256Signer("key1", bytes.Repeat([]byte{1}, 64),
		NewSignConfig().SignCreated(false), Headers("@method"))
	client := NewDefaultClient("sig22", signer, nil, nil) // sign, don't verify

	// Send an HTTP GET, get response -- signing and verification happen behind the scenes
	res, err := client.Get(ts.URL)
	assert.NoError(t, err, "Get failed")

	assert.Equal(t, res.StatusCode, 599, "Verification did not fail?")
}
