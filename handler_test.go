package httpsign

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_WrapHandler(t *testing.T) {
	fetchVerifier := func(r *http.Request) (string, *Verifier) {
		sigName := "sig1"
		verifier, _ := NewHMACSHA256Verifier("key", bytes.Repeat([]byte{0}, 64), nil,
			HeaderList([]string{"@method"}))
		return sigName, verifier
	}

	fetchSigner := func(res http.Response, r *http.Request) (string, *Signer) {
		sigName := "sig1"
		signer, _ := NewHMACSHA256Signer("key", bytes.Repeat([]byte{0}, 64), nil,
			HeaderList([]string{"@status", "bar", "date"}))
		return sigName, signer
	}

	simpleHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("bar", "baz and baz again")
		fmt.Fprintln(w, "Hello, client")
		fmt.Fprintln(w, "Hello again")
	}
	config := NewHandlerConfig().SetFetchVerifier(fetchVerifier).SetVerifyRequest(false).
		SetFetchSigner(fetchSigner)
	ts := httptest.NewServer(WrapHandler(http.HandlerFunc(simpleHandler), config))
	defer ts.Close()

	verifier, err := NewHMACSHA256Verifier("key", bytes.Repeat([]byte{0}, 64), NewVerifyConfig(), *NewFields())
	if err != nil {
		t.Errorf("%v", err)
	}
	client := NewDefaultClient("sig1", nil, verifier, nil)
	res, err := client.Get(ts.URL)
	if err != nil {
		t.Errorf("%v", err)
	}
	if res != nil {
		_, err = io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Errorf("%v", err)
		}

		if res.Status != "200 OK" {
			t.Errorf("Bad status returned")
		}
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
				HeaderList([]string{"@status", "bar", "date"}))
			return sigName, signer
		}
		badFetchSigner := func(res http.Response, r *http.Request) (string, *Signer) {
			return "just a name", nil
		}

		simpleHandler := func(w http.ResponseWriter, r *http.Request) { // this handler gets wrapped
			w.WriteHeader(200)
			w.Header().Set("bar", "baz")
			fmt.Fprintln(w, "Hello, client")
		}

		// Configure the wrapper and set it up
		var config *HandlerConfig
		if !nilSigner {
			if !noSigner {
				config = NewHandlerConfig().SetVerifyRequest(false).SetFetchSigner(fetchSigner)
			} else {
				config = NewHandlerConfig().SetVerifyRequest(false).SetFetchSigner(badFetchSigner)
			}

		} else {
			config = NewHandlerConfig().SetVerifyRequest(false).SetFetchSigner(nil)

		}
		if dontSignResponse {
			config = config.SetSignResponse(false)
		}
		if verifyRequest {
			serverVerifier, _ := NewHMACSHA256Verifier("key", bytes.Repeat([]byte{9}, 64), NewVerifyConfig(), *NewFields())
			config = config.SetFetchVerifier(func(r *http.Request) (sigName string, verifier *Verifier) {
				return "sig333", serverVerifier
			})
			config = config.SetVerifyRequest(true) // override
		}
		ts := httptest.NewServer(WrapHandler(http.HandlerFunc(simpleHandler), config))
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
	verifyFailed := func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(599)
		if err == nil { // should not happen
			t.Errorf("Test failed, handler received an error: %v", err)
		}
		log.Println("Could not verify request signature: " + err.Error())
		_, _ = fmt.Fprintln(w, "Could not verify request signature")
	}
	fetchVerifier := func(r *http.Request) (string, *Verifier) {
		sigName := "sig1"
		verifier, _ := NewHMACSHA256Verifier("key", bytes.Repeat([]byte{0}, 64), nil,
			HeaderList([]string{"@method"}))
		return sigName, verifier
	}
	config := NewHandlerConfig().SetReqNotVerified(verifyFailed).SetFetchVerifier(fetchVerifier)
	ts := httptest.NewServer(WrapHandler(http.HandlerFunc(simpleHandler), config))
	defer ts.Close()

	// Client code starts here
	// Create a signer and a wrapped HTTP client (we set SignCreated to false to make the response deterministic,
	// don't do that in production.)
	signer, _ := NewHMACSHA256Signer("key1", bytes.Repeat([]byte{1}, 64),
		NewSignConfig().SignCreated(false), HeaderList([]string{"@method"}))
	client := NewDefaultClient("sig22", signer, nil, nil) // sign, don't verify

	// Send an HTTP GET, get response -- signing and verification happen behind the scenes
	res, err := client.Get(ts.URL)
	if err != nil {
		t.Errorf("Get failed: %s", err)
	}

	if res.StatusCode != 599 {
		t.Errorf("Verification did not fail?")
	}
}
