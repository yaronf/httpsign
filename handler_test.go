package httpsign

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
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
		w.Header().Set("bar", "baz")
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

func ExampleWrapHandler_clientSigns() {
	// Callback to let the server locate its verifying key and configuration
	fetchVerifier := func(r *http.Request) (string, *Verifier) {
		sigName := "sig1"
		verifier, _ := NewHMACSHA256Verifier("key", bytes.Repeat([]byte{0x99}, 64), nil,
			HeaderList([]string{"@method"}))
		return sigName, verifier
	}

	// The basic handler (HTTP server) that gets wrapped
	simpleHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("bar", "baz")
		fmt.Fprintln(w, "Hey client, your message verified just fine")
	}

	// Configure the wrapper and set it up
	config := NewHandlerConfig().SetSignResponse(false).SetFetchVerifier(fetchVerifier)
	ts := httptest.NewServer(WrapHandler(http.HandlerFunc(simpleHandler), config))
	defer ts.Close()

	// HTTP client code, with a signer
	signer, _ := NewHMACSHA256Signer("key", bytes.Repeat([]byte{0x99}, 64), nil,
		*NewFields().AddHeader("content-type").AddQueryParam("pet").AddHeader("@method"))

	client := NewDefaultClient("sig1", signer, nil, nil)
	body := `{"hello": "world"}`
	host := ts.URL // test server
	path := "/foo?param=value&pet=dog"
	res, _ := client.Post(host+path, "application/json", bufio.NewReader(strings.NewReader(body)))

	serverText, _ := io.ReadAll(res.Body)
	res.Body.Close()

	fmt.Println("Status: ", res.Status)
	fmt.Println("Server sent: ", string(serverText))
	// output: Status:  200 OK
	//Server sent:  Hey client, your message verified just fine
}

func ExampleWrapHandler_serverSigns() {
	// Callback to let the server locate its signing key and configuration
	fetchSigner := func(res http.Response, r *http.Request) (string, *Signer) {
		sigName := "sig1"
		signer, _ := NewHMACSHA256Signer("key", bytes.Repeat([]byte{0}, 64), nil,
			HeaderList([]string{"@status", "bar", "date"}))
		return sigName, signer
	}

	simpleHandler := func(w http.ResponseWriter, r *http.Request) { // this handler gets wrapped
		w.WriteHeader(200)
		w.Header().Set("bar", "baz")
		fmt.Fprintln(w, "Hello, client")
	}

	// Configure the wrapper and set it up
	config := NewHandlerConfig().SetVerifyRequest(false).SetFetchSigner(fetchSigner)
	ts := httptest.NewServer(WrapHandler(http.HandlerFunc(simpleHandler), config))
	defer ts.Close()

	// HTTP client code
	verifier, _ := NewHMACSHA256Verifier("key", bytes.Repeat([]byte{0}, 64), NewVerifyConfig(), *NewFields())
	client := NewDefaultClient("sig1", nil, verifier, nil)
	res, err := client.Get(ts.URL)
	if err != nil {
		log.Fatal(err)
	}
	serverText, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	res.Body.Close()

	fmt.Println("Server sent: ", string(serverText))
	// output: Server sent:  Hello, client
}

// test various failures
func TestWrapHandlerServerSigns(t *testing.T) {
	serverSignsTestCase := func(t *testing.T, nilSigner, dontSignResponse, earlyExpires, noSigner, badKey, badAlgs bool) {
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
		_, err := client.Get(ts.URL)
		if err == nil {
			t.Errorf("Surprise! Signature validation was successful.")
		}
	}
	nilSigner := func(t *testing.T) {
		serverSignsTestCase(t, true, false, false, false, false, false)
	}
	dontSignResponse := func(t *testing.T) {
		serverSignsTestCase(t, false, true, false, false, false, false)
	}
	earlyExpires := func(t *testing.T) {
		serverSignsTestCase(t, false, false, true, false, false, false)
	}
	noSigner := func(t *testing.T) {
		serverSignsTestCase(t, false, false, false, true, false, false)
	}
	badKey := func(t *testing.T) {
		serverSignsTestCase(t, false, false, false, false, true, false)
	}
	badAlgs := func(t *testing.T) {
		serverSignsTestCase(t, false, false, false, false, false, true)
	}
	t.Run("nil signer", nilSigner)
	t.Run("don't sign response", dontSignResponse)
	t.Run("early expires field", earlyExpires)
	t.Run("bad fetch signer", noSigner)
	t.Run("wrong verification key", badKey)
	t.Run("failed algorithm check", badAlgs)
}
