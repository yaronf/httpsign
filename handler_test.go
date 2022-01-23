package httpsign

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
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

	res, err := http.Get(ts.URL)
	if err != nil {
		log.Fatal(err)
	}
	_, err = io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	if res.Status != "200 OK" {
		t.Errorf("Bad status returned")
	}

	verifier, err := NewHMACSHA256Verifier("key", bytes.Repeat([]byte{0}, 64), NewVerifyConfig(), *NewFields())
	_, err = VerifyResponse("sig1", *verifier, res)
	if err != nil {
		log.Fatal(err)
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

	// HTTP client code
	signer, _ := NewHMACSHA256Signer("key", bytes.Repeat([]byte{0x99}, 64), nil,
		*NewFields().AddHeader("content-type").AddQueryParam("pet").AddHeader("@method"))

	client := &http.Client{}
	body := `{"hello": "world"}`
	host := ts.URL // test server
	path := "/foo?param=value&pet=dog"
	req, _ := http.NewRequest("POST", "http://ignore.me", bufio.NewReader(strings.NewReader(body)))
	req.RequestURI = "" // the http package wants this field to be unset for client responses, instead...
	u, _ := url.Parse(host + path)
	req.URL = u
	req.Header.Set("Content-Type", "application/json")

	// Request is ready, sign it
	sigInput, sig, err := SignRequest("sig1", *signer, req)
	if err != nil {
		log.Fatalf("Failed to sign request: %v", err)
	}
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)

	// Send the request, receive response
	res, _ := client.Do(req)
	serverText, _ := io.ReadAll(res.Body)
	res.Body.Close()

	fmt.Println("Status: ", res.Status)
	fmt.Println("Server sent: ", string(serverText))
	// output: Status:  200 OK
	//Server sent:  Hey client, your message verified just fine
}

func ExampleWrapHandler_serverSigns() {
	// Callback to let the server locate its verification key and configuration
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
	res, err := http.Get(ts.URL)
	if err != nil {
		log.Fatal(err)
	}
	_, err = io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	res.Body.Close()

	verifier, _ := NewHMACSHA256Verifier("key", bytes.Repeat([]byte{0}, 64), NewVerifyConfig(), *NewFields())
	verified, _ := VerifyResponse("sig1", *verifier, res)

	fmt.Println("verified: ", verified)
	// output: verified:  true
}
