package httpsign_test

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/yaronf/httpsign"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
)

func ExampleWrapHandler_clientSigns() {
	// Note: client/server examples may fail in the Go Playground, https://github.com/golang/go/issues/45855
	// Callback to let the server locate its verifying key and configuration
	fetchVerifier := func(r *http.Request) (string, *httpsign.Verifier) {
		sigName := "sig1"
		verifier, _ := httpsign.NewHMACSHA256Verifier("key", bytes.Repeat([]byte{0x99}, 64), nil,
			httpsign.Headers("@method"))
		return sigName, verifier
	}

	// The basic handler (HTTP server) that gets wrapped
	simpleHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("bar", "baz")
		fmt.Fprintln(w, "Hey client, your message verified just fine")
	}

	// Configure the wrapper and set it up
	config := httpsign.NewHandlerConfig().SetFetchVerifier(fetchVerifier)
	ts := httptest.NewServer(httpsign.WrapHandler(http.HandlerFunc(simpleHandler), *config))
	defer ts.Close()

	// HTTP client code, with a signer
	signer, _ := httpsign.NewHMACSHA256Signer("key", bytes.Repeat([]byte{0x99}, 64), nil,
		*httpsign.NewFields().AddHeader("content-type").AddQueryParam("pet").AddHeader("@method"))

	client := httpsign.NewDefaultClient("sig1", signer, nil, nil)
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
	// Note: client/server examples may fail in the Go Playground, https://github.com/golang/go/issues/45855
	// Callback to let the server locate its signing key and configuration
	fetchSigner := func(res http.Response, r *http.Request) (string, *httpsign.Signer) {
		sigName := "sig1"
		signer, _ := httpsign.NewHMACSHA256Signer("key", bytes.Repeat([]byte{0}, 64), nil,
			httpsign.Headers("@status", "bar", "date", "content-type"))
		return sigName, signer
	}

	simpleHandler := func(w http.ResponseWriter, r *http.Request) { // this handler gets wrapped
		w.WriteHeader(200)
		w.Header().Set("bar", "some text here") // note: a single word in the header value would be interpreted is a trivial dictionary!
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "Hello, client")
	}

	// Configure the wrapper and set it up
	config := httpsign.NewHandlerConfig().SetFetchSigner(fetchSigner)
	ts := httptest.NewServer(httpsign.WrapHandler(http.HandlerFunc(simpleHandler), *config))
	defer ts.Close()

	// HTTP client code
	verifier, _ := httpsign.NewHMACSHA256Verifier("key", bytes.Repeat([]byte{0}, 64), httpsign.NewVerifyConfig(), *httpsign.NewFields())
	client := httpsign.NewDefaultClient("sig1", nil, verifier, nil)
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
