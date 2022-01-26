package httpsign_test

import (
	"bytes"
	"fmt"
	"github.com/yaronf/httpsign"
	"io"
	"net/http"
	"net/http/httptest"
)

func ExampleClient_Get() {
	// Set up a test server
	simpleHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "Hey client, you sent a signature with these parameters: %s\n",
			r.Header.Get("Signature-Input"))
	}
	ts := httptest.NewServer(http.HandlerFunc(simpleHandler))
	defer ts.Close()

	// Client code starts here
	// Create a signer and a wrapped HTTP client (we set SignCreated to false to make the response deterministic,
	// don't do that in production.)
	signer, _ := httpsign.NewHMACSHA256Signer("key1", bytes.Repeat([]byte{1}, 64),
		httpsign.NewSignConfig().SignCreated(false), httpsign.HeaderList([]string{"@method"}))
	client := httpsign.NewDefaultClient("sig22", signer, nil, nil) // sign, don't verify

	// Send an HTTP GET, get response -- signing and verification happen behind the scenes
	res, _ := client.Get(ts.URL)

	// Read the response
	serverText, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()

	fmt.Println("Server sent: ", string(serverText))
	// Output: Server sent:  Hey client, you sent a signature with these parameters: sig22=("@method");alg="hmac-sha256";keyid="key1"
}
