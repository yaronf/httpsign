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

func Test_VerifyAndSign(t *testing.T) {
	fetchVerifier := func(r *http.Request) (string, Verifier) {
		sigName := "sig1"
		verifier, _ := NewHMACSHA256Verifier("key", bytes.Repeat([]byte{0}, 64), nil,
			HeaderList([]string{"@method"}))
		return sigName, *verifier
	}

	fetchSigner := func(res http.Response, r *http.Request) (string, Signer) {
		sigName := "sig1"
		signer, _ := NewHMACSHA256Signer("key", bytes.Repeat([]byte{0}, 64), nil,
			HeaderList([]string{"@status", "bar", "date"}))
		return sigName, *signer
	}

	simpleHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("bar", "baz")
		fmt.Fprintln(w, "Hello, client")
	}
	config := NewHandlerConfig().SetFetchVerifier(fetchVerifier).SetVerifyRequest(false).
		SetFetchSigner(fetchSigner)
	ts := httptest.NewServer(VerifyAndSign(http.HandlerFunc(simpleHandler), config))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		log.Fatal(err)
	}
	greeting, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Client received status: %s\n", res.Status)
	fmt.Printf("Client received headers: %s\n", res.Header)
	fmt.Printf("%s\n", greeting)
}
