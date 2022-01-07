package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	res, err := readResponse()
	if err != nil {
		log.Fatal(err)
	}
	// fields := []string{"@method", "@authority", "content-type", "cache-control"}
	fields := []string{"@status", "content-type"}
	sigInput, sig, err := SignResponse("key1", "sig1", "hmac-sha256", res, fields)
	if err != nil {
		log.Fatal("Could not sign: ", err)
	}
	fmt.Println("Signature Params: ", sigInput)
	fmt.Println("Signature: ", sig)
}

func readRequest() (*http.Request, error) {
	in := bufio.NewReader(os.Stdin)
	req, err := http.ReadRequest(in)
	return req, err
}

func readResponse() (*http.Response, error) {
	in := bufio.NewReader(os.Stdin)
	res, err := http.ReadResponse(in, nil)
	return res, err
}
