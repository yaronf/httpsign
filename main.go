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
	signer, err := NewHMACSHA256Signer("key1", []byte("01234567890123456789012345678901"))
	if err != nil {
		log.Fatal("Could not create signer: ", err)
	}
	sigInput, sig, err := SignResponse("sig1", *signer, res, fields)
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
