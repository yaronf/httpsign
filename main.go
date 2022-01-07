package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	config := NewConfig()
	config.SignAlg = false
	config.FakeCreated = 1618884475
	log.Print("Config: ", config)

	req, err := readRequest()
	if err != nil {
		log.Fatal(err)
	}
	fields := []string{"@authority", "date", "content-type"}
	// fields := []string{"@status", "content-type"}
	// Key from draft's test cases, Appendix B
	key, err := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
	if err != nil {
		log.Fatal("Failed to decode key: ", err)
	}
	signer, err := NewHMACSHA256Signer("test-shared-secret", key)
	if err != nil {
		log.Fatal("Could not create signer: ", err)
	}
	sigInput, sig, err := SignRequest(config, "sig1", *signer, req, fields)
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
