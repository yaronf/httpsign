package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	res, err := readResponse()
	if err != nil {
		log.Fatal(err)
	}
	// fields := []string{"@method", "@authority", "content-type", "cache-control"}
	fields := []string{"@status", "content-type", "cache-control"}
	sigInput, sig, err := SignResponse("key1", "sig1", "hmac-sha256", res, fields)
	fmt.Println("Signature Input: ", sigInput)
	fmt.Println("Signature: ", sig)
}

func SignRequest(keyId, signatureName, alg string, req *http.Request, fields []string) (string, string, error) {
	parsedMessage := ParseRequest(req)
	return signMessage(keyId, signatureName, alg, parsedMessage, fields)
}

func signMessage(keyId, signatureName, alg string, parsedMessage parsedMessage, fields []string) (string, string, error) {
	_ = matchFields(parsedMessage.components, fields)
	sigParams := generateSigParams(keyId, fields)
	sigInputHeader := fmt.Sprintf("%s=%s", signatureName, sigParams)
	return sigInputHeader, "signature TBD", nil
}

func generateSigParams(keyId string, fields []string) string {
	var sp string
	if len(fields) == 0 {
		sp = "();"
	} else {
		sp = "(" + fmt.Sprintf("\"%s\"", fields[0])
		for _, f := range fields {
			sp += fmt.Sprintf(" \"%s\"", f)
		}
		sp += ");"
	}
	sp += fmt.Sprintf("created=%d;", time.Now().Unix()) +
		fmt.Sprintf("keyid=\"%s\"", keyId)
	return sp
}

func readRequest() (*http.Request, error) {
	in := bufio.NewReader(os.Stdin)
	req, err := http.ReadRequest(in)
	return req, err
}

func SignResponse(keyId, signatureName, alg string, res *http.Response, fields []string) (string, string, error) {
	parsedMessage := ParseResponse(res)
	return signMessage(keyId, signatureName, alg, parsedMessage, fields)
}

func readResponse() (*http.Response, error) {
	in := bufio.NewReader(os.Stdin)
	res, err := http.ReadResponse(in, nil)
	return res, err
}
