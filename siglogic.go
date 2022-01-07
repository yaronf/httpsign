package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"
)

func signMessage(config Config, signatureName string, signer Signer, parsedMessage parsedMessage, fields []string) (string, string, error) {
	sigParams := generateSigParams(config, signer.keyId, signer.alg, fields)
	sigInputHeader := fmt.Sprintf("%s=%s", signatureName, sigParams)
	signatureInput, err := generateSignatureInput(parsedMessage, fields, sigParams)
	if err != nil {
		return "", "", err
	}
	signature, err := generateSignature(signatureName, signer, signatureInput)
	if err != nil {
		return "", "", err
	}
	return sigInputHeader, signature, nil
}

func generateSignature(name string, signer Signer, input string) (string, error) {
	raw, err := signer.sign([]byte(input))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s=:%s:", name, base64.StdEncoding.EncodeToString(raw)), nil // TODO
}

func generateSignatureInput(message parsedMessage, fields []string, params string) (string, error) {
	mf, err := matchFields(message.components, fields)
	if err != nil {
		return "", err
	}
	inp := ""
	for _, c := range mf {
		inp += fmt.Sprintf("\"%s\": %s\n", c.name, c.value)
	}
	inp += fmt.Sprintf("\"%s\": %s", "@signature-params", params)
	log.Println("Sig input:")
	log.Println(inp)
	return inp, nil
}

func generateSigParams(config Config, keyId, alg string, fields []string) string {
	var sp string
	if len(fields) == 0 {
		sp = "();"
	} else {
		sp = "(" + fmt.Sprintf("\"%s\"", fields[0])
		for i := 1; i < len(fields); i++ {
			sp += fmt.Sprintf(" \"%s\"", fields[i])
		}
		sp += ");"
	}
	var createdTime int64
	if config.FakeCreated != 0 {
		createdTime = config.FakeCreated
	} else {
		createdTime = time.Now().Unix()
	}
	if config.SignCreated {
		sp += fmt.Sprintf("created=%d;", createdTime)
	}
	if config.SignAlg {
		sp += fmt.Sprintf("alg=\"%s\";", alg)
	}
	sp += fmt.Sprintf("keyid=\"%s\"", keyId)
	return sp
}

func SignRequest(config Config, signatureName string, signer Signer, req *http.Request, fields []string) (string, string, error) {
	parsedMessage := ParseRequest(req)
	return signMessage(config, signatureName, signer, parsedMessage, fields)
}

func SignResponse(config Config, signatureName string, signer Signer, res *http.Response, fields []string) (string, string, error) {
	parsedMessage := ParseResponse(res)
	return signMessage(config, signatureName, signer, parsedMessage, fields)
}
