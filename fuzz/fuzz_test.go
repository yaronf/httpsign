package main

import "github.com/yaronf/httpsign"

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func readRequest(s string) *http.Request {
	in := strings.NewReader(s)
	req, err := http.ReadRequest(bufio.NewReader(in))
	if err != nil {
		fmt.Println("read req: ", err)
	}
	return req
}

var httpreq1pssMinimal = `POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
Content-Length: 18

{"hello": "world"}
`

var rsaPSSPubKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----
`

func makeRSAVerifier(t *testing.F, fields httpsign.Fields) httpsign.Verifier {
	return (func() httpsign.Verifier {
		pubKey, err := parseRsaPublicKeyFromPemStr(rsaPSSPubKey)
		if err != nil {
			t.Errorf("cannot parse public key: %v", err)
		}
		verifier, _ := httpsign.NewRSAPSSVerifier("test-key-rsa-pss", pubKey, httpsign.NewVerifyConfig().SetVerifyCreated(false), fields)
		return *verifier
	})()
}

func parseRsaPublicKeyFromPemStr(pemString string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, fmt.Errorf("cannot decode PEM")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return k.(*rsa.PublicKey), nil
}

type inputs struct {
	sigInput, sig string
}

func FuzzHelloWorld(f *testing.F) {
	testcases := []inputs{
		{
			"sig-b21=();created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"b3k2pp5k7z-50gnwp.yemd\"",
			"sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:",
		},
	}
	for _, tc := range testcases {
		f.Add(tc.sigInput, tc.sig) // Use f.Add to provide a seed corpus
	}
	f.Fuzz(func(t *testing.T, sigInput, sig string) {
		req := readRequest(httpreq1pssMinimal)
		if req != nil {
			req.Header.Set("Signature-Input", sigInput)
			req.Header.Set("Signature", sig)
		}

		sigName := "sig-b21"
		verifier := makeRSAVerifier(f, *httpsign.NewFields())
		_ = httpsign.VerifyRequest(sigName, verifier, req)
		// only report panics
	})
}
