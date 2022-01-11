package httpsign

import (
	"bufio"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

var httpreq1 = `POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Cache-Control: max-age=60
Cache-Control:    must-revalidate
Content-Length: 18

{"hello": "world"}
`

var httpres1 = `HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
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

// To generate the private key: openssl genpkey -algorithm RSA-PSS -outform PEM -out priv-op.key

var rsaPSSPrvKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
rOjr9w349JooGXhOxbu8nOxX
-----END RSA PRIVATE KEY-----
`

// Workaround, from https://go.dev/play/p/fIz218Lj2L0. Credit: Ryan Castner.

var oidRsaPss = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}

func loadPrivateKey(pemEncodedPK string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemEncodedPK))
	if block == nil {
		return nil, errors.New("empty block")
	}

	// taken from crypto/x509/pkcs8.go
	type pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		// optional attributes omitted.
	}
	var privKey pkcs8
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		return nil, err
	}

	if privKey.Algo.Algorithm.Equal(oidRsaPss) {
		rsaPrivKey, err := x509.ParsePKCS1PrivateKey(privKey.PrivateKey)
		if err == nil {
			return rsaPrivKey, nil
		}
	}

	return nil, errors.New("unknown algorithm")
}

// This will work when crypto/x509 implements PKCS8 RSA-PSS keys
func parseRsaPrivateKeyFromPemStr(pemString string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, fmt.Errorf("cannot decode PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return k.(*rsa.PrivateKey), nil
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

func TestSignRequest(t *testing.T) {
	type args struct {
		config        Config
		signatureName string
		signer        Signer
		req           *http.Request
		fields        []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   string
		wantErr bool
	}{
		{
			name: "test case B.2.5",
			args: args{
				config:        NewConfig().SignAlg(false).setFakeCreated(1618884475),
				signatureName: "sig1",
				signer: (func() Signer {
					key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
					signer, _ := NewHMACSHA256Signer("test-shared-secret", key)
					return *signer
				})(),
				req:    readRequest(httpreq1),
				fields: []string{"@authority", "date", "content-type"},
			},
			want:    "sig1=(\"@authority\" \"date\" \"content-type\");created=1618884475;keyid=\"test-shared-secret\"",
			want1:   "sig1=:fN3AMNGbx0V/cIEKkZOvLOoC3InI+lM2+gTv22x3ia8=:",
			wantErr: false,
		},
		{
			name: "test case B.2.1",
			args: args{
				config:        NewConfig().SignAlg(false).setFakeCreated(1618884475),
				signatureName: "sig1",
				signer: (func() Signer {
					prvKey, err := loadPrivateKey(rsaPSSPrvKey)
					if err != nil {
						t.Errorf("cannot parse private key: %v", err)
					}
					signer, _ := NewRSAPSSSigner("test-key-rsa-pss", prvKey.(*rsa.PrivateKey))
					return *signer
				})(),
				req:    readRequest(httpreq1),
				fields: []string{},
			},
			want:    "sig1=();created=1618884475;keyid=\"test-key-rsa-pss\"",
			want1:   "",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := SignRequest(tt.args.config, tt.args.signatureName, tt.args.signer, tt.args.req, tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SignRequest() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 && tt.want1 != "" { // some signatures are non-deterministic
				t.Errorf("SignRequest() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func readRequest(s string) *http.Request {
	in := strings.NewReader(s)
	req, _ := http.ReadRequest(bufio.NewReader(in))
	return req
}

func readResponse(s string) *http.Response {
	in := strings.NewReader(s)
	res, _ := http.ReadResponse(bufio.NewReader(in), nil)
	return res
}

func TestSignAndVerifyHMAC(t *testing.T) {
	config := NewConfig().SignAlg(false).setFakeCreated(1618884475)
	signatureName := "sig1"
	key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
	signer, _ := NewHMACSHA256Signer("test-shared-secret", key)
	req := readRequest(httpreq1)
	fields := []string{"@authority", "date", "content-type"}
	sigInput, sig, _ := SignRequest(config, signatureName, *signer, req, fields)
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)
	verifier, err := NewHMACSHA256Verifier("test-shared-secret", key)
	if err != nil {
		t.Errorf("could not generate verifier: %s", err)
	}
	verified, err := VerifyRequest(signatureName, *verifier, req, fields)
	if err != nil {
		t.Errorf("verification error: %s", err)
	}
	if !verified {
		t.Errorf("message did not pass verification")
	}
}

func TestSignAndVerifyResponseHMAC(t *testing.T) {
	config := NewConfig()
	signatureName := "sigres"
	key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
	signer, _ := NewHMACSHA256Signer("test-shared-secret", key)
	res := readResponse(httpres1)
	fields := []string{"@status", "date", "content-type"}
	sigInput, sig, err := SignResponse(config, signatureName, *signer, res, fields)

	res2 := readResponse(httpres1)
	res2.Header.Add("Signature", sig)
	res2.Header.Add("Signature-Input", sigInput)
	verifier, err := NewHMACSHA256Verifier("test-shared-secret", key)
	if err != nil {
		t.Errorf("could not generate verifier: %s", err)
	}
	verified, err := VerifyResponse(signatureName, *verifier, res2, fields)
	if err != nil {
		t.Errorf("verification error: %s", err)
	}
	if !verified {
		t.Errorf("message did not pass verification")
	}
}

func TestSignAndVerifyRSAPSS(t *testing.T) {
	config := NewConfig().SignAlg(false).setFakeCreated(1618884475)
	signatureName := "sig1"
	prvKey, err := loadPrivateKey(rsaPSSPrvKey)
	if err != nil {
		t.Errorf("cannot read private key")
	}
	signer, _ := NewRSAPSSSigner("test-key-rsa-pss", prvKey.(*rsa.PrivateKey))
	req := readRequest(httpreq1)
	fields := []string{"@authority", "date", "content-type"}
	sigInput, sig, _ := SignRequest(config, signatureName, *signer, req, fields)
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)
	pubKey, err := parseRsaPublicKeyFromPemStr(rsaPSSPubKey)
	if err != nil {
		t.Errorf("cannot read public key: %v", err)
	}
	verifier, err := NewRSAPSSVerifier("test-key-rsa-pss", pubKey)
	if err != nil {
		t.Errorf("could not generate verifier: %s", err)
	}
	verified, err := VerifyRequest(signatureName, *verifier, req, fields)
	if err != nil {
		t.Errorf("verification error: %s", err)
	}
	if !verified {
		t.Errorf("message did not pass verification")
	}
}

func TestSignResponse(t *testing.T) {
	type args struct {
		config        Config
		signatureName string
		signer        Signer
		res           *http.Response
		fields        []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   string
		wantErr bool
	}{
		{
			name: "test response with HMAC",
			args: args{
				config:        NewConfig().setFakeCreated(1618889999),
				signatureName: "sig1",
				signer: (func() Signer {
					key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
					signer, _ := NewHMACSHA256Signer("test-shared-secret", key)
					return *signer
				})(),
				res:    readResponse(httpres1),
				fields: []string{"@status", "date", "content-type"},
			},
			want:    "sig1=(\"@status\" \"date\" \"content-type\");created=1618889999;alg=\"hmac-sha256\";keyid=\"test-shared-secret\"",
			want1:   "sig1=:5s7SCXZBsy7g/xqoFjVy+WWvWi4bb3G7bQoE+blEyz4=:",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := SignResponse(tt.args.config, tt.args.signatureName, tt.args.signer, tt.args.res, tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SignResponse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("SignResponse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
