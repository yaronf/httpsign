package httpsign

import (
	"bufio"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

var http1 = `POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Cache-Control: max-age=60
Cache-Control:    must-revalidate
Content-Length: 18

{"hello": "world"}
`

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
				req: (func() *http.Request {
					in := strings.NewReader(http1)
					req, _ := http.ReadRequest(bufio.NewReader(in))
					return req
				})(),
				fields: []string{"@authority", "date", "content-type"},
			},
			want:    "sig1=(\"@authority\" \"date\" \"content-type\");created=1618884475;keyid=\"test-shared-secret\"",
			want1:   "sig1=:fN3AMNGbx0V/cIEKkZOvLOoC3InI+lM2+gTv22x3ia8=:",
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
			if got1 != tt.want1 {
				t.Errorf("SignRequest() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestSignAndVerify(t *testing.T) {
	config := NewConfig().SignAlg(false).setFakeCreated(1618884475)
	signatureName := "sig1"
	key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
	signer, _ := NewHMACSHA256Signer("test-shared-secret", key)
	in := strings.NewReader(http1)
	req, _ := http.ReadRequest(bufio.NewReader(in))
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
