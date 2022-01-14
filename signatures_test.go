package httpsign

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
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

var httpreq1pssMinimal = `POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Cache-Control: max-age=60
Cache-Control:    must-revalidate
Content-Length: 18
Signature-Input: sig1=();created=1618884475;keyid="test-key-rsa-pss";alg="rsa-pss-sha512"
Signature: sig1=:HWP69ZNiom9Obu1KIdqPPcu/C1a5ZUMBbqS/xwJECV8bhIQVmEAAAzz8LQPvtP1iFSxxluDO1KE9b8L+O64LEOvhwYdDctV5+E39Jy1eJiD7nYREBgxTpdUfzTO+Trath0vZdTylFlxK4H3l3s/cuFhnOCxmFYgEa+cw+StBRgY1JtafSFwNcZgLxVwialuH5VnqJS4JN8PHD91XLfkjMscTo4jmVMpFd3iLVe0hqVFl7MDt6TMkwIyVFnEZ7B/VIQofdShO+C/7MuupCSLVjQz5xA+Zs6Hw+W9ESD/6BuGs6LF1TcKLxW+5K+2zvDY/Cia34HNpRW5io7Iv9/b7iQ==:

{"hello": "world"}
`

var httpreq1pssSelective = `POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Cache-Control: max-age=60
Cache-Control:    must-revalidate
Content-Length: 18
Signature-Input: sig1=("@authority" "content-type");created=1618884475;keyid="test-key-rsa-pss"
Signature: sig1=:ik+OtGmM/kFqENDf9Plm8AmPtqtC7C9a+zYSaxr58b/E6h81ghJS3PcH+m1asiMp8yvccnO/RfaexnqanVB3C72WRNZN7skPTJmUVmoIeqZncdP2mlfxlLP6UbkrgYsk91NS6nwkKC6RRgLhBFqzP42oq8D2336OiQPDAo/04SxZt4Wx9nDGuy2SfZJUhsJqZyEWRk4204x7YEB3VxDAAlVgGt8ewilWbIKKTOKp3ymUeQIwptqYwv0l8mN404PPzRBTpB7+HpClyK4CNp+SVv46+6sHMfJU4taz10s/NoYRmYCGXyadzYYDj0BYnFdERB6NblI/AOWFGl5Axhhmjg==:

{"hello": "world"}
`

var httpreq1pssFull = `POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Cache-Control: max-age=60
Cache-Control:    must-revalidate
Content-Length: 18
Signature-Input: sig1=("date" "@method" "@path" "@query" "@authority" "content-type" "digest" "content-length");created=1618884475;keyid="test-key-rsa-pss"
Signature: sig1=:JuJnJMFGD4HMysAGsfOY6N5ZTZUknsQUdClNG51VezDgPUOW03QMe74vbIdndKwW1BBrHOHR3NzKGYZJ7X3ur23FMCdANe4VmKb3Rc1Q/5YxOO8p7KoyfVa4uUcMk5jB9KAn1M1MbgBnqwZkRWsbv8ocCqrnD85Kavr73lx51k1/gU8w673WT/oBtxPtAn1eFjUyIKyA+XD7kYph82I+ahvm0pSgDPagu917SlqUjeaQaNnlZzO03Iy1RZ5XpgbNeDLCqSLuZFVID80EohC2CQ1cL5svjslrlCNstd2JCLmhjL7xV3NYXerLim4bqUQGRgDwNJRnqobpS6C1NBns/Q==:

{"hello": "world"}
`

var httpreq1p256 = `POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Cache-Control: max-age=60
Cache-Control:    must-revalidate
Content-Length: 18
Signature-Input: sig1=("content-type" "digest" "content-length");created=1618884475;keyid="test-key-ecc-p256"
Signature: sig1=:n8RKXkj0iseWDmC6PNSQ1GX2R9650v+lhbb6rTGoSrSSx18zmn6fPOtBx48/WffYLO0n1RHHf9scvNGAgGq52Q==:

{"hello": "world"}
`

var rsaPubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyD6Hrh5mV16s/jQngCF1
IfpzLuJTraeqJFlNESsvbeNMcA4dQjU/LMX2XA3vyF7nOyleTisdmzFZb9TLoC1H
UkcEBb1lkEh0ecm6Kz6wI6imKloeoDoASlXpIa6vr5dT3hcfek15SDBkOgbfEJoe
UFvQZrBfIWFQt/fekPsfgSPT9FNw1Chi3+crmnEck8j2Nwoxi44O4jaVNbHm+CVM
/FJH7jPjD9SY5UdC1rpmG3iBopnZDwEYWzDmH4yjYVNTb4Uvmwr+vbe2FEoLz3U1
+utEJ8RA03EEzAEkUVyp7wYpyvM/FWXbRCSwY/ZBSvRjrPgnW8C908k5GvC8QLSs
OQIDAQAB
-----END PUBLIC KEY-----
`

var rsaPrvKey = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDIPoeuHmZXXqz+
NCeAIXUh+nMu4lOtp6okWU0RKy9t40xwDh1CNT8sxfZcDe/IXuc7KV5OKx2bMVlv
1MugLUdSRwQFvWWQSHR5yborPrAjqKYqWh6gOgBKVekhrq+vl1PeFx96TXlIMGQ6
Bt8Qmh5QW9BmsF8hYVC3996Q+x+BI9P0U3DUKGLf5yuacRyTyPY3CjGLjg7iNpU1
seb4JUz8UkfuM+MP1JjlR0LWumYbeIGimdkPARhbMOYfjKNhU1NvhS+bCv69t7YU
SgvPdTX660QnxEDTcQTMASRRXKnvBinK8z8VZdtEJLBj9kFK9GOs+CdbwL3TyTka
8LxAtKw5AgMBAAECggEBAKcW9mSmXUN+bt/XaTaTtIfb0o1GsghvpZubIKG45WTO
jBPc0zFR+RtFPONnhbQu7MgDJvwXIidDsJuOdzN7VM4lEAgyGDOjIf4WBFDdiGDY
837XoEKW43Mj6NsARv1ASu1BYjTNvOwt5RQ+c5gI4k6vrmBhv5+88nvwSzmzMoCw
h3ZLz4DfyOoBu7dqlnw9EttZuW7k1SXXW/cC5Sh90j8gZmYlNN76O1LsiCxZowCj
Ys5Qdm5tcNuV8jK3XIFE4uYyBRHx5+haNjgKeM8n8IEEPYhzqcYIAYWGRHSkTvGy
DxAb8AJBwuFCsFQz0oXyzVd8Mqz8RbqC7N50LdncCWECgYEA9zE9u/x8r7/De25U
FcDDLt63qkqDmSn1PMkwf1DdOj734fYWd8Ay2R5E43NJMQalcR7Q7++O5KOQOFUl
mpd79U9LO3b9FE0vR8xG81wushKy3xhHQdB2ucKliGwcYvcfgjWUoD7aKfrlHmNA
olj1/21tJQGotEGg9NpiinJaiT0CgYEAz2ENkkEH3ZXtMKr3DXoqLNU+er4pHzm1
cRxzpCNqNwZBlv0pxeIo6izH4TIrBPdIqSApUpZ0N+NgA0bjj0527GATGkGDgo+b
TZFAhOhg7bfUyLsbgL/zycnyQwDWw2fo5ei9Bb2pPqfeQgrgYE+ag+ucJrhJNymv
3gG6Vmdwhq0CgYEAr6rwwl2Ghqdy1o7rdqIMk4x3Xa+iogBtZYtcyb2/2hrRsmVe
Ri/yctXOAw3038BnZmKN/VVzaQzL+xyXoqswzn5Raqr+46SOiymi6mOCU85yC5WH
XkA1f4HSfYbHDZWtcK1/N/oytE628Md8MWOjPqiXPgtVxvQ03I0uJlFqAckCgYB6
w/yxwTez0MaqkftRCiofglnLdfmIF7S28l3vJFwDmPuJM/PfxoPsJXhqczWOagmk
vXpY/uJsF3nGVtfuBUhXpISKfZAp4XPR1pQ4WgzPjY01C7c7X+clZRy616tL4J66
RC5qUJ35joz/0cqEmXtibz9wmJYXRuFq7uDtt6ygvQKBgQCMopIJCcH5+DmbXmyw
J8fxjxp8YpkEoFMtloaJ7lWHkiCUSWYCbGlvG1Nb1CoVqOuMffGXAZKAU9cw7YA2
cJQuDUjlA0haDD4W3IibLGbANw414qqpqRmo5kM6aMpnShGsvxpp/0+XKrfcwgiC
Ufa6y08wtZ/O7ZCBBbJTY90uqA==
-----END PRIVATE KEY-----
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

var p256PubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWAO+Y/BP3c7Aw7dSWYGkuckwl/e6
H54D/P9uzXDjby0Frysdpcny/NL807iRVfVDDg+ctHhuRTzBwP+lwVdN2g==
-----END PUBLIC KEY-----
`

var p256PrvKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMLnTZwmWikcBCrKlXZVUjaq9jwsv22sy/P7yIIonkVwoAoGCCqGSM49
AwEHoUQDQgAEWAO+Y/BP3c7Aw7dSWYGkuckwl/e6H54D/P9uzXDjby0Frysdpcny
/NL807iRVfVDDg+ctHhuRTzBwP+lwVdN2g==
-----END EC PRIVATE KEY-----
`

var p256PubKey2 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----
`

var p256PrvKey2 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END EC PRIVATE KEY-----
`

// Workaround, from https://go.dev/play/p/fIz218Lj2L0. Credit: Ryan Castner.

var oidRsaPss = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}

func loadRSAPSSPrivateKey(pemEncodedPK string) (crypto.PrivateKey, error) {
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

// This will work for PSS when crypto/x509 implements PKCS8 RSA-PSS keys
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

func parseECPrivateKeyFromPemStr(pemString string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, fmt.Errorf("cannot decode PEM")
	}
	k, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func parseECPublicKeyFromPemStr(pemString string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, fmt.Errorf("cannot decode PEM")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return k.(*ecdsa.PublicKey), nil
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
			name: "test case B.2.1 (partial)",
			args: args{
				config:        NewConfig().SignAlg(false).setFakeCreated(1618884475),
				signatureName: "sig1",
				signer: (func() Signer {
					prvKey, err := loadRSAPSSPrivateKey(rsaPSSPrvKey)
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
	prvKey, err := loadRSAPSSPrivateKey(rsaPSSPrvKey)
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

func TestSignAndVerifyRSA(t *testing.T) {
	config := NewConfig().SignAlg(false).setFakeCreated(1618884475)
	signatureName := "sig1"
	prvKey, err := parseRsaPrivateKeyFromPemStr(rsaPrvKey)
	if err != nil {
		t.Errorf("cannot read private key")
	}
	signer, _ := NewRSASigner("test-key-rsa", prvKey)
	req := readRequest(httpreq1)
	fields := []string{"@authority", "date", "content-type"}
	sigInput, sig, _ := SignRequest(config, signatureName, *signer, req, fields)
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)
	pubKey, err := parseRsaPublicKeyFromPemStr(rsaPubKey)
	if err != nil {
		t.Errorf("cannot read public key: %v", err)
	}
	verifier, err := NewRSAVerifier("test-key-rsa", pubKey)
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

func TestSignAndVerifyP256(t *testing.T) {
	config := NewConfig().SignAlg(false).setFakeCreated(1618884475)
	signatureName := "sig1"
	prvKey, err := parseECPrivateKeyFromPemStr(p256PrvKey)
	if err != nil {
		t.Errorf("cannot read private key")
	}
	signer, _ := NewP256Signer("test-key-p256", prvKey)
	req := readRequest(httpreq1)
	fields := []string{"@authority", "date", "content-type"}
	sigInput, sig, _ := SignRequest(config, signatureName, *signer, req, fields)
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)
	pubKey, err := parseECPublicKeyFromPemStr(p256PubKey)
	if err != nil {
		t.Errorf("cannot read public key: %v", err)
	}
	verifier, err := NewP256Verifier("test-key-p256", pubKey)
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

func TestVerifyRequest(t *testing.T) {
	type args struct {
		signatureName string
		verifier      Verifier
		req           *http.Request
		fields        []string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "test case B.2.1",
			args: args{
				signatureName: "sig1",
				verifier: (func() Verifier {
					pubKey, err := parseRsaPublicKeyFromPemStr(rsaPSSPubKey)
					if err != nil {
						t.Errorf("cannot parse public key: %v", err)
					}
					verifier, _ := NewRSAPSSVerifier("test-key-rsa-pss", pubKey)
					return *verifier
				})(),
				req:    readRequest(httpreq1pssMinimal),
				fields: []string{},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "test case B.2.2",
			args: args{
				signatureName: "sig1",
				verifier: (func() Verifier {
					pubKey, err := parseRsaPublicKeyFromPemStr(rsaPSSPubKey)
					if err != nil {
						t.Errorf("cannot parse public key: %v", err)
					}
					verifier, _ := NewRSAPSSVerifier("test-key-rsa-pss", pubKey)
					return *verifier
				})(),
				req:    readRequest(httpreq1pssSelective),
				fields: []string{},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "test case B.2.3",
			args: args{
				signatureName: "sig1",
				verifier: (func() Verifier {
					pubKey, err := parseRsaPublicKeyFromPemStr(rsaPSSPubKey)
					if err != nil {
						t.Errorf("cannot parse public key: %v", err)
					}
					verifier, _ := NewRSAPSSVerifier("test-key-rsa-pss", pubKey)
					return *verifier
				})(),
				req:    readRequest(httpreq1pssFull),
				fields: []string{},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "test case B.2.4",
			args: args{
				signatureName: "sig1",
				verifier: (func() Verifier {
					pubKey, err := parseECPublicKeyFromPemStr(p256PubKey2)
					if err != nil {
						t.Errorf("cannot parse public key: %v", err)
					}
					verifier, _ := NewP256Verifier("test-key-ecc-p256", pubKey)
					return *verifier
				})(),
				req:    readRequest(httpreq1p256),
				fields: []string{},
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyRequest(tt.args.signatureName, tt.args.verifier, tt.args.req, tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VerifyRequest() got = %v, want %v", got, tt.want)
			}
		})
	}
}
