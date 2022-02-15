package httpsign

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"strings"
	"testing"
	"time"
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

var httpreq1pssMinimal = `POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
Content-Length: 18
Signature-Input: sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"
Signature: sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:

{"hello": "world"}
`

var httpreq1pssSelective = `POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
Content-Length: 18
Signature-Input: sig-b22=("@authority" "content-digest");created=1618884473;keyid="test-key-rsa-pss"
Signature: sig-b22=:Fee1uy9YGZq5UUwwYU6vz4dZNvfw3GYrFl1L6YlVIyUMuWswWDNSvql4dVtSeidYjYZUm7SBCENIb5KYy2ByoC3bI+7gydd2i4OAT5lyDtmeapnAa8uP/b9xUpg+VSPElbBs6JWBIQsd+nMdHDe+ls/IwVMwXktC37SqsnbNyhNp6kcvcWpevjzFcD2VqdZleUz4jN7P+W5A3wHiMGfIjIWn36KXNB+RKyrlGnIS8yaBBrom5rcZWLrLbtg6VlrH1+/07RV+kgTh/l10h8qgpl9zQHu7mWbDKTq0tJ8K4ywcPoC4s2I4rU88jzDKDGdTTQFZoTVZxZmuTM1FvHfzIw==:

{"hello": "world"}
`

var httpreq1pssSelectiveBad = `POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Cache-Control: max-age=60
Cache-Control:    must-revalidate
Content-Length: 18
Signature-Input: sig1=("@authority" "content-type");created=1618884475;keyid="test-key-rsa-pss"
Signature: sig1=:badbadik+OtGmM/kFqENDf9Plm8AmPtqtC7C9a+zYSaxr58b/E6h81ghJS3PcH+m1asiMp8yvccnO/RfaexnqanVB3C72WRNZN7skPTJmUVmoIeqZncdP2mlfxlLP6UbkrgYsk91NS6nwkKC6RRgLhBFqzP42oq8D2336OiQPDAo/04SxZt4Wx9nDGuy2SfZJUhsJqZyEWRk4204x7YEB3VxDAAlVgGt8ewilWbIKKTOKp3ymUeQIwptqYwv0l8mN404PPzRBTpB7+HpClyK4CNp+SVv46+6sHMfJU4taz10s/NoYRmYCGXyadzYYDj0BYnFdERB6NblI/AOWFGl5Axhhmjg==:

{"hello": "world"}
`

var httpreq1pssFull = `POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
Content-Length: 18
Signature-Input: sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"
Signature: sig-b23=:bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:

{"hello": "world"}
`

var httpreq1ed25519 = `POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
Content-Length: 18
Signature-Input: sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"
Signature: sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:

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

var httpreq2 = `POST /foo?param=value&pet=dog&pet=snake&bar=baz HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Cache-Control: max-age=60
Cache-Control:    must-revalidate
Content-Length: 18

{"hello": "world"}
`

var httpres2 = `HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Content-Length: 18

{"hello": "world"}
`

var httpreq3 = `POST /foo?param=value&pet=dog&pet=snake&bar=baz HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
@Method: GET
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Cache-Control: max-age=60
Cache-Control:    must-revalidate
Content-Length: 18

{"hello": "world"}
`

var httpres3 = `HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Signature: sig7=:n8RKXkj0iseWDmC6PNSQ1GX2R9650v+lhbb6rTGoSrSSx18zmn6fPOtBx48/WffYLO0n1RHHf9scvNGAgGq52Q==:
Signature-Input: sig7=("content-type" "digest" "content-length");keyid="my-key"
Content-Length: 18

{"hello": "world"}
`

var httpres4 = `HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Digest: sha-512=:JlEy2bfUz7WrWIjc1qV6KVLpdr/7L5/L4h7Sxvh6sNHpDQWDCL+GauFQWcZBvVDhiyOnAQsxzZFYwi0wDH+1pw==:
Content-Length: 23
Signature-Input: sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"
Signature: sig-b24=:0Ry6HsvzS5VmA6HlfBYS/fYYeNs7fYuA7s0tAdxfUlPGv0CSVuwrrzBOjcCFHTxVRJ01wjvSzM2BetJauj8dsw==:

{"message": "good dog"}
`

var httpreqtlsproxy = `POST /foo?param=Value&Pet=dog HTTP/1.1
Host: service.internal.example
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Length: 18
Client-Cert: :MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQKDBJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBDQTAeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXmckC8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQGV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0Q6bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=:
Signature-Input: ttrp=("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256"
Signature: ttrp=:xVMHVpawaAC/0SbHrKRs9i8I3eOs5RtTMGCWXm/9nvZzoHsIg6Mce9315T6xoklyy0yzhD9ah4JHRwMLOgmizw==:

{"hello": "world"}`

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

// Note: the private key from the draft is never used
var p256PubKey2 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----
`

var ed25519PrvKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`

// Workaround, from https://go.dev/play/p/fIz218Lj2L0. Credit: Ryan Castner.

var oidRsaPss = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
var oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

func loadRSAPSSPrivateKey(pemEncodedPK string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemEncodedPK))
	if block == nil {
		return nil, fmt.Errorf("empty block")
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

	return nil, fmt.Errorf("unknown algorithm")
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

func parseEdDSAPrivateKeyFromPemStr(pemEncodedPK string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemEncodedPK))
	if block == nil {
		return nil, fmt.Errorf("empty block")
	}

	// taken from crypto/x509/pkcs8.go
	type pkcs8 struct {
		Version           int
		Algo              pkix.AlgorithmIdentifier
		SeedStructWrapper []byte
		// optional attributes omitted.
	}

	type seedInner []byte // This appears to be an openssl bug: the seed octet string is wrapped
	// inside another octet string

	var privKey pkcs8
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		return nil, err
	}

	if !privKey.Algo.Algorithm.Equal(oidEd25519) {
		return nil, fmt.Errorf("unknown algorithm")
	}

	var seed seedInner
	_, err := asn1.Unmarshal(privKey.SeedStructWrapper, &seed) // double trouble
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal inner asn.1 octet string")
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed is malformed")
	}
	prv := ed25519.NewKeyFromSeed(seed)
	return prv, nil
}

func TestSignRequest(t *testing.T) {
	type args struct {
		signatureName string
		signer        Signer
		req           *http.Request
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
				signatureName: "sig-b25",
				signer: (func() Signer {
					config := NewSignConfig().SignAlg(false).setFakeCreated(1618884473)
					fields := Headers("date", "@authority", "content-type")
					key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
					signer, _ := NewHMACSHA256Signer("test-shared-secret", key, config, fields)
					return *signer
				})(),
				req: readRequest(httpreq1),
			},
			want:    "sig-b25=(\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\"",
			want1:   "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:",
			wantErr: false,
		},
		{
			name: "missing derived field",
			args: args{
				signatureName: "sig1",
				signer: (func() Signer {
					config := NewSignConfig().SignAlg(false).setFakeCreated(1618884475)
					fields := Headers("@authorityxx", "date", "content-type")
					key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
					signer, _ := NewHMACSHA256Signer("test-shared-secret", key, config, fields)
					return *signer
				})(),
				req: readRequest(httpreq1),
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
		{
			name: "missing header",
			args: args{
				signatureName: "sig1",
				signer: (func() Signer {
					config := NewSignConfig().SignAlg(false).setFakeCreated(1618884475)
					fields := Headers("@authority", "date-not-really", "content-type")
					key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
					signer, _ := NewHMACSHA256Signer("test-shared-secret", key, config, fields)
					return *signer
				})(),
				req: readRequest(httpreq1),
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
		{
			name: "sign request: nil request",
			args: args{
				signatureName: "sig1",
				signer: (func() Signer {
					prvKey, err := loadRSAPSSPrivateKey(rsaPSSPrvKey)
					if err != nil {
						t.Errorf("cannot parse private key: %v", err)
					}
					config := NewSignConfig().SignAlg(false).setFakeCreated(1618884475)
					fields := *NewFields()
					signer, _ := NewRSAPSSSigner("test-key-rsa-pss", *prvKey, config, fields)
					return *signer
				})(),
				req: nil,
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
		{
			name: "sign request: malicious request",
			args: args{
				signatureName: "sig1",
				signer:        makeRSAPSSSigner(t, *NewSignConfig().SignAlg(false).setFakeCreated(1618884475), *NewFields()),
				req:           readRequest(httpreq3),
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
		{
			name: "sign request: empty sig name",
			args: args{
				signatureName: "",
				signer:        makeRSAPSSSigner(t, *NewSignConfig().SignAlg(false).setFakeCreated(1618884475), *NewFields()),
				req:           readRequest(httpreq1),
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
		{
			name: "sign request: missing required field",
			args: args{
				signatureName: "sig1",
				signer:        makeRSAPSSSigner(t, *NewSignConfig().SignAlg(false).setFakeCreated(1618884475), *NewFields().AddHeader("Missing")),
				req:           readRequest(httpreq1),
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := SignRequest(tt.args.signatureName, tt.args.signer, tt.args.req)
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

func makeRSAPSSSigner(t *testing.T, config SignConfig, fields Fields) Signer {
	prvKey, err := loadRSAPSSPrivateKey(rsaPSSPrvKey)
	assert.NoError(t, err, "cannot parse private key")
	signer, _ := NewRSAPSSSigner("test-key-rsa-pss", *prvKey, &config, fields)
	return *signer
}

func makeHMACSigner(config SignConfig, fields Fields) Signer {
	signer, _ := NewHMACSHA256Signer("test-key-hmac", bytes.Repeat([]byte{0x33}, 64), &config, fields)
	return *signer
}

// Do not test for a particular signature: for non-deterministic methods
func TestSignRequestDiscardSig(t *testing.T) {
	type args struct {
		signatureName string
		signer        Signer
		req           *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   string
		wantErr bool
	}{
		{
			name: "test case B.2.1 (partial)", // note: sig params are not in the same order as in the spec
			args: args{
				signatureName: "sig-b21",
				signer: (func() Signer {
					config := NewSignConfig().SignAlg(false).
						setFakeCreated(1618884473).SetNonce("b3k2pp5k7z-50gnwp.yemd")
					fields := *NewFields()
					prvKey, err := loadRSAPSSPrivateKey(rsaPSSPrvKey)
					if err != nil {
						t.Errorf("cannot parse private key: %v", err)
					}
					signer, _ := NewRSAPSSSigner("test-key-rsa-pss", *prvKey, config, fields)
					return *signer
				})(),
				req: readRequest(httpreq1),
			},
			want:    "sig-b21=();created=1618884473;nonce=\"b3k2pp5k7z-50gnwp.yemd\";keyid=\"test-key-rsa-pss\"",
			want1:   "",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := SignRequest(tt.args.signatureName, tt.args.signer, tt.args.req)
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
	config := NewSignConfig().SignAlg(false).setFakeCreated(1618884475)
	fields := Headers("@authority", "date", "content-type")
	signatureName := "sig1"
	key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
	signer, _ := NewHMACSHA256Signer("test-shared-secret", key, config, fields)
	req := readRequest(httpreq1)
	sigInput, sig, _ := SignRequest(signatureName, *signer, req)
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)
	verifier, err := NewHMACSHA256Verifier("test-shared-secret", key, NewVerifyConfig().SetVerifyCreated(false), fields)
	assert.NoError(t, err, "could not generate Verifier")
	err = VerifyRequest(signatureName, *verifier, req)
	assert.NoError(t, err, "verification error")
}

func TestSignAndVerifyHMACBad(t *testing.T) {
	config := NewSignConfig().SignAlg(false).setFakeCreated(1618884475)
	fields := Headers("@authority", "date", "content-type")
	signatureName := "sig1"
	key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
	signer, _ := NewHMACSHA256Signer("test-shared-secret", key, config, fields)
	req := readRequest(httpreq1)
	sigInput, sig, _ := SignRequest(signatureName, *signer, req)
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)
	badkey := append(key, byte(0x77))
	verifier, err := NewHMACSHA256Verifier("test-shared-secret", badkey, NewVerifyConfig().SetVerifyCreated(false), fields)
	assert.NoError(t, err, "could not generate Verifier")
	err = VerifyRequest(signatureName, *verifier, req)
	assert.Error(t, err, "verification should have failed")
}

func TestCreated(t *testing.T) {
	testOnceWithConfig := func(t *testing.T, createdTime int64, verifyConfig *VerifyConfig, wantSuccess bool) {
		fields := Headers("@status", "date", "content-type")
		signatureName := "sigres"
		key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
		signConfig := NewSignConfig().SignCreated(true).setFakeCreated(createdTime)
		signer, _ := NewHMACSHA256Signer("test-shared-secret", key, signConfig, fields)
		res := readResponse(httpres2)
		nowStr := time.Now().UTC().Format(http.TimeFormat)
		res.Header.Set("Date", nowStr)
		sigInput, sig, _ := SignResponse(signatureName, *signer, res)

		res2 := readResponse(httpres2)
		res2.Header.Set("Date", nowStr)
		res2.Header.Add("Signature", sig)
		res2.Header.Add("Signature-Input", sigInput)
		verifier, err := NewHMACSHA256Verifier("test-shared-secret", key, verifyConfig, fields)
		if err != nil {
			t.Errorf("could not generate Verifier: %s", err)
		}
		err = VerifyResponse(signatureName, *verifier, res2)

		if wantSuccess && err != nil {
			t.Errorf("verification error: %s", err)
		}
		if !wantSuccess && err == nil {
			t.Errorf("expected verification to fail")
		}
	}
	testOnce := func(t *testing.T, createdTime int64, wantSuccess bool) {
		testOnceWithConfig(t, createdTime, nil, wantSuccess)
	}
	now := time.Now().Unix() // the window is in ms, but "created" granularity is in sec!
	testInWindow := func(t *testing.T) { testOnce(t, now, true) }
	testOlder := func(t *testing.T) { testOnce(t, now-20_000, false) }
	testNewer := func(t *testing.T) { testOnce(t, now+3_000, false) }
	testOldWindow1 := func(t *testing.T) {
		testOnceWithConfig(t, now-20_000, NewVerifyConfig().SetNotOlderThan(19_000*time.Second), false)
	}
	testOldWindow2 := func(t *testing.T) {
		testOnceWithConfig(t, now-20_000, NewVerifyConfig().SetNotOlderThan(21_000*time.Second), true)
	}
	testNewWindow1 := func(t *testing.T) {
		testOnceWithConfig(t, now+15_000, NewVerifyConfig().SetNotNewerThan(16_000*time.Second), true)
	}
	testNewWindow2 := func(t *testing.T) {
		testOnceWithConfig(t, now+15_000, NewVerifyConfig().SetNotNewerThan(14_000*time.Second), false)
	}
	testDate := func(t *testing.T) {
		testOnceWithConfig(t, now, NewVerifyConfig().SetVerifyDateWithin(100*time.Millisecond), true)
	}
	testDateFail := func(t *testing.T) {
		testOnceWithConfig(t, now, NewVerifyConfig().SetVerifyCreated(false).SetVerifyDateWithin(100*time.Millisecond), false)
	}
	t.Run("in window", testInWindow)
	t.Run("older", testOlder)
	t.Run("newer", testNewer)
	t.Run("older, smaller than window", testOldWindow1)
	t.Run("older, larger than window", testOldWindow2)
	t.Run("newer, smaller than window", testNewWindow1)
	t.Run("newer, larger than window", testNewWindow2)
	t.Run("verify Date header within window", testDate)
	t.Run("verify logic requires to verify Created", testDateFail)
}

func TestSignAndVerifyResponseHMAC(t *testing.T) {
	fields := Headers("@status", "date", "content-type")
	signatureName := "sigres"
	key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
	config := NewSignConfig().SetExpires(999)                                   // should have expired long ago (but will be ignored by verifier)
	signer, _ := NewHMACSHA256Signer("test-shared-secret", key, config, fields) // default config
	res := readResponse(httpres2)
	sigInput, sig, _ := SignResponse(signatureName, *signer, res)

	res2 := readResponse(httpres2)
	res2.Header.Add("Signature", sig)
	res2.Header.Add("Signature-Input", sigInput)
	verifier, err := NewHMACSHA256Verifier("test-shared-secret", key, NewVerifyConfig().SetRejectExpired(false), fields)
	if err != nil {
		t.Errorf("could not generate Verifier: %s", err)
	}
	err = VerifyResponse(signatureName, *verifier, res2)
	if err != nil {
		t.Errorf("verification error: %s", err)
	}
}

func TestSignAndVerifyRSAPSS(t *testing.T) {
	config := NewSignConfig().SignAlg(false).setFakeCreated(1618884475)
	fields := Headers("@authority", "date", "content-type")
	signatureName := "sig1"
	prvKey, err := loadRSAPSSPrivateKey(rsaPSSPrvKey)
	if err != nil {
		t.Errorf("cannot read private key")
	}
	signer, _ := NewRSAPSSSigner("test-key-rsa-pss", *prvKey, config, fields)
	req := readRequest(httpreq1)
	sigInput, sig, _ := SignRequest(signatureName, *signer, req)
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)
	pubKey, err := parseRsaPublicKeyFromPemStr(rsaPSSPubKey)
	if err != nil {
		t.Errorf("cannot read public key: %v", err)
	}
	verifier, err := NewRSAPSSVerifier("test-key-rsa-pss", *pubKey, NewVerifyConfig().SetVerifyCreated(false), fields)
	if err != nil {
		t.Errorf("could not generate Verifier: %s", err)
	}
	err = VerifyRequest(signatureName, *verifier, req)
	if err != nil {
		t.Errorf("verification error: %s", err)
	}
}

func TestSignAndVerifyRSA(t *testing.T) {
	config := NewSignConfig().SignAlg(false).setFakeCreated(1618884475)
	fields := Headers("@authority", "date", "content-type")
	signatureName := "sig1"
	prvKey, err := parseRsaPrivateKeyFromPemStr(rsaPrvKey)
	if err != nil {
		t.Errorf("cannot read private key")
	}
	signer, _ := NewRSASigner("test-key-rsa", *prvKey, config, fields)
	req := readRequest(httpreq1)
	sigInput, sig, _ := SignRequest(signatureName, *signer, req)
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)
	pubKey, err := parseRsaPublicKeyFromPemStr(rsaPubKey)
	if err != nil {
		t.Errorf("cannot read public key: %v", err)
	}
	verifier, err := NewRSAVerifier("test-key-rsa", *pubKey, NewVerifyConfig().SetVerifyCreated(false), fields)
	if err != nil {
		t.Errorf("could not generate Verifier: %s", err)
	}
	err = VerifyRequest(signatureName, *verifier, req)
	if err != nil {
		t.Errorf("verification error: %s", err)
	}
}

func TestSignAndVerifyP256(t *testing.T) {
	config := NewSignConfig().setFakeCreated(1618884475)
	signatureName := "sig1"
	prvKey, err := parseECPrivateKeyFromPemStr(p256PrvKey)
	if err != nil {
		t.Errorf("cannot read private key")
	}
	fields := *NewFields().AddHeader("@method").AddHeader("Date").AddHeader("Content-Type").AddQueryParam("pet")
	signer, _ := NewP256Signer("test-key-p256", *prvKey, config, fields)
	req := readRequest(httpreq2)
	sigInput, sig, err := SignRequest(signatureName, *signer, req)
	if err != nil {
		t.Errorf("signature failed: %v", err)
	}
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)
	pubKey, err := parseECPublicKeyFromPemStr(p256PubKey)
	if err != nil {
		t.Errorf("cannot read public key: %v", err)
	}
	verifier, err := NewP256Verifier("test-key-p256", *pubKey, NewVerifyConfig().SetVerifyCreated(false), fields)
	if err != nil {
		t.Errorf("could not generate Verifier: %s", err)
	}
	err = VerifyRequest(signatureName, *verifier, req)
	if err != nil {
		t.Errorf("verification error: %s", err)
	}
}

func TestSignAndVerifyEdDSA(t *testing.T) {
	pubKey1, prvKey1, err := ed25519.GenerateKey(nil) // Need some tweaking for RFC 8032 keys, see package doc
	if err != nil {
		t.Errorf("cannot generate keypair: %s", err)
	}
	config := NewSignConfig().setFakeCreated(1618884475)
	fields := *NewFields().AddHeader("@method").AddHeader("Date").AddHeader("Content-Type").AddQueryParam("pet")
	signer1, _ := NewEd25519Signer("test-key-ed25519", prvKey1, config, fields)

	signAndVerifyEdDSA(t, signer1, pubKey1, fields)

	seed2 := make([]byte, ed25519.SeedSize)
	_, err = rand.Read(seed2)
	if err != nil {
		t.Errorf("rand failed?")
	}
	prvKey2 := ed25519.NewKeyFromSeed(seed2)
	pubKey2 := prvKey2.Public().(ed25519.PublicKey)

	signer2, _ := NewEd25519SignerFromSeed("test-key-ed25519", seed2, config, fields)

	signAndVerifyEdDSA(t, signer2, pubKey2, fields)
}

func signAndVerifyEdDSA(t *testing.T, signer *Signer, pubKey ed25519.PublicKey, fields Fields) {
	signatureName := "sig1"
	req := readRequest(httpreq2)
	sigInput, sig, err := SignRequest(signatureName, *signer, req)
	if err != nil {
		t.Errorf("signature failed: %v", err)
	}
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)
	verifier, err := NewEd25519Verifier("test-key-ed25519", pubKey, NewVerifyConfig().SetVerifyCreated(false), fields)
	if err != nil {
		t.Errorf("could not generate Verifier: %s", err)
	}
	err = VerifyRequest(signatureName, *verifier, req)
	if err != nil {
		t.Errorf("verification error: %s", err)
	}
}

func TestSignResponse(t *testing.T) {
	type args struct {
		signatureName string
		signer        Signer
		res           *http.Response
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
				signatureName: "sig1",
				signer: (func() Signer {
					key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
					signer, _ := NewHMACSHA256Signer("test-shared-secret", key, NewSignConfig().setFakeCreated(1618889999), Headers(
						"@status", "date", "content-type"))
					return *signer
				})(),
				res: readResponse(httpres1),
			},
			want:    "sig1=(\"@status\" \"date\" \"content-type\");created=1618889999;alg=\"hmac-sha256\";keyid=\"test-shared-secret\"",
			want1:   "sig1=:5s7SCXZBsy7g/xqoFjVy+WWvWi4bb3G7bQoE+blEyz4=:",
			wantErr: false,
		},
		{
			name: "test response with HMAC: nil response",
			args: args{
				signatureName: "sig1",
				signer: (func() Signer {
					key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
					signer, _ := NewHMACSHA256Signer("test-shared-secret", key, NewSignConfig().setFakeCreated(1618889999), Headers(

						"@status", "date", "content-type",
					))
					return *signer
				})(),
				res: nil,
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := SignResponse(tt.args.signatureName, tt.args.signer, tt.args.res)
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
				signatureName: "sig-b21",
				verifier:      makeRSAVerifier(t, "test-key-rsa-pss", *NewFields()),
				req:           readRequest(httpreq1pssMinimal),
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "test case B.2.2",
			args: args{
				signatureName: "sig-b22",
				verifier: (func() Verifier {
					pubKey, err := parseRsaPublicKeyFromPemStr(rsaPSSPubKey)
					if err != nil {
						t.Errorf("cannot parse public key: %v", err)
					}
					verifier, _ := NewRSAPSSVerifier("test-key-rsa-pss", *pubKey, NewVerifyConfig().SetVerifyCreated(false), *NewFields())
					return *verifier
				})(),
				req: readRequest(httpreq1pssSelective),
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "test case B.2.3",
			args: args{
				signatureName: "sig-b23",
				verifier: (func() Verifier {
					pubKey, err := parseRsaPublicKeyFromPemStr(rsaPSSPubKey)
					if err != nil {
						t.Errorf("cannot parse public key: %v", err)
					}
					verifier, _ := NewRSAPSSVerifier("test-key-rsa-pss", *pubKey, NewVerifyConfig().SetVerifyCreated(false), *NewFields())
					return *verifier
				})(),
				req: readRequest(httpreq1pssFull),
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "test case B.2.6",
			args: args{
				signatureName: "sig-b26",
				verifier: (func() Verifier {
					prvKey, err := parseEdDSAPrivateKeyFromPemStr(ed25519PrvKey)
					if err != nil {
						t.Errorf("cannot parse public key: %v", err)
					}
					pubKey := prvKey.Public().(ed25519.PublicKey)
					verifier, _ := NewEd25519Verifier("test-key-ed25519", pubKey, NewVerifyConfig().SetVerifyCreated(false), *NewFields())
					return *verifier
				})(),
				req: readRequest(httpreq1ed25519),
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "test case B.3", // TLS-terminating proxy
			args: args{
				signatureName: "ttrp",
				verifier: (func() Verifier {
					pubKey, _ := parseECPublicKeyFromPemStr(p256PubKey2)
					verifier, _ := NewP256Verifier("test-key-ecc-p256", *pubKey, NewVerifyConfig().SetVerifyCreated(false), *NewFields())
					return *verifier
				})(),
				req: readRequest(httpreqtlsproxy),
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "verify bad sig (not base64)",
			args: args{
				signatureName: "sig1",
				verifier:      makeRSAVerifier(t, "test-key-rsa-pss", *NewFields()),
				req:           readRequest(httpreq1pssSelectiveBad),
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "missing fields",
			args: args{
				signatureName: "sig1",
				verifier:      makeRSAVerifier(t, "test-key-rsa-pss", *NewFields().AddQueryParam("missing")),
				req:           readRequest(httpreq1pssMinimal),
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "bad keyID",
			args: args{
				signatureName: "sig-b22",
				verifier: (func() Verifier {
					pubKey, err := parseRsaPublicKeyFromPemStr(rsaPSSPubKey)
					if err != nil {
						t.Errorf("cannot parse public key: %v", err)
					}
					verifier, _ := NewRSAPSSVerifier("bad-key-id", *pubKey, NewVerifyConfig().SetVerifyCreated(false), *NewFields())
					return *verifier
				})(),
				req: readRequest(httpreq1pssSelective),
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "bad keyID but not verified", // this is NOT a failure
			args: args{
				signatureName: "sig-b22",
				verifier: (func() Verifier {
					pubKey, err := parseRsaPublicKeyFromPemStr(rsaPSSPubKey)
					if err != nil {
						t.Errorf("cannot parse public key: %v", err)
					}
					verifier, _ := NewRSAPSSVerifier("bad-key-id", *pubKey, NewVerifyConfig().
						SetVerifyCreated(false).SetVerifyKeyID(false), *NewFields())
					return *verifier
				})(),
				req: readRequest(httpreq1pssSelective),
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyRequest(tt.args.signatureName, tt.args.verifier, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func makeRSAVerifier(t *testing.T, keyID string, fields Fields) Verifier {
	return (func() Verifier {
		pubKey, err := parseRsaPublicKeyFromPemStr(rsaPSSPubKey)
		if err != nil {
			t.Errorf("cannot parse public key: %v", err)
		}
		verifier, _ := NewRSAPSSVerifier(keyID, *pubKey, NewVerifyConfig().SetVerifyCreated(false), fields)
		return *verifier
	})()
}

func TestRequestDetails(t *testing.T) {
	type args struct {
		signatureName string
		req           *http.Request
	}
	tests := []struct {
		name      string
		args      args
		wantKeyID string
		wantAlg   string
		wantErr   bool
	}{
		{
			name: "happy path",
			args: args{
				signatureName: "sig1",
				req:           readRequest(httpreq1p256),
			},
			wantKeyID: "test-key-ecc-p256",
			wantAlg:   "",
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKeyID, gotAlg, err := RequestDetails(tt.args.signatureName, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("RequestDetails() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotKeyID != tt.wantKeyID {
				t.Errorf("RequestDetails() gotKeyID = %v, want %v", gotKeyID, tt.wantKeyID)
			}
			if gotAlg != tt.wantAlg {
				t.Errorf("RequestDetails() gotAlg = %v, want %v", gotAlg, tt.wantAlg)
			}
		})
	}
}

func TestResponseDetails(t *testing.T) {
	type args struct {
		signatureName string
		res           *http.Response
	}
	tests := []struct {
		name      string
		args      args
		wantKeyID string
		wantAlg   string
		wantErr   bool
	}{
		{
			name: "happy path",
			args: args{
				signatureName: "sig7",
				res:           readResponse(httpres3),
			},
			wantKeyID: "my-key",
			wantAlg:   "",
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKeyID, gotAlg, err := ResponseDetails(tt.args.signatureName, tt.args.res)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResponseDetails() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotKeyID != tt.wantKeyID {
				t.Errorf("ResponseDetails() gotKeyID = %v, want %v", gotKeyID, tt.wantKeyID)
			}
			if gotAlg != tt.wantAlg {
				t.Errorf("ResponseDetails() gotAlg = %v, want %v", gotAlg, tt.wantAlg)
			}
		})
	}
}

func genP256KeyPair() (priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, err error) {
	priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub = priv.Public().(*ecdsa.PublicKey)
	return priv, pub, nil
}

func TestRequestResponse(t *testing.T) {
	// Client signs request
	priv1, pub1, err := genP256KeyPair() // client keys
	if err != nil {
		t.Errorf("Could not generate P-256 keypair")
	}
	req := readRequest(httpreq2)
	signer1, err := NewP256Signer("key9", *priv1, NewSignConfig(), Headers("@request-target"))
	if err != nil {
		t.Errorf("Could not create signer")
	}
	sigInput1, sig1, err := SignRequest("sig1", *signer1, req)
	if err != nil {
		t.Errorf("Could not sign request: %v", err)
	}
	req.Header.Add("Signature-Input", sigInput1)
	req.Header.Add("Signature", sig1)

	// Server verifies request and signs response
	verifier1, err := NewP256Verifier("key9", *pub1, NewVerifyConfig(), Headers("@request-target"))
	if err != nil {
		t.Errorf("Could not create verifier: %v", err)
	}
	err = VerifyRequest("sig1", *verifier1, req)
	if err != nil {
		t.Errorf("Could not verify request: %v", err)
	}

	priv2, pub2, err := genP256KeyPair() // client keys
	if err != nil {
		t.Errorf("Could not generate second P-256 keypair")
	}
	res := readResponse(httpres2)
	sig1Value, err := GetRequestSignature(req, "sig1")
	if err != nil {
		t.Errorf("Could not parse sig1")
	}
	signer2, err := NewP256Signer("key10", *priv2, NewSignConfig().SetRequestResponse("sig1", sig1Value), Headers("@status"))
	if err != nil {
		t.Errorf("Could not create signer")
	}
	sigInput2, sig2, err := SignResponse("sig2", *signer2, res)
	if err != nil {
		t.Errorf("Could not sign response: %v", err)
	}
	res.Header.Add("Signature-Input", sigInput2)
	res.Header.Add("Signature", sig2)

	// Client verifies response
	verifier2, err := NewP256Verifier("key10", *pub2, NewVerifyConfig().SetRequestResponse("sigxx", sig1Value).SetVerifyCreated(false), Headers("@status"))
	if err != nil {
		t.Errorf("Could not create second verifier: %v", err)
	}
	err = VerifyResponse("sig2", *verifier2, res)
	if err == nil {
		t.Errorf("Verification should have failed, wrong sig name in SetRequestResponse")
	}
	verifier2, err = NewP256Verifier("key10", *pub2, NewVerifyConfig().SetRequestResponse("sig1", sig1Value).SetVerifyCreated(false), Headers("@status"))
	if err != nil {
		t.Errorf("Could not create second verifier: %v", err)
	}
	err = VerifyResponse("sig2", *verifier2, res)
	if err != nil {
		t.Errorf("Could not verify response: %v", err)
	}
}

func TestDictionary(t *testing.T) {
	priv, pub, err := genP256KeyPair()
	if err != nil {
		t.Errorf("failed to generate key")
	}
	res := readResponse(httpres2)
	res.Header.Set("X-Dictionary", "a=1, b=2;x=1;y=2, c=(a b c)")
	signer2, err := NewP256Signer("key10", *priv, NewSignConfig(),
		*NewFields().AddHeader("@status").AddDictHeader("x-dictionary", "a"))
	if err != nil {
		t.Errorf("Could not create signer")
	}
	sigInput2, sig2, err := SignResponse("sig2", *signer2, res)
	if err != nil {
		t.Errorf("Could not sign response: %v", err)
	}
	res.Header.Add("Signature-Input", sigInput2)
	res.Header.Add("Signature", sig2)

	// Client verifies response
	verifier2, err := NewP256Verifier("key10", *pub, NewVerifyConfig().SetVerifyCreated(false),
		*NewFields().AddHeader("@status").AddDictHeader("x-dictionary", "a"))
	if err != nil {
		t.Errorf("Could not create verifier: %v", err)
	}
	err = VerifyResponse("sig2", *verifier2, res)
	if err != nil {
		t.Errorf("Could not verify response: %v", err)
	}
}

func TestMultipleSignatures(t *testing.T) {
	priv1, _, err := genP256KeyPair() // no pub, no verify
	res := readResponse(httpres2)
	signer1, err := NewP256Signer("key10", *priv1, NewSignConfig().SignCreated(false), Headers("Content-Type", "Digest"))
	if err != nil {
		t.Errorf("Could not create signer")
	}
	sigInput1, sig1, err := SignResponse("sig2", *signer1, res)
	if err != nil {
		t.Errorf("Could not sign response: %v", err)
	}
	res.Header.Add("Signature-Input", sigInput1)
	res.Header.Add("Signature", sig1)

	priv2, _, err := genP256KeyPair() // no pub, no verify
	signer2, err := NewP256Signer("key20", *priv2, NewSignConfig().SignCreated(false), *NewFields().AddDictHeader("Signature", "sig2"))
	if err != nil {
		t.Errorf("Could not create signer")
	}
	sigInput2, sig2, err := SignResponse("proxy_sig", *signer2, res)
	if err != nil {
		t.Errorf("Proxy could not sign response: %v", err)
	}
	res.Header.Add("Signature-Input", sigInput2)
	res.Header.Add("Signature", sig2)
	wantSigInput := "sig2=(\"content-type\" \"digest\");alg=\"ecdsa-p256-sha256\";keyid=\"key10\",proxy_sig=(\"signature\";key=\"sig2\");alg=\"ecdsa-p256-sha256\";keyid=\"key20\""
	gotSigInput := fold(res.Header.Values("Signature-Input"))
	if gotSigInput != wantSigInput {
		t.Errorf("Signature-Header, want %s, got %s", wantSigInput, gotSigInput)
	}
}

func fold(vs []string) string {
	return strings.Join(vs, ",")
}

var dict1 = `GET /foo?param=value&pet=dog&pet=snake&bar=baz HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Example-Dict:  a=1,    b=2;x=1;y=2,   c=(a   b   c)
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=

`

var dict2 = `GET /foo?param=value&pet=dog&pet=snake&bar=baz HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Example-Dict:  a=1    
Example-Dict:      b=2;x=1;y=2,   c=(a   b   c)
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=

`

var httpreq4 = `GET /foo?param=value&pet=dog&pet=snake&bar=baz HTTP/1.1
Host: www.example.com
Date: Tue, 20 Apr 2021 02:07:56 GMT
X-OWS-Header:   Leading and trailing whitespace.
X-Obs-Fold-Header: Obsolete
    line folding.
Cache-Control: max-age=60
Cache-Control:    must-revalidate
Example-Dict:  a=1,    b=2;x=1;y=2,   c=(a   b   c)

`

func Test_signRequestDebug(t *testing.T) {
	type args struct {
		signatureName string
		signer        Signer
		req           *http.Request
	}
	tests := []struct {
		name                     string
		args                     args
		wantSignatureInputHeader string
		wantSignature            string
		wantSignatureInput       string
		wantErr                  bool
	}{
		{
			name: "normal header, sec. 2.1.1",
			args: args{
				signatureName: "sig1",
				signer:        makeHMACSigner(*NewSignConfig().SignCreated(false), Headers("example-dict")),
				req:           readRequest(dict1),
			},
			wantSignatureInputHeader: "sig1=(\"example-dict\");alg=\"hmac-sha256\";keyid=\"test-key-hmac\"",
			wantSignature:            "sig1=:QIpdcJ+ooLtayPLbo/wte3hVTH78oyg6xfKpO1JIXgU=:",
			wantSignatureInput:       "\"example-dict\": a=1,    b=2;x=1;y=2,   c=(a   b   c)\n\"@signature-params\": (\"example-dict\");alg=\"hmac-sha256\";keyid=\"test-key-hmac\"",
			wantErr:                  false,
		},
		{
			name: "normal header as SFV, sec. 2.1.1",
			args: args{
				signatureName: "sig1",
				signer:        makeHMACSigner(*NewSignConfig().SignCreated(false), *NewFields().AddStructuredField("example-dict")),
				req:           readRequest(dict1),
			},
			wantSignatureInputHeader: "sig1=(\"example-dict\";sf);alg=\"hmac-sha256\";keyid=\"test-key-hmac\"",
			wantSignature:            "sig1=:rYmKiJM/+dqWmK6NsSOSk5KnZIubvwGPCD8TU0CXVd0=:",
			wantSignatureInput:       "\"example-dict\";sf: a=1, b=2;x=1;y=2, c=(a b c)\n\"@signature-params\": (\"example-dict\";sf);alg=\"hmac-sha256\";keyid=\"test-key-hmac\"",
			wantErr:                  false,
		},
		{
			name: "cross-line header, trim",
			args: args{
				signatureName: "sig1",
				signer:        makeHMACSigner(*NewSignConfig().SignCreated(false), Headers("example-dict")),
				req:           readRequest(dict2),
			},
			wantSignatureInputHeader: "sig1=(\"example-dict\");alg=\"hmac-sha256\";keyid=\"test-key-hmac\"",
			wantSignature:            "sig1=:xboyl9rhvXv0b7ulp/jt6CrVx8VRhuYixUbk3UmcJ50=:",
			wantSignatureInput:       "\"example-dict\": a=1, b=2;x=1;y=2,   c=(a   b   c)\n\"@signature-params\": (\"example-dict\");alg=\"hmac-sha256\";keyid=\"test-key-hmac\"",
			wantErr:                  false,
		},
		{
			name: "various headers, Sec. 2.1",
			args: args{
				signatureName: "sig1",
				signer: makeHMACSigner(*NewSignConfig().SignCreated(false),
					Headers("X-OWS-Header", "X-Obs-Fold-Header", "Cache-Control", "example-dict")),
				req: readRequest(httpreq4),
			},
			wantSignatureInputHeader: "sig1=(\"x-ows-header\" \"x-obs-fold-header\" \"cache-control\" \"example-dict\");alg=\"hmac-sha256\";keyid=\"test-key-hmac\"",
			wantSignature:            "sig1=:em2Fo9lAgLfPKqZQUhFyYrcBhF+5K8y71+zcFyzAJb8=:",
			wantSignatureInput:       "\"x-ows-header\": Leading and trailing whitespace.\n\"x-obs-fold-header\": Obsolete line folding.\n\"cache-control\": max-age=60, must-revalidate\n\"example-dict\": a=1,    b=2;x=1;y=2,   c=(a   b   c)\n\"@signature-params\": (\"x-ows-header\" \"x-obs-fold-header\" \"cache-control\" \"example-dict\");alg=\"hmac-sha256\";keyid=\"test-key-hmac\"",
			wantErr:                  false,
		},
		{
			name: "reserialized dictionary headers, Sec. 2.1.2",
			args: args{
				signatureName: "sig1",
				signer: makeHMACSigner(*NewSignConfig().SignCreated(false),
					*NewFields().AddHeaders("Cache-Control").AddDictHeader("example-dict", "a").AddDictHeader("example-dict", "b").AddDictHeader("example-dict", "c")),
				req: readRequest(httpreq4),
			},
			wantSignatureInputHeader: "sig1=(\"cache-control\" \"example-dict\";key=\"a\" \"example-dict\";key=\"b\" \"example-dict\";key=\"c\");alg=\"hmac-sha256\";keyid=\"test-key-hmac\"",
			wantSignature:            "sig1=:ZgRaU7rBGNrMr2aEpKjXYU6sReB0V+Uks2jpm30jh24=:",
			wantSignatureInput:       "\"cache-control\": max-age=60, must-revalidate\n\"example-dict\";key=\"a\": 1\n\"example-dict\";key=\"b\": 2;x=1;y=2\n\"example-dict\";key=\"c\": (a b c)\n\"@signature-params\": (\"cache-control\" \"example-dict\";key=\"a\" \"example-dict\";key=\"b\" \"example-dict\";key=\"c\");alg=\"hmac-sha256\";keyid=\"test-key-hmac\"",
			wantErr:                  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSignatureInputHeader, gotSignature, gotSignatureInput, err := signRequestDebug(tt.args.signatureName, tt.args.signer, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("signRequestDebug() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotSignatureInputHeader != tt.wantSignatureInputHeader {
				t.Errorf("signRequestDebug() gotSignatureInputHeader = %v, want %v", gotSignatureInputHeader, tt.wantSignatureInputHeader)
			}
			if gotSignature != tt.wantSignature {
				t.Errorf("signRequestDebug() gotSignature = %v, want %v", gotSignature, tt.wantSignature)
			}
			if gotSignatureInput != tt.wantSignatureInput {
				t.Errorf("signRequestDebug() gotSignatureInput = %v, want %v", gotSignatureInput, tt.wantSignatureInput)
			}
		})
	}
}

func TestVerifyResponse(t *testing.T) {
	type args struct {
		signatureName string
		verifier      Verifier
		res           *http.Response
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test case B.2.4",
			args: args{
				signatureName: "sig-b24",
				verifier: (func() Verifier {
					pubKey, err := parseECPublicKeyFromPemStr(p256PubKey2)
					if err != nil {
						t.Errorf("cannot parse public key: %v", err)
					}
					verifier, _ := NewP256Verifier("test-key-ecc-p256", *pubKey, NewVerifyConfig().SetVerifyCreated(false), *NewFields())
					return *verifier
				})(),
				res: readResponse(httpres4),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifyResponse(tt.args.signatureName, tt.args.verifier, tt.args.res); (err != nil) != tt.wantErr {
				t.Errorf("VerifyResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
