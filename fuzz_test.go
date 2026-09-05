package httpsign

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
)

var httpreq1pssNoSig = `POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
Content-Length: 18

{"hello": "world"}
`

var httpreqTrailers = `POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Trailer: Expires
Content-Length: 18

{"hello": "world"}
Expires: Wed, 9 Nov 2022 07:28:00 GMT
`

// sharedHMACKeyB64 is the RFC 9421 test shared secret (base64).
const sharedHMACKeyB64 = "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="

func fuzzHMACKey() []byte {
	key, _ := base64.StdEncoding.DecodeString(sharedHMACKeyB64)
	return key
}

// FuzzVerifyRequest mutates Signature-Input / Signature against a fixed verifier.
// Panic-oriented: expected verify/parse failures are ignored.
func FuzzVerifyRequest(f *testing.F) {
	type inputs struct {
		req, sigInput, sig string
	}
	testcases := []inputs{
		{httpreq1pssNoSig,
			`sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`,
			`sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`,
		},
		{httpreq1pssNoSig,
			`sig-b21=(date);created=1618884473;keyid="test-key-rsa-pss";nonce="xxxb3k5k7z-50gnwp.yemd"`,
			`sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`,
		},
		{httpreqTrailers,
			`sig-b21=("expires";tr);created=1618884473;keyid="test-key-rsa-pss";nonce="xxxb3k5k7z-50gnwp.yemd"`,
			`sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`,
		},
		{httpreq1pssNoSig,
			`sig-b21=("content-type";bs);created=1618884473;keyid="test-key-rsa-pss"`,
			`sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`,
		},
		{httpreq1pssNoSig,
			`sig-b21=("content-type";sf);created=1618884473;keyid="test-key-rsa-pss"`,
			`sig-b21=:AAAA:`,
		},
		{httpreq1pssNoSig,
			`sig-b21=("@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss"`,
			`sig-b21=:AAAA:`,
		},
		{httpreq1pssNoSig,
			`sig-b21=("content-digest");created=1618884473;keyid="test-key-rsa-pss"`,
			`sig-b21=:AAAA:`,
		},
		// Malformed SFV / truncated dictionaries
		{httpreq1pssNoSig, `sig-b21=(`, `sig-b21=:AAAA:`},
		{httpreq1pssNoSig, `sig-b21=("@method";created=1`, `sig-b21=:AAAA:`},
		{httpreq1pssNoSig, `not-a-dict`, `sig-b21=:not-b64:`},
		{httpreq1pssNoSig, `sig-b21=("@method");created=abc;keyid="x"`, `sig-b21=:AAAA:`},
		{httpreq1pssNoSig, `sig-b21=("@method" "date");alg="rsa-pss-sha512";created=1618884473;keyid="test-key-rsa-pss";tag="t";nonce="n"`, `sig-b21=:AAAA:`},
		{httpreq1pssNoSig, `sig-b21=("@method");created=1618884473;keyid="test-key-rsa-pss",sig2=("@authority");created=1`, `sig-b21=:AAAA:,sig2=:BBBB:`},
	}
	for _, tc := range testcases {
		f.Add(tc.req, tc.sigInput, tc.sig)
	}
	verifier := makeRSAVerifier(f, "key1", *NewFields())
	f.Fuzz(func(t *testing.T, reqString, sigInput, sig string) {
		req := readRequest(reqString)
		if req == nil {
			return
		}
		req.Header.Set("Signature-Input", sigInput)
		req.Header.Set("Signature", sig)
		_ = VerifyRequest("sig-b21", verifier, req)
	})
}

// FuzzVerifyViaMessage is the Message.Verify twin of FuzzVerifyRequest.
// Kept separately: Message construction and header maps are a distinct panic surface from net/http helpers.
func FuzzVerifyViaMessage(f *testing.F) {
	type inputs struct {
		req, sigInput, sig string
	}
	testcases := []inputs{
		{httpreq1pssNoSig,
			`sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`,
			`sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`,
		},
		{httpreq1pssNoSig,
			`sig-b21=(date);created=1618884473;keyid="test-key-rsa-pss";nonce="xxxb3k5k7z-50gnwp.yemd"`,
			`sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`,
		},
		{httpreqTrailers,
			`sig-b21=("expires";tr);created=1618884473;keyid="test-key-rsa-pss"`,
			`sig-b21=:AAAA:`,
		},
		{httpreq1pssNoSig,
			`sig-b21=("content-type";bs);created=1618884473;keyid="test-key-rsa-pss"`,
			`sig-b21=:AAAA:`,
		},
		{httpreq1pssNoSig,
			`sig-b21=("@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss"`,
			`sig-b21=:AAAA:`,
		},
		{httpreq1pssNoSig, `sig-b21=(`, `sig-b21=:AAAA:`},
		{httpreq1pssNoSig, `sig-b21=("@method");created=abc`, `sig-b21=:not-b64:`},
	}
	for _, tc := range testcases {
		f.Add(tc.req, tc.sigInput, tc.sig)
	}
	verifier := makeRSAVerifier(f, "key1", *NewFields())
	f.Fuzz(func(t *testing.T, reqString, sigInput, sig string) {
		req := readRequest(reqString)
		if req == nil {
			return
		}
		req.Header.Set("Signature-Input", sigInput)
		req.Header.Set("Signature", sig)
		msg, err := NewMessage(NewMessageConfig().WithRequest(req))
		if err != nil {
			return
		}
		_, _ = msg.Verify("sig-b21", verifier)
	})
}

// FuzzSignAndVerifyHMAC round-trips SignRequest → VerifyRequest.
// Asserts only after a successful SignRequest (nil / parse / sign errors return early).
func FuzzSignAndVerifyHMAC(f *testing.F) {
	for _, req := range []string{httpreq1, httpreq1pssNoSig, httpreqTrailers} {
		f.Add(req)
	}
	key := fuzzHMACKey()
	f.Fuzz(func(t *testing.T, reqString string) {
		req := readRequest(reqString)
		if req == nil {
			return
		}
		if digests := req.Header.Values("Content-Digest"); len(digests) > 0 && req.Body != nil {
			_ = ValidateContentDigestHeader(digests, &req.Body, []string{DigestSha256, DigestSha512})
		}
		config := NewSignConfig().SignAlg(false).setFakeCreated(1618884475)
		fields := Headers("@authority", "date", "content-type")
		if req.Header.Get("Content-Digest") != "" {
			fields = Headers("@authority", "date", "content-type", "content-digest")
		}
		signer, err := NewHMACSHA256Signer(key, config.SetKeyID("test-shared-secret"), fields)
		if err != nil || signer == nil {
			return
		}
		sigInput, sig, err := SignRequest("sig1", *signer, req)
		if err != nil {
			return
		}
		req.Header.Add("Signature", sig)
		req.Header.Add("Signature-Input", sigInput)
		verifier, err := NewHMACSHA256Verifier(key, NewVerifyConfig().SetVerifyCreated(false).SetKeyID("test-shared-secret"), fields)
		if err != nil || verifier == nil {
			return
		}
		if err := VerifyRequest("sig1", *verifier, req); err != nil {
			t.Fatalf("round-trip verify failed after successful sign: %v", err)
		}
	})
}

// FuzzHMACViaMessage is the Message.Verify twin of FuzzSignAndVerifyHMAC (same keep rationale as FuzzVerifyViaMessage).
func FuzzHMACViaMessage(f *testing.F) {
	for _, req := range []string{httpreq1, httpreq1pssNoSig, httpreqTrailers} {
		f.Add(req)
	}
	key := fuzzHMACKey()
	f.Fuzz(func(t *testing.T, reqString string) {
		req := readRequest(reqString)
		if req == nil {
			return
		}
		if digests := req.Header.Values("Content-Digest"); len(digests) > 0 && req.Body != nil {
			_ = ValidateContentDigestHeader(digests, &req.Body, []string{DigestSha256, DigestSha512})
		}
		config := NewSignConfig().SignAlg(false).setFakeCreated(1618884475)
		fields := Headers("@authority", "date", "content-type")
		if req.Header.Get("Content-Digest") != "" {
			fields = Headers("@authority", "date", "content-type", "content-digest")
		}
		signer, err := NewHMACSHA256Signer(key, config.SetKeyID("test-shared-secret"), fields)
		if err != nil || signer == nil {
			return
		}
		sigInput, sig, err := SignRequest("sig1", *signer, req)
		if err != nil {
			return
		}
		req.Header.Add("Signature", sig)
		req.Header.Add("Signature-Input", sigInput)
		verifier, err := NewHMACSHA256Verifier(key, NewVerifyConfig().SetVerifyCreated(false).SetKeyID("test-shared-secret"), fields)
		if err != nil || verifier == nil {
			return
		}
		msg, err := NewMessage(NewMessageConfig().WithRequest(req))
		if err != nil {
			return
		}
		if _, err := msg.Verify("sig1", *verifier); err != nil {
			t.Fatalf("round-trip Message.Verify failed after successful sign: %v", err)
		}
	})
}

// FuzzNewMessage exercises MessageConfig / NewMessage (and a smoke Verify), including response + associated-request shapes.
func FuzzNewMessage(f *testing.F) {
	f.Add("GET", "https://example.com/path", "example.com", "https", 0, "", "", "", "", true, false)
	f.Add("POST", "https://api.example.com", "api.example.com", "https", 0, "", "", "", "", false, true)
	f.Add("", "", "", "", 200, "GET", "https://example.com", "example.com", "https", true, false)
	f.Add("PUT", "", "", "http", 0, "", "", "", "", false, false)
	f.Add("", "", "", "", 404, "", "", "", "", false, false)
	f.Add("0", "%", "0", "0", 0, "", "", "", "", true, false)
	f.Add("", "", "", "", 200, "POST", "https://example.com/x?q=1", "example.com", "https", true, true)
	f.Add("PATCH", "https://example.com/a?b=c", "example.com", "https", 0, "", "", "", "", true, true)

	key := fuzzHMACKey()
	f.Fuzz(func(t *testing.T, method, urlStr, authority, scheme string, statusCode int,
		assocMethod, assocURLStr, assocAuthority, assocScheme string,
		hasHeaders, hasTrailers bool) {

		config := NewMessageConfig()

		if method != "" {
			config = config.WithMethod(method)
		}
		if urlStr != "" {
			u, err := url.Parse(urlStr)
			if err == nil {
				config = config.WithURL(u)
			}
		}
		if authority != "" {
			config = config.WithAuthority(authority)
		}
		if scheme != "" {
			config = config.WithScheme(scheme)
		}

		if statusCode > 0 {
			config = config.WithStatusCode(statusCode)
		}

		if hasHeaders {
			headers := http.Header{
				"Content-Type":    []string{"application/json"},
				"X-Test":          []string{"fuzz"},
				"Content-Digest":  []string{"sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"},
				"Signature-Input": []string{`sig1=("@method");created=1618884473;keyid="test-key"`},
				"Signature":       []string{`sig1=:AAAA:`},
			}
			config = config.WithHeaders(headers)
		}
		if hasTrailers {
			trailers := http.Header{
				"X-Trailer": []string{"test"},
				"Expires":   []string{"Wed, 9 Nov 2022 07:28:00 GMT"},
			}
			config = config.WithTrailers(trailers)
		}

		if statusCode > 0 && assocMethod != "" {
			var assocURL *url.URL
			if assocURLStr != "" {
				assocURL, _ = url.Parse(assocURLStr)
			}
			assocHeaders := http.Header{"X-Assoc": []string{"test"}}
			config = config.WithAssociatedRequest(assocMethod, assocURL, assocHeaders, assocAuthority, assocScheme)
		}

		msg, err := NewMessage(config)
		if err != nil {
			// Invalid configs are expected; only panics are interesting.
			return
		}
		if msg.headers == nil && msg.method != "" {
			t.Fatalf("request message created without headers")
		}
		if msg.headers == nil && msg.statusCode != nil {
			t.Fatalf("response message created without headers")
		}

		verifier, err := NewHMACSHA256Verifier(key, NewVerifyConfig().SetVerifyCreated(false), Fields{})
		if err != nil || verifier == nil {
			return
		}
		_, _ = msg.Verify("sig1", *verifier)
	})
}
