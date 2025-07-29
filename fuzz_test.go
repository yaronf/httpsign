package httpsign

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

var httpreq1pssNoSig = `POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
Content-Length: 18

{"hello": "world"}
`

func FuzzVerifyRequest(f *testing.F) {
	type inputs struct {
		req, sigInput, sig string
	}
	testcases := []inputs{
		{httpreq1pssNoSig,
			"sig-b21=();created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"b3k2pp5k7z-50gnwp.yemd\"",
			"sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:",
		},
		{httpreq1pssNoSig,
			"sig-b21=(date);created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"xxxb3k5k7z-50gnwp.yemd\"",
			"sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:",
		},
		{httpreq1pssNoSig,
			"sig-b21=(some-field;tr);created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"xxxb3k5k7z-50gnwp.yemd\"",
			"sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:",
		},
		{httpreq1pssNoSig,
			"sig-b22=(some-field;tr;bs);created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"xxxb3k5k7z-50gnwp.yemd\"",
			"sig-b22=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:",
		},
	}
	for _, tc := range testcases {
		f.Add(tc.req, tc.sigInput, tc.sig) // Use f.Add to provide a seed corpus
	}
	f.Fuzz(func(t *testing.T, reqString, sigInput, sig string) {
		req := readRequest(reqString)
		if req != nil {
			req.Header.Set("Signature-Input", sigInput)
			req.Header.Set("Signature", sig)
		}

		sigName := "sig-b21"
		verifier := makeRSAVerifier(f, "key1", *NewFields())
		_ = VerifyRequest(sigName, verifier, req)
		// only report panics
	})
}

// Same as FuzzVerifyRequest but using Message
func FuzzMessageVerifyRequest(f *testing.F) {
	type inputs struct {
		req, sigInput, sig string
	}
	testcases := []inputs{
		{httpreq1pssNoSig,
			"sig-b21=();created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"b3k2pp5k7z-50gnwp.yemd\"",
			"sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:",
		},
		{httpreq1pssNoSig,
			"sig-b21=(date);created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"xxxb3k5k7z-50gnwp.yemd\"",
			"sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:",
		},
		{httpreq1pssNoSig,
			"sig-b21=(some-field;tr);created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"xxxb3k5k7z-50gnwp.yemd\"",
			"sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:",
		},
		{httpreq1pssNoSig,
			"sig-b22=(some-field;tr;bs);created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"xxxb3k5k7z-50gnwp.yemd\"",
			"sig-b22=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:",
		},
	}
	for _, tc := range testcases {
		f.Add(tc.req, tc.sigInput, tc.sig) // Use f.Add to provide a seed corpus
	}
	f.Fuzz(func(t *testing.T, reqString, sigInput, sig string) {
		req := readRequest(reqString)
		if req != nil {
			req.Header.Set("Signature-Input", sigInput)
			req.Header.Set("Signature", sig)
		}

		sigName := "sig-b21"
		verifier := makeRSAVerifier(f, "key1", *NewFields())
		msg, err := NewMessage(NewMessageConfig().WithRequest(req))
		if err != nil {
			t.Errorf("Failed to create Message")
		}
		_, _ = msg.Verify(sigName, verifier)
		// only report panics
	})
}

func FuzzSignAndVerifyHMAC(f *testing.F) {
	type inputs struct {
		req string
	}
	testcases := []inputs{
		{httpreq1},
	}
	for _, tc := range testcases {
		f.Add(tc.req)
	}
	f.Fuzz(func(t *testing.T, reqString string) {
		config := NewSignConfig().SignAlg(false).setFakeCreated(1618884475)
		fields := Headers("@authority", "date", "content-type")
		signatureName := "sig1"
		key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
		signer, _ := NewHMACSHA256Signer(key, config.SetKeyID("test-shared-secret"), fields)
		req := readRequest(reqString)
		sigInput, sig, err := SignRequest(signatureName, *signer, req)
		if err == nil {
			req.Header.Add("Signature", sig)
			req.Header.Add("Signature-Input", sigInput)
			verifier, err := NewHMACSHA256Verifier(key, NewVerifyConfig().SetVerifyCreated(false).SetKeyID("test-shared-secret"), fields)
			assert.NoError(t, err, "could not generate Verifier")
			err = VerifyRequest(signatureName, *verifier, req)
			assert.NoError(t, err, "verification error")
		}
	})
}

// Same as FuzzSignAndVerifyHMAC but using Message
func FuzzMessageSignAndVerifyHMAC(f *testing.F) {
	type inputs struct {
		req string
	}
	testcases := []inputs{
		{httpreq1},
	}
	for _, tc := range testcases {
		f.Add(tc.req)
	}
	f.Fuzz(func(t *testing.T, reqString string) {
		config := NewSignConfig().SignAlg(false).setFakeCreated(1618884475)
		fields := Headers("@authority", "date", "content-type")
		signatureName := "sig1"
		key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
		signer, _ := NewHMACSHA256Signer(key, config.SetKeyID("test-shared-secret"), fields)
		req := readRequest(reqString)
		sigInput, sig, err := SignRequest(signatureName, *signer, req)
		if err == nil {
			req.Header.Add("Signature", sig)
			req.Header.Add("Signature-Input", sigInput)
			verifier, err := NewHMACSHA256Verifier(key, NewVerifyConfig().SetVerifyCreated(false).SetKeyID("test-shared-secret"), fields)
			assert.NoError(t, err, "could not generate Verifier")
			msg, err := NewMessage(NewMessageConfig().WithRequest(req))
			if err != nil {
				t.Errorf("Failed to create Message")
			}
			_, err = msg.Verify(signatureName, *verifier)
			assert.NoError(t, err, "verification error")
		}
	})
}

func FuzzMessageVerify(f *testing.F) {
	f.Add("GET", "https://example.com/path", "example.com", "https", 0, "", "", "", "", true, false)
	f.Add("POST", "https://api.example.com", "api.example.com", "https", 0, "", "", "", "", false, true)
	f.Add("", "", "", "", 200, "GET", "https://example.com", "example.com", "https", true, false)
	f.Add("PUT", "", "", "http", 0, "", "", "", "", false, false)
	f.Add("", "", "", "", 404, "", "", "", "", false, false)
	f.Add("0", "%", "0", "0", 0, "", "", "", "", true, false)

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
				"Content-Type": []string{"application/json"},
				"X-Test":       []string{"fuzz"},
			}
			config = config.WithHeaders(headers)
		}
		if hasTrailers {
			trailers := http.Header{
				"X-Trailer": []string{"test"},
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

		if err == nil {
			if msg.headers == nil && msg.method != "" {
				t.Errorf("Request message created without headers")
			}
			if msg.headers == nil && msg.statusCode != nil {
				t.Errorf("Response message created without headers")
			}

			key, _ := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
			verifier, _ := NewHMACSHA256Verifier(key, NewVerifyConfig().SetVerifyCreated(false), Fields{})

			if msg.headers != nil {
				msg.headers.Set("Signature-Input", `sig1=("@method");created=1618884473;keyid="test-key"`)
				msg.headers.Set("Signature", `sig1=:test:`)
			}

			_, _ = msg.Verify("sig1", *verifier)
		}

		if err != nil {
			hasRequest := method != ""
			hasResponse := statusCode > 0

			if !hasRequest && !hasResponse {
				assert.Contains(t, err.Error(), "must have either method")
			} else if hasRequest && hasResponse {
				assert.Contains(t, err.Error(), "cannot have both request and response")
			} else if (hasRequest || hasResponse) && !hasHeaders {
				assert.Contains(t, err.Error(), "must have headers")
			}
		}
	})
}
