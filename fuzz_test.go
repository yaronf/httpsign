package httpsign

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
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
		signer, _ := NewHMACSHA256Signer("test-shared-secret", key, config, fields)
		req := readRequest(reqString)
		sigInput, sig, err := SignRequest(signatureName, *signer, req)
		if err == nil {
			req.Header.Add("Signature", sig)
			req.Header.Add("Signature-Input", sigInput)
			verifier, err := NewHMACSHA256Verifier("test-shared-secret", key, NewVerifyConfig().SetVerifyCreated(false), fields)
			assert.NoError(t, err, "could not generate Verifier")
			err = VerifyRequest(signatureName, *verifier, req)
			assert.NoError(t, err, "verification error")
		}
	})
}
