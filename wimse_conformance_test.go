package httpsign

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WIMSE HTTP Message Signature profile (draft-ietf-wimse-http-signature-06).
// Vectors: https://github.com/kanywst/wimsey/tree/main/conformance/httpsig
//
// httpsign implements RFC 9421, not the WIMSE profile. This harness:
//  1. checks we can mint/verify the golden HTTP signature
//  2. overlays the profile checks a WIMSE verifier would do on top of
//     RequestDetails + ValidateContentDigestHeader + VerifyRequest
const wimseTag = "wimse-workload-to-workload"

type wimseHTTPRequest struct {
	Method    string      `json:"method"`
	Authority string      `json:"authority"`
	Path      string      `json:"path"`
	Query     *string     `json:"query"`
	Headers   [][2]string `json:"headers"`
}

type wimseNegative struct {
	ID                 string            `json:"id"`
	Description        string            `json:"description"`
	Expect             string            `json:"expect"`
	SignatureInput     string            `json:"signature_input"`
	Signature          string            `json:"signature"`
	Body               string            `json:"body"`
	Request            *wimseHTTPRequest `json:"request"`
	VerifyNow          int64             `json:"verify_now"`
	MaxAge             int64             `json:"max_age"`
	AcceptAudience     string            `json:"accept_audience"`
	AcceptLabel        string            `json:"accept_label"`
	RequiredComponents []string          `json:"required_components"`
}

type wimseSuite struct {
	Format               string            `json:"format"`
	ID                   string            `json:"id"`
	Spec                 string            `json:"spec"`
	Description          string            `json:"description"`
	PopSigningKeySeed    string            `json:"pop_signing_key_seed_b64u"`
	VerifyNow            int64             `json:"verify_now"`
	Label                string            `json:"label"`
	Components           []string          `json:"components"`
	Params               map[string]any    `json:"params"`
	Request              wimseHTTPRequest  `json:"request"`
	Body                 string            `json:"body"`
	SignatureInput       string            `json:"signature_input"`
	Signature            string            `json:"signature"`
	Negative             []wimseNegative   `json:"negative"`
}

func loadWimseSuite(t *testing.T) wimseSuite {
	t.Helper()
	b, err := os.ReadFile("testdata/wimse/sign-basic.json")
	require.NoError(t, err)
	var s wimseSuite
	require.NoError(t, json.Unmarshal(b, &s))
	return s
}

func wimseKeys(t *testing.T, seedB64u string) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(seedB64u)
	require.NoError(t, err)
	require.Len(t, seed, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

func wimseFields(components []string) Fields {
	names := make([]string, 0, len(components))
	for _, c := range components {
		names = append(names, strings.Trim(c, `"`))
	}
	return Headers(names...)
}

func wimseHTTPReq(t *testing.T, r wimseHTTPRequest, body string) *http.Request {
	t.Helper()
	path := r.Path
	if r.Query != nil && *r.Query != "" {
		path += "?" + *r.Query
	}
	req, err := http.NewRequest(r.Method, "https://"+r.Authority+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Host = r.Authority
	for _, h := range r.Headers {
		req.Header.Set(h[0], h[1])
	}
	return req
}

func wimseSignConfig(t *testing.T, params map[string]any) *SignConfig {
	t.Helper()
	cfg := NewSignConfig().SignAlg(false) // WIMSE forbids the alg parameter
	if v, ok := params["created"].(float64); ok {
		cfg.setFakeCreated(int64(v))
	}
	if v, ok := params["expires"].(float64); ok {
		cfg.SetExpires(int64(v))
	}
	if v, ok := params["nonce"].(string); ok {
		cfg.SetNonce(v)
	}
	if v, ok := params["tag"].(string); ok {
		cfg.SetTag(v)
	}
	if v, ok := params["wimse_aud"].(string); ok {
		cfg.AddCustomParam("wimse-aud", v)
	}
	return cfg
}

func wimseRFCVerifier(t *testing.T, pub ed25519.PublicKey, required Fields) *Verifier {
	t.Helper()
	// Golden vectors are from 2023; RFC 9421 clock/expiry use time.Now().
	v, err := NewEd25519Verifier(pub, NewVerifyConfig().
		SetVerifyCreated(false).
		SetRejectExpired(false).
		SetAllowedTags([]string{wimseTag}),
		required)
	require.NoError(t, err)
	return v
}

// wimseProfileError is the profile-layer failure class (vector "expect" values).
func wimseProfileCheck(details *MessageDetails, req *http.Request, now time.Time, maxAge time.Duration, acceptAudience string, required []string) string {
	if details.Alg != "" || details.KeyID != nil {
		return "forbidden_parameter"
	}
	if details.Nonce == nil || details.Expires == nil {
		return "missing_parameter"
	}
	if details.CustomParams == nil {
		return "missing_parameter"
	}
	aud, ok := details.CustomParams["wimse-aud"].(string)
	if !ok || aud == "" {
		return "missing_parameter"
	}
	if details.Tag == nil || *details.Tag != wimseTag {
		return "wrong_tag"
	}
	if acceptAudience != "" && aud != acceptAudience {
		return "audience_mismatch"
	}
	if details.Created != nil && details.Created.After(now) {
		return "created_in_future"
	}
	if maxAge > 0 && details.Created != nil && now.Sub(*details.Created) > maxAge {
		return "too_old"
	}
	if len(required) > 0 {
		need := wimseFields(required)
		if !details.Fields.contains(&need) {
			return "missing_required_component"
		}
	}
	cd := req.Header.Values("Content-Digest")
	if len(cd) > 0 {
		if err := ValidateContentDigestHeader(cd, &req.Body, []string{DigestSha256}); err != nil {
			return "content_digest_mismatch"
		}
	}
	return ""
}

func TestWimseSignBasic_Sign(t *testing.T) {
	s := loadWimseSuite(t)
	priv, _ := wimseKeys(t, s.PopSigningKeySeed)
	signer, err := NewEd25519Signer(priv, wimseSignConfig(t, s.Params), wimseFields(s.Components))
	require.NoError(t, err)

	req := wimseHTTPReq(t, s.Request, s.Body)
	sigInput, sig, err := SignRequest(s.Label, *signer, req)
	require.NoError(t, err)
	assert.Equal(t, s.SignatureInput, sigInput)
	assert.Equal(t, s.Signature, sig)
}

func TestWimseSignBasic_VerifyGolden(t *testing.T) {
	s := loadWimseSuite(t)
	_, pub := wimseKeys(t, s.PopSigningKeySeed)
	req := wimseHTTPReq(t, s.Request, s.Body)
	req.Header.Set("Signature-Input", s.SignatureInput)
	req.Header.Set("Signature", s.Signature)

	details, err := RequestDetails(s.Label, req)
	require.NoError(t, err)
	got := wimseProfileCheck(details, req, time.Unix(s.VerifyNow, 0), 0, "https://service.example/transfer", s.Components)
	require.Empty(t, got)

	err = VerifyRequest(s.Label, *wimseRFCVerifier(t, pub, wimseFields(s.Components)), req)
	require.NoError(t, err)
}

func TestWimseSignBasic_Negatives(t *testing.T) {
	s := loadWimseSuite(t)
	_, pub := wimseKeys(t, s.PopSigningKeySeed)

	for _, n := range s.Negative {
		t.Run(n.ID, func(t *testing.T) {
			body := s.Body
			if n.Body != "" {
				body = n.Body
			}
			httpReq := s.Request
			if n.Request != nil {
				httpReq = *n.Request
			}
			sigIn := s.SignatureInput
			if n.SignatureInput != "" {
				sigIn = n.SignatureInput
			}
			sig := s.Signature
			if n.Signature != "" {
				sig = n.Signature
			}
			label := s.Label
			if n.AcceptLabel != "" {
				label = n.AcceptLabel
			}
			now := s.VerifyNow
			if n.VerifyNow != 0 {
				now = n.VerifyNow
			}
			aud := "https://service.example/transfer"
			if n.AcceptAudience != "" {
				aud = n.AcceptAudience
			}

			req := wimseHTTPReq(t, httpReq, body)
			req.Header.Set("Signature-Input", sigIn)
			req.Header.Set("Signature", sig)

			if n.Expect == "label_mismatch" {
				_, err := RequestDetails(label, req)
				require.Error(t, err)
				return
			}

			details, err := RequestDetails(s.Label, req)
			require.NoError(t, err)

			var maxAge time.Duration
			if n.MaxAge != 0 {
				maxAge = time.Duration(n.MaxAge) * time.Second
			}
			class := wimseProfileCheck(details, req, time.Unix(now, 0), maxAge, aud, n.RequiredComponents)
			if class == "" {
				ver := wimseRFCVerifier(t, pub, wimseFields(s.Components))
				if err := VerifyRequest(s.Label, *ver, req); err != nil {
					class = "invalid_signature"
				}
			}
			assert.Equal(t, n.Expect, class, n.Description)
		})
	}
}
