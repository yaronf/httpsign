package httpsign

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WIMSE HTTP Message Signature profile (draft-ietf-wimse-http-signature-06).
// Vectors: https://github.com/kanywst/wimsey/tree/main/conformance/httpsig
//
// httpsign implements RFC 9421, not the WIMSE profile. This harness:
//  1. checks we can mint/verify the golden HTTP signatures
//  2. overlays the profile checks a WIMSE verifier would do on top of
//     RequestDetails/ResponseDetails + ValidateContentDigestHeader + VerifyRequest/VerifyResponse
const wimseTag = "wimse-workload-to-workload"

var wimseVectorFiles = []string{
	"sign-eddsa.json",
	"sign-es256.json",
}

type wimseJWK struct {
	Alg string `json:"alg"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d"`
}

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
	ExpectedReqNonce   string            `json:"expected_req_nonce"`
}

type wimseResponse struct {
	Status           int             `json:"status"`
	Headers          [][2]string     `json:"headers"`
	Body             string          `json:"body"`
	Components       []string        `json:"components"`
	Params           map[string]any  `json:"params"`
	SignatureInput   string          `json:"signature_input"`
	Signature        string          `json:"signature"`
	ExpectedReqNonce string          `json:"expected_req_nonce"`
	Negative         []wimseNegative `json:"negative"`
}

type wimseSuite struct {
	Format        string           `json:"format"`
	ID            string           `json:"id"`
	Spec          string           `json:"spec"`
	Description   string           `json:"description"`
	PopSigningKey wimseJWK         `json:"pop_signing_key"`
	VerifyNow     int64            `json:"verify_now"`
	Label         string           `json:"label"`
	Components    []string         `json:"components"`
	Params        map[string]any   `json:"params"`
	Request       wimseHTTPRequest `json:"request"`
	Body          string           `json:"body"`
	SignatureInput string          `json:"signature_input"`
	Signature     string           `json:"signature"`
	Negative      []wimseNegative  `json:"negative"`
	Response      *wimseResponse   `json:"response"`
}

func loadWimseSuite(t *testing.T, name string) wimseSuite {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "wimse", name))
	require.NoError(t, err)
	var s wimseSuite
	require.NoError(t, json.Unmarshal(b, &s))
	return s
}

func wimseB64u(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

func wimseEd25519Key(t *testing.T, jwk wimseJWK) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	require.Equal(t, "EdDSA", jwk.Alg)
	seed := wimseB64u(t, jwk.D)
	require.Len(t, seed, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

func wimseP256Key(t *testing.T, jwk wimseJWK) (*ecdsa.PrivateKey, ecdsa.PublicKey) {
	t.Helper()
	require.Equal(t, "ES256", jwk.Alg)
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()},
		D:         new(big.Int).SetBytes(wimseB64u(t, jwk.D)),
	}
	priv.X = new(big.Int).SetBytes(wimseB64u(t, jwk.X))
	priv.Y = new(big.Int).SetBytes(wimseB64u(t, jwk.Y))
	return priv, priv.PublicKey
}

type wimseKeyPair struct {
	newSigner  func(*SignConfig, Fields) (*Signer, error)
	newVerifier func(*VerifyConfig, Fields) (*Verifier, error)
}

func wimseKeyPairFromJWK(t *testing.T, jwk wimseJWK) wimseKeyPair {
	t.Helper()
	switch jwk.Alg {
	case "EdDSA":
		priv, pub := wimseEd25519Key(t, jwk)
		return wimseKeyPair{
			newSigner: func(cfg *SignConfig, fields Fields) (*Signer, error) {
				return NewEd25519Signer(priv, cfg, fields)
			},
			newVerifier: func(cfg *VerifyConfig, fields Fields) (*Verifier, error) {
				return NewEd25519Verifier(pub, cfg, fields)
			},
		}
	case "ES256":
		priv, pub := wimseP256Key(t, jwk)
		return wimseKeyPair{
			newSigner: func(cfg *SignConfig, fields Fields) (*Signer, error) {
				return NewP256Signer(*priv, cfg, fields)
			},
			newVerifier: func(cfg *VerifyConfig, fields Fields) (*Verifier, error) {
				return NewP256Verifier(pub, cfg, fields)
			},
		}
	default:
		t.Fatalf("unsupported signing key alg %q", jwk.Alg)
		return wimseKeyPair{}
	}
}

func wimseFieldsFromComponents(t *testing.T, components []string) Fields {
	t.Helper()
	fs := NewFields()
	for _, c := range components {
		item, err := httpsfv.UnmarshalItem([]string{c})
		require.NoError(t, err, "component %q", c)
		fs.f = append(fs.f, field(item))
	}
	return *fs
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

func wimseHTTPRes(t *testing.T, status int, headers [][2]string, body string) *http.Response {
	t.Helper()
	res := &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	for _, h := range headers {
		res.Header.Set(h[0], h[1])
	}
	return res
}

func wimseSignConfig(t *testing.T, params map[string]any, forResponse bool) *SignConfig {
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
	if forResponse {
		if v, ok := params["wimse_req_nonce"].(string); ok && v != "" {
			cfg.AddCustomParam("wimse-req-nonce", v)
		}
	} else {
		if v, ok := params["wimse_aud"].(string); ok && v != "" {
			cfg.AddCustomParam("wimse-aud", v)
		}
		if v, ok := params["wimse_sign_response"].(bool); ok && v {
			cfg.AddCustomParam("wimse-sign-response", true)
		}
	}
	return cfg
}

func wimseVerifyConfig() *VerifyConfig {
	return NewVerifyConfig().
		SetVerifyCreated(false).
		SetRejectExpired(false).
		SetAllowedTags([]string{wimseTag})
}

func wimseRFCVerifier(t *testing.T, keys wimseKeyPair, required Fields) *Verifier {
	t.Helper()
	v, err := keys.newVerifier(wimseVerifyConfig(), required)
	require.NoError(t, err)
	return v
}

// wimseRequestProfileCheck is the request profile-layer failure class (vector "expect" values).
func wimseRequestProfileCheck(t *testing.T, details *MessageDetails, req *http.Request, now time.Time, maxAge time.Duration, acceptAudience string, required []string) string {
	if details.Alg != "" || details.KeyID != nil {
		return "forbidden_parameter"
	}
	if details.Created == nil || details.Nonce == nil || details.Expires == nil {
		return "missing_parameter"
	}
	if details.CustomParams == nil {
		return "missing_parameter"
	}
	aud, ok := details.CustomParams["wimse-aud"].(string)
	if !ok || aud == "" {
		return "missing_parameter"
	}
	if _, ok := details.CustomParams["wimse-sign-response"].(bool); !ok {
		return "missing_parameter"
	}
	if details.Tag == nil || *details.Tag != wimseTag {
		return "wrong_tag"
	}
	if acceptAudience != "" && aud != acceptAudience {
		return "audience_mismatch"
	}
	if details.Created.After(now) {
		return "created_in_future"
	}
	if maxAge > 0 && now.Sub(*details.Created) > maxAge {
		return "too_old"
	}
	if len(required) > 0 {
		need := wimseFieldsFromComponents(t, required)
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

// wimseResponseProfileCheck is the response profile-layer failure class.
func wimseResponseProfileCheck(t *testing.T, details *MessageDetails, res *http.Response, now time.Time, maxAge time.Duration, expectedReqNonce string, required []string) string {
	if details.Alg != "" || details.KeyID != nil {
		return "forbidden_parameter"
	}
	if details.Created == nil || details.Nonce == nil || details.Expires == nil {
		return "missing_parameter"
	}
	if details.CustomParams == nil {
		return "missing_parameter"
	}
	if aud, ok := details.CustomParams["wimse-aud"].(string); ok && aud != "" {
		return "forbidden_parameter"
	}
	reqNonce, ok := details.CustomParams["wimse-req-nonce"].(string)
	if !ok || reqNonce == "" {
		return "missing_parameter"
	}
	if expectedReqNonce != "" && reqNonce != expectedReqNonce {
		return "request_nonce_mismatch"
	}
	if details.Tag == nil || *details.Tag != wimseTag {
		return "wrong_tag"
	}
	if details.Created.After(now) {
		return "created_in_future"
	}
	if maxAge > 0 && now.Sub(*details.Created) > maxAge {
		return "too_old"
	}
	if len(required) > 0 {
		need := wimseFieldsFromComponents(t, required)
		if !details.Fields.contains(&need) {
			return "missing_required_component"
		}
	}
	cd := res.Header.Values("Content-Digest")
	if len(cd) > 0 {
		if err := ValidateContentDigestHeader(cd, &res.Body, []string{DigestSha256}); err != nil {
			return "content_digest_mismatch"
		}
	}
	return ""
}

func TestWimseConformance(t *testing.T) {
	for _, file := range wimseVectorFiles {
		t.Run(strings.TrimSuffix(file, ".json"), func(t *testing.T) {
			s := loadWimseSuite(t, file)
			keys := wimseKeyPairFromJWK(t, s.PopSigningKey)
			reqFields := wimseFieldsFromComponents(t, s.Components)

			t.Run("Sign", func(t *testing.T) {
				signer, err := keys.newSigner(wimseSignConfig(t, s.Params, false), reqFields)
				require.NoError(t, err)
				req := wimseHTTPReq(t, s.Request, s.Body)
				sigInput, sig, err := SignRequest(s.Label, *signer, req)
				require.NoError(t, err)
				assert.Equal(t, s.SignatureInput, sigInput)
				if s.PopSigningKey.Alg == "EdDSA" {
					assert.Equal(t, s.Signature, sig)
				}
				req.Header.Set("Signature-Input", sigInput)
				req.Header.Set("Signature", sig)
				err = VerifyRequest(s.Label, *wimseRFCVerifier(t, keys, reqFields), req)
				require.NoError(t, err)
			})

			t.Run("VerifyGolden", func(t *testing.T) {
				req := wimseHTTPReq(t, s.Request, s.Body)
				req.Header.Set("Signature-Input", s.SignatureInput)
				req.Header.Set("Signature", s.Signature)

				details, err := RequestDetails(s.Label, req)
				require.NoError(t, err)
				got := wimseRequestProfileCheck(t, details, req, time.Unix(s.VerifyNow, 0), 0, "https://service.example/transfer", s.Components)
				require.Empty(t, got)

				err = VerifyRequest(s.Label, *wimseRFCVerifier(t, keys, reqFields), req)
				require.NoError(t, err)
			})

			t.Run("Negatives", func(t *testing.T) {
				for _, n := range s.Negative {
					t.Run(n.ID, func(t *testing.T) {
						runWimseRequestNegative(t, s, keys, reqFields, n)
					})
				}
			})

			if s.Response == nil {
				return
			}
			resp := s.Response
			resFields := wimseFieldsFromComponents(t, resp.Components)
			assocReq := wimseHTTPReq(t, s.Request, s.Body)

			t.Run("ResponseSign", func(t *testing.T) {
				signer, err := keys.newSigner(wimseSignConfig(t, resp.Params, true), resFields)
				require.NoError(t, err)
				res := wimseHTTPRes(t, resp.Status, resp.Headers, resp.Body)
				sigInput, sig, err := SignResponse(s.Label, *signer, res, assocReq)
				require.NoError(t, err)
				assert.Equal(t, resp.SignatureInput, sigInput)
				if s.PopSigningKey.Alg == "EdDSA" {
					assert.Equal(t, resp.Signature, sig)
				}
				res.Header.Set("Signature-Input", sigInput)
				res.Header.Set("Signature", sig)
				err = VerifyResponse(s.Label, *wimseRFCVerifier(t, keys, resFields), res, assocReq)
				require.NoError(t, err)
			})

			t.Run("ResponseVerifyGolden", func(t *testing.T) {
				res := wimseHTTPRes(t, resp.Status, resp.Headers, resp.Body)
				res.Header.Set("Signature-Input", resp.SignatureInput)
				res.Header.Set("Signature", resp.Signature)

				details, err := ResponseDetails(s.Label, res)
				require.NoError(t, err)
				got := wimseResponseProfileCheck(t, details, res, time.Unix(s.VerifyNow, 0), 0, resp.ExpectedReqNonce, resp.Components)
				require.Empty(t, got)

				err = VerifyResponse(s.Label, *wimseRFCVerifier(t, keys, resFields), res, assocReq)
				require.NoError(t, err)
			})

			t.Run("ResponseNegatives", func(t *testing.T) {
				for _, n := range resp.Negative {
					t.Run(n.ID, func(t *testing.T) {
						runWimseResponseNegative(t, s, resp, keys, resFields, assocReq, n)
					})
				}
			})
		})
	}
}

func runWimseRequestNegative(t *testing.T, s wimseSuite, keys wimseKeyPair, reqFields Fields, n wimseNegative) {
	t.Helper()
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
	class := wimseRequestProfileCheck(t, details, req, time.Unix(now, 0), maxAge, aud, n.RequiredComponents)
	if class == "" {
		ver := wimseRFCVerifier(t, keys, reqFields)
		if err := VerifyRequest(s.Label, *ver, req); err != nil {
			class = "invalid_signature"
		}
	}
	assert.Equal(t, n.Expect, class, n.Description)
}

func runWimseResponseNegative(t *testing.T, s wimseSuite, resp *wimseResponse, keys wimseKeyPair, resFields Fields, defaultReq *http.Request, n wimseNegative) {
	t.Helper()
	assocReq := defaultReq
	if n.Request != nil {
		assocReq = wimseHTTPReq(t, *n.Request, s.Body)
	}
	res := wimseHTTPRes(t, resp.Status, resp.Headers, resp.Body)
	res.Header.Set("Signature-Input", resp.SignatureInput)
	res.Header.Set("Signature", resp.Signature)

	details, err := ResponseDetails(s.Label, res)
	require.NoError(t, err)

	expectedReqNonce := resp.ExpectedReqNonce
	if n.ExpectedReqNonce != "" {
		expectedReqNonce = n.ExpectedReqNonce
	}

	class := wimseResponseProfileCheck(t, details, res, time.Unix(s.VerifyNow, 0), 0, expectedReqNonce, n.RequiredComponents)
	if class == "" {
		ver := wimseRFCVerifier(t, keys, resFields)
		if err := VerifyResponse(s.Label, *ver, res, assocReq); err != nil {
			class = "invalid_signature"
		}
	}
	assert.Equal(t, n.Expect, class, n.Description)
}
