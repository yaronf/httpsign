package httpsign

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FuzzSignAndVerifyJWS exercises foreign JWS (ES256) sign→verify over mutated requests.
// Keys are generated once outside the fuzz loop.
func FuzzSignAndVerifyJWS(f *testing.F) {
	f.Add(httpreq1)
	f.Add(httpreq2)
	f.Add("")
	f.Add("not an HTTP request")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(f, err)
	pub := &priv.PublicKey

	fields := *NewFields().AddHeader("@method").AddHeader("date").AddHeader("content-type")
	signer, err := NewJWSSigner(jwa.ES256(), priv, NewSignConfig().SignAlg(false).setFakeCreated(1618884475).SetKeyID("fuzz-es256"), fields)
	require.NoError(f, err)
	allowed, err := NewJWSAlgAllowlist(jwa.ES256())
	require.NoError(f, err)
	verifier, err := NewJWSVerifier(allowed, pub, NewVerifyConfig().SetVerifyCreated(false).SetKeyID("fuzz-es256"), fields)
	require.NoError(f, err)

	f.Fuzz(func(t *testing.T, reqString string) {
		req := readRequest(reqString)
		if req == nil {
			return
		}
		sigInput, sig, err := SignRequest("sig1", *signer, req)
		if err != nil {
			return
		}
		req.Header.Add("Signature-Input", sigInput)
		req.Header.Add("Signature", sig)
		assert.NoError(t, VerifyRequest("sig1", *verifier, req))
	})
}

// FuzzJWSVerifyRequest looks for panics when verifying attacker-controlled Signature headers
// with a foreign ES256 verifier (inferred *ecdsa.PublicKey path).
func FuzzJWSVerifyRequest(f *testing.F) {
	f.Add(httpreq1pssNoSig,
		`sig1=("@method");created=1618884475;keyid="fuzz-es256"`,
		`sig1=:AQAB:`)
	f.Add(httpreq1pssNoSig, "not-a-dictionary", "also-bad")
	f.Add(httpreq1pssNoSig, "", "")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(f, err)
	verifier, err := NewJWSVerifier(nil, &priv.PublicKey, NewVerifyConfig().SetVerifyCreated(false), *NewFields())
	require.NoError(f, err)

	f.Fuzz(func(t *testing.T, reqString, sigInput, sig string) {
		req := readRequest(reqString)
		if req == nil {
			return
		}
		req.Header.Set("Signature-Input", sigInput)
		req.Header.Set("Signature", sig)
		_ = VerifyRequest("sig1", *verifier, req)
	})
}

// FuzzSignAndVerifyMLDSA exercises foreign ML-DSA-44 sign→verify (cheapest parameter set).
func FuzzSignAndVerifyMLDSA(f *testing.F) {
	f.Add(httpreq1)
	f.Add(httpreq2)
	f.Add("")

	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(f, err)
	pub, ok := priv.Public().(*mldsa.PublicKey)
	require.True(f, ok)

	fields := *NewFields().AddHeader("@method").AddHeader("date")
	signer, err := NewJWSSigner(jwa.MLDSA44(), priv, NewSignConfig().SignAlg(false).setFakeCreated(1618884475).SetKeyID("fuzz-mldsa"), fields)
	require.NoError(f, err)
	allowed, err := NewJWSAlgAllowlist(jwa.MLDSA44())
	require.NoError(f, err)
	verifier, err := NewJWSVerifier(allowed, pub, NewVerifyConfig().SetVerifyCreated(false).SetKeyID("fuzz-mldsa"), fields)
	require.NoError(f, err)

	f.Fuzz(func(t *testing.T, reqString string) {
		req := readRequest(reqString)
		if req == nil {
			return
		}
		sigInput, sig, err := SignRequest("sig1", *signer, req)
		if err != nil {
			return
		}
		req.Header.Add("Signature-Input", sigInput)
		req.Header.Add("Signature", sig)
		assert.NoError(t, VerifyRequest("sig1", *verifier, req))
	})
}

// FuzzInferJWSVerifier feeds arbitrary JWK JSON into NewJWSVerifier (preferred infer path)
// and NewJWSVerifierWithAlg with a few fixed algs. Only panics are failures.
func FuzzInferJWSVerifier(f *testing.F) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(f, err)
	ecJWK, err := jwk.Import[jwk.Key](&p256.PublicKey)
	require.NoError(f, err)
	ecJSON, err := json.Marshal(ecJWK)
	require.NoError(f, err)

	_, edPub, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(f, err)
	edJWK, err := jwk.Import[jwk.Key](edPub)
	require.NoError(f, err)
	require.NoError(f, edJWK.Set(jwk.AlgorithmKey, jwa.EdDSAEd25519()))
	edJSON, err := json.Marshal(edJWK)
	require.NoError(f, err)

	mldsaPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(f, err)
	mldsaJWK, err := jwk.Import[jwk.Key](mldsaPriv.Public().(*mldsa.PublicKey))
	require.NoError(f, err)
	require.NoError(f, mldsaJWK.Set(jwk.AlgorithmKey, jwa.MLDSA44()))
	mldsaJSON, err := json.Marshal(mldsaJWK)
	require.NoError(f, err)

	f.Add(ecJSON)
	f.Add(edJSON)
	f.Add(mldsaJSON)
	f.Add([]byte(""))
	f.Add([]byte("not-json"))
	f.Add([]byte(`{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"}`))
	f.Add([]byte(`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`))
	f.Add([]byte(`{"kty":"AKP","alg":"ML-DSA-44","pub":"AAAA"}`))
	f.Add([]byte(`{"kty":"RSA","n":"AQAB","e":"AQAB"}`))
	f.Add([]byte(`{"kty":"oct","k":"AQAB"}`))

	allowed, err := NewJWSAlgAllowlist(
		jwa.ES256(), jwa.ES384(), jwa.ES512(),
		jwa.EdDSA(), jwa.EdDSAEd25519(),
		jwa.MLDSA44(), jwa.MLDSA65(), jwa.MLDSA87(),
		jwa.RS256(), jwa.PS256(),
	)
	require.NoError(f, err)

	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := jwk.ParseKeyAs[jwk.Key](data)
		if err != nil {
			return
		}
		_, _, _ = inferJWSVerifierKey(key)
		_, _ = NewJWSVerifier(nil, key, nil, *NewFields())
		_, _ = NewJWSVerifier(allowed, key, nil, *NewFields())
	})
}

// FuzzNewJWSConstructors hammers resolveRegisteredJWSAlg + key checks with fuzzed alg names
// against fixed key material (and nil keys).
func FuzzNewJWSConstructors(f *testing.F) {
	for _, alg := range []string{
		"ES256", "EdDSA", "Ed25519", "ML-DSA-44", "RS256", "HS256",
		"none", "NONE", "", "nope", "es256",
	} {
		f.Add(alg, true)
		f.Add(alg, false)
	}

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(f, err)
	_, edPub, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(f, err)
	mldsaPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(f, err)
	hmacKey := []byte("0123456789abcdef0123456789abcdef")

	keys := []any{
		ecPriv, &ecPriv.PublicKey,
		edPub,
		mldsaPriv, mldsaPriv.Public().(*mldsa.PublicKey),
		hmacKey,
		nil,
	}

	f.Fuzz(func(t *testing.T, algName string, useAllowlist bool) {
		alg := jwa.NewSignatureAlgorithm(algName)
		var allowed *JWSAlgAllowlist
		if useAllowlist {
			allowed, _ = NewJWSAlgAllowlist(jwa.ES256(), jwa.EdDSAEd25519(), jwa.MLDSA44())
		}
		for _, key := range keys {
			_, _ = NewJWSSigner(alg, key, nil, *NewFields())
			_, _ = NewJWSVerifierWithAlg(allowed, alg, key, nil, *NewFields())
		}
	})
}
