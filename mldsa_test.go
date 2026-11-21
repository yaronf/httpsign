package httpsign

import (
	"crypto/mldsa"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMLDSAConstructorsRejectNilAndMismatch(t *testing.T) {
	t.Parallel()

	priv44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	priv65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	pub44 := priv44.PublicKey()
	pub65 := priv65.PublicKey()

	_, err = NewMLDSA44Signer(nil, nil, *NewFields())
	require.Error(t, err)
	_, err = NewMLDSA44Signer(priv65, nil, *NewFields())
	require.Error(t, err)
	_, err = NewMLDSA44Verifier(nil, nil, *NewFields())
	require.Error(t, err)
	_, err = NewMLDSA44Verifier(pub65, nil, *NewFields())
	require.Error(t, err)

	_, err = NewMLDSA65Signer(priv44, nil, *NewFields())
	require.Error(t, err)
	_, err = NewMLDSA65Verifier(pub44, nil, *NewFields())
	require.Error(t, err)

	_, err = NewMLDSA87Signer(priv44, nil, *NewFields())
	require.Error(t, err)
	_, err = NewMLDSA87Verifier(pub44, nil, *NewFields())
	require.Error(t, err)
}

func TestMLDSARoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		params  mldsa.Parameters
		newSign func(*mldsa.PrivateKey, *SignConfig, Fields) (*Signer, error)
		newVer  func(*mldsa.PublicKey, *VerifyConfig, Fields) (*Verifier, error)
		alg     string
	}{
		{"44", mldsa.MLDSA44(), NewMLDSA44Signer, NewMLDSA44Verifier, "ml-dsa-44"},
		{"65", mldsa.MLDSA65(), NewMLDSA65Signer, NewMLDSA65Verifier, "ml-dsa-65"},
		{"87", mldsa.MLDSA87(), NewMLDSA87Signer, NewMLDSA87Verifier, "ml-dsa-87"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			priv, err := mldsa.GenerateKey(tc.params)
			require.NoError(t, err)
			pub := priv.PublicKey()
			fields := Headers("@method", "@path", "content-type")
			config := NewSignConfig().SetKeyID("test-mldsa").setFakeCreated(1618884475)
			signer, err := tc.newSign(priv, config, fields)
			require.NoError(t, err)
			assert.Equal(t, tc.alg, signer.alg)

			body := `{"hello":"world"}`
			req, err := http.NewRequest("POST", "https://example.com/foo", strings.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			sigInput, sig, err := SignRequest("sig1", *signer, req)
			require.NoError(t, err)
			assert.Contains(t, sigInput, `alg="`+tc.alg+`"`)
			req.Header.Set("Signature-Input", sigInput)
			req.Header.Set("Signature", sig)

			req.Body = io.NopCloser(strings.NewReader(body))
			verifier, err := tc.newVer(pub, NewVerifyConfig().SetKeyID("test-mldsa").SetVerifyCreated(false), fields)
			require.NoError(t, err)
			require.NoError(t, VerifyRequest("sig1", *verifier, req))
		})
	}
}

func TestMLDSAVerifyRejectsBadSignatureLength(t *testing.T) {
	t.Parallel()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	pub := priv.PublicKey()
	v, err := NewMLDSA44Verifier(pub, nil, *NewFields())
	require.NoError(t, err)
	ok, err := v.verify([]byte("msg"), []byte("short"))
	assert.False(t, ok)
	require.Error(t, err)
}

func TestMLDSASignVerifyRejectAlgKeyMismatch(t *testing.T) {
	t.Parallel()
	priv44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	priv65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	s, err := NewMLDSA44Signer(priv44, nil, *NewFields())
	require.NoError(t, err)
	s.alg = "ml-dsa-65"
	_, err = s.sign([]byte("msg"))
	require.Error(t, err)

	v, err := NewMLDSA44Verifier(priv44.PublicKey(), nil, *NewFields())
	require.NoError(t, err)
	sig, err := priv65.Sign(nil, []byte("msg"), &mldsa.Options{})
	require.NoError(t, err)
	// Verifier still holds a -44 key but claims -65.
	v.alg = "ml-dsa-65"
	ok, err := v.verify([]byte("msg"), sig)
	assert.False(t, ok)
	require.Error(t, err)
}

func TestMLDSASignProducesSignatureSize(t *testing.T) {
	t.Parallel()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	s, err := NewMLDSA44Signer(priv, nil, *NewFields())
	require.NoError(t, err)
	sig, err := s.sign([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, mldsa.MLDSA44().SignatureSize(), len(sig))
	// Hedged: two signatures over the same message differ with overwhelming probability.
	sig2, err := s.sign([]byte("hello"))
	require.NoError(t, err)
	assert.NotEqual(t, sig, sig2)
}
