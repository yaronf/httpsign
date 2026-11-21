package httpsign

import (
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type httpsigPQVectorsFile struct {
	Version int `json:"version"`
	Vectors []struct {
		ID                           string `json:"id"`
		Algorithm                    string `json:"algorithm"`
		PrivateKeySeedHex            string `json:"private_key_seed_hex"`
		PublicKeyBase64              string `json:"public_key_base64"`
		SignatureBaseBase64          string `json:"signature_base_base64"`
		SignatureBaseLength          int    `json:"signature_base_length"`
		SignatureBaseSHA256          string `json:"signature_base_sha256"`
		SerializedSignatureInput     string `json:"serialized_signature_input"`
		DeterministicSignatureBase64 string `json:"deterministic_signature_base64"`
	} `json:"vectors"`
}

func loadHTTPSIGPQVectors(t *testing.T) httpsigPQVectorsFile {
	t.Helper()
	path := filepath.Join("testdata", "httpsig-pq-v1.0.1.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc httpsigPQVectorsFile
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.Equal(t, 1, doc.Version)
	require.Len(t, doc.Vectors, 3)
	return doc
}

func mldsaParamsForAlg(t *testing.T, alg string) mldsa.Parameters {
	t.Helper()
	switch alg {
	case "ml-dsa-44":
		return mldsa.MLDSA44()
	case "ml-dsa-65":
		return mldsa.MLDSA65()
	case "ml-dsa-87":
		return mldsa.MLDSA87()
	default:
		t.Fatalf("unknown algorithm %q", alg)
		return mldsa.Parameters{}
	}
}

func newNativeMLDSAVerifier(t *testing.T, alg string, pub *mldsa.PublicKey) *Verifier {
	t.Helper()
	var (
		v   *Verifier
		err error
	)
	switch alg {
	case "ml-dsa-44":
		v, err = NewMLDSA44Verifier(pub, NewVerifyConfig().SetVerifyCreated(false), *NewFields())
	case "ml-dsa-65":
		v, err = NewMLDSA65Verifier(pub, NewVerifyConfig().SetVerifyCreated(false), *NewFields())
	case "ml-dsa-87":
		v, err = NewMLDSA87Verifier(pub, NewVerifyConfig().SetVerifyCreated(false), *NewFields())
	default:
		t.Fatalf("unknown algorithm %q", alg)
	}
	require.NoError(t, err)
	return v
}

func TestHTTPSIGPQVectors(t *testing.T) {
	t.Parallel()
	doc := loadHTTPSIGPQVectors(t)

	for _, vec := range doc.Vectors {
		t.Run(vec.ID, func(t *testing.T) {
			t.Parallel()
			params := mldsaParamsForAlg(t, vec.Algorithm)

			seed, err := hex.DecodeString(vec.PrivateKeySeedHex)
			require.NoError(t, err)
			require.Len(t, seed, mldsa.PrivateKeySize)

			priv, err := mldsa.NewPrivateKey(params, seed)
			require.NoError(t, err)
			wantPub, err := base64.StdEncoding.DecodeString(vec.PublicKeyBase64)
			require.NoError(t, err)
			assert.Equal(t, wantPub, priv.PublicKey().Bytes())

			m, err := base64.StdEncoding.DecodeString(vec.SignatureBaseBase64)
			require.NoError(t, err)
			assert.Equal(t, vec.SignatureBaseLength, len(m))
			sum := sha256.Sum256(m)
			assert.Equal(t, vec.SignatureBaseSHA256, hex.EncodeToString(sum[:]))
			assert.NotContains(t, string(m), "\r")
			assert.False(t, len(m) > 0 && m[len(m)-1] == '\n')

			sig, err := base64.StdEncoding.DecodeString(vec.DeterministicSignatureBase64)
			require.NoError(t, err)
			assert.Equal(t, params.SignatureSize(), len(sig))

			pub := priv.PublicKey()
			verifier := newNativeMLDSAVerifier(t, vec.Algorithm, pub)
			ok, err := verifier.verify(m, sig)
			require.NoError(t, err)
			assert.True(t, ok)

			// Negatives from httpsig-pq: keep S, change inputs.
			flipped := append([]byte(nil), sig...)
			flipped[0] ^= 0x01
			ok, err = verifier.verify(m, flipped)
			assert.False(t, ok)
			require.Error(t, err)

			truncated := sig[:len(sig)-1]
			ok, err = verifier.verify(m, truncated)
			assert.False(t, ok)
			require.Error(t, err)

			extended := append(append([]byte(nil), sig...), 0x00)
			ok, err = verifier.verify(m, extended)
			assert.False(t, ok)
			require.Error(t, err)

			// Wrong public key, same parameter set.
			other, err := mldsa.GenerateKey(params)
			require.NoError(t, err)
			otherVer := newNativeMLDSAVerifier(t, vec.Algorithm, other.PublicKey())
			ok, err = otherVer.verify(m, sig)
			assert.False(t, ok)
			require.Error(t, err)

			// Change covered @signature-params alg spelling in M (LF preserved).
			old := `alg="` + vec.Algorithm + `"`
			var replacement string
			switch vec.Algorithm {
			case "ml-dsa-44":
				replacement = `alg="ml-dsa-65"`
			default:
				replacement = `alg="ml-dsa-44"`
			}
			require.Contains(t, string(m), old)
			tamperedM := []byte(strings.Replace(string(m), old, replacement, 1))
			ok, err = verifier.verify(tamperedM, sig)
			assert.False(t, ok)
			require.Error(t, err)

			// Append terminal LF to M.
			ok, err = verifier.verify(append(append([]byte(nil), m...), '\n'), sig)
			assert.False(t, ok)
			require.Error(t, err)
		})
	}
}
