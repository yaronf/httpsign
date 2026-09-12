package httpsign

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/require"
)

func TestValidateJWSKeyAlgPassthrough(t *testing.T) {
	// Unknown / future algs are left to jwx (default branch). Constructors reject
	// unregistered names first via resolveRegisteredJWSAlg.
	require.NoError(t, validateJWSKeyAlg(jwa.EmptySignatureAlgorithm(), []byte("x"), true))
}

func TestResolveRegisteredJWSAlg(t *testing.T) {
	got, err := resolveRegisteredJWSAlg(jwa.NewSignatureAlgorithm("HS256"))
	require.NoError(t, err)
	require.Equal(t, jwa.HS256(), got)

	_, err = resolveRegisteredJWSAlg(jwa.EmptySignatureAlgorithm())
	require.Error(t, err)
	_, err = resolveRegisteredJWSAlg(jwa.NoSignature())
	require.Error(t, err)
	_, err = resolveRegisteredJWSAlg(jwa.NewSignatureAlgorithm("NONE"))
	require.Error(t, err)
	_, err = resolveRegisteredJWSAlg(jwa.NewSignatureAlgorithm("totally-made-up"))
	require.Error(t, err)
}

func TestValidateHMACKey(t *testing.T) {
	require.NoError(t, validateHMACKey(jwa.HS256(), []byte(strings.Repeat("a", 32))))
	require.NoError(t, validateHMACKey(jwa.HS384(), []byte(strings.Repeat("a", 48))))
	require.NoError(t, validateHMACKey(jwa.HS512(), []byte(strings.Repeat("a", 64))))

	require.Error(t, validateHMACKey(jwa.HS256(), "not-bytes"))
	require.Error(t, validateHMACKey(jwa.HS384(), []byte(strings.Repeat("a", 47))))
	require.Error(t, validateHMACKey(jwa.HS512(), []byte(strings.Repeat("a", 63))))
	require.Error(t, validateHMACKey(jwa.ES256(), []byte(strings.Repeat("a", 32)))) // unsupported HMAC alg
}

func TestValidateRSAKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	pub := &priv.PublicKey

	require.NoError(t, validateRSAKey(jwa.RS256(), priv, true))
	require.NoError(t, validateRSAKey(jwa.PS256(), pub, false))
	require.NoError(t, validateRSAKey(jwa.RS384(), *priv, true))
	require.NoError(t, validateRSAKey(jwa.RS512(), *pub, false))

	var nilPriv *rsa.PrivateKey
	var nilPub *rsa.PublicKey
	require.Error(t, validateRSAKey(jwa.RS256(), nilPriv, true))
	require.Error(t, validateRSAKey(jwa.RS256(), nilPub, false))
	require.Error(t, validateRSAKey(jwa.RS256(), priv, false))  // private for verify
	require.Error(t, validateRSAKey(jwa.RS256(), *priv, false)) // value private for verify
	require.Error(t, validateRSAKey(jwa.RS256(), pub, true))    // public for sign
	require.Error(t, validateRSAKey(jwa.RS256(), *pub, true))   // value public for sign
	require.Error(t, validateRSAKey(jwa.RS256(), []byte("x"), true))
}

func TestValidateECDSAKey(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	require.NoError(t, validateECDSAKey(jwa.ES256(), p256, true))
	require.NoError(t, validateECDSAKey(jwa.ES256(), &p256.PublicKey, false))
	require.NoError(t, validateECDSAKey(jwa.ES384(), p384, true))
	require.NoError(t, validateECDSAKey(jwa.ES512(), p521, true))

	// value types via ecdsaKeyOf
	require.NoError(t, validateECDSAKey(jwa.ES256(), *p256, true))
	require.NoError(t, validateECDSAKey(jwa.ES256(), p256.PublicKey, false))

	require.Error(t, validateECDSAKey(jwa.ES256(), []byte("x"), true))
	require.Error(t, validateECDSAKey(jwa.ES256(), &p256.PublicKey, true))
	require.Error(t, validateECDSAKey(jwa.ES256(), p256, false))
	require.Error(t, validateECDSAKey(jwa.ES256(), &ecdsa.PublicKey{Curve: nil, X: big.NewInt(1), Y: big.NewInt(1)}, false))
	require.Error(t, validateECDSAKey(jwa.ES256(), p384, true)) // curve mismatch
	require.Error(t, validateECDSAKey(jwa.HS256(), p256, true)) // unsupported ECDSA alg

	var nilPriv *ecdsa.PrivateKey
	var nilPub *ecdsa.PublicKey
	_, _, ok := ecdsaKeyOf(nilPriv)
	require.False(t, ok)
	_, _, ok = ecdsaKeyOf(nilPub)
	require.False(t, ok)
	_, _, ok = ecdsaKeyOf("nope")
	require.False(t, ok)
}

func TestValidateEd25519Key(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	require.NoError(t, validateEd25519Key(jwa.EdDSA(), priv, true))
	require.NoError(t, validateEd25519Key(jwa.EdDSAEd25519(), pub, false))
	require.NoError(t, validateEd25519Key(jwa.EdDSA(), &priv, true))
	require.NoError(t, validateEd25519Key(jwa.EdDSA(), &pub, false))

	require.Error(t, validateEd25519Key(jwa.EdDSA(), ed25519.PrivateKey(strings.Repeat("a", 63)), true))
	require.Error(t, validateEd25519Key(jwa.EdDSA(), priv, false))
	require.Error(t, validateEd25519Key(jwa.EdDSA(), ed25519.PublicKey(strings.Repeat("a", 31)), false))
	require.Error(t, validateEd25519Key(jwa.EdDSA(), pub, true))

	var nilPriv *ed25519.PrivateKey
	var nilPub *ed25519.PublicKey
	require.Error(t, validateEd25519Key(jwa.EdDSA(), nilPriv, true))
	require.Error(t, validateEd25519Key(jwa.EdDSA(), nilPub, false))
	badPriv := ed25519.PrivateKey(strings.Repeat("a", 63))
	badPub := ed25519.PublicKey(strings.Repeat("a", 31))
	require.Error(t, validateEd25519Key(jwa.EdDSA(), &badPriv, true))
	require.Error(t, validateEd25519Key(jwa.EdDSA(), &badPub, false))
	require.Error(t, validateEd25519Key(jwa.EdDSA(), &priv, false))
	require.Error(t, validateEd25519Key(jwa.EdDSA(), &pub, true))
	require.Error(t, validateEd25519Key(jwa.EdDSA(), []byte("x"), true))
}

func TestValidateMLDSAKey(t *testing.T) {
	priv44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	pub44 := priv44.Public().(*mldsa.PublicKey)
	priv65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	require.NoError(t, validateMLDSAKey(jwa.MLDSA44(), priv44, true))
	require.NoError(t, validateMLDSAKey(jwa.MLDSA44(), pub44, false))
	require.Error(t, validateMLDSAKey(jwa.MLDSA44(), pub44, true))
	require.Error(t, validateMLDSAKey(jwa.MLDSA44(), priv44, false))
	require.Error(t, validateMLDSAKey(jwa.MLDSA44(), priv65, true)) // params mismatch
	require.Error(t, validateMLDSAKey(jwa.MLDSA44(), []byte("x"), true))
	require.Error(t, validateMLDSAKey(jwa.HS256(), priv44, true)) // unsupported ML-DSA alg

	var nilPriv *mldsa.PrivateKey
	var nilPub *mldsa.PublicKey
	_, _, ok := mldsaKeyOf(nilPriv)
	require.False(t, ok)
	_, _, ok = mldsaKeyOf(nilPub)
	require.False(t, ok)
	_, _, ok = mldsaKeyOf("nope")
	require.False(t, ok)
}
