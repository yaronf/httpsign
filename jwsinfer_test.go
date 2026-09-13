package httpsign

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

func TestNewJWSVerifierFromJWK(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("ec crv without alg", func(t *testing.T) {
		ecJWK, err := jwk.Import[jwk.Key](&p256.PublicKey)
		require.NoError(t, err)
		v, err := NewJWSVerifier(nil, ecJWK, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v)
	})

	t.Run("ec with matching alg", func(t *testing.T) {
		ecJWK, err := jwk.Import[jwk.Key](&p256.PublicKey)
		require.NoError(t, err)
		require.NoError(t, ecJWK.Set(jwk.AlgorithmKey, jwa.ES256()))
		v, err := NewJWSVerifier(nil, ecJWK, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v)
	})

	t.Run("ec alg disagrees with crv", func(t *testing.T) {
		ecJWK, err := jwk.Import[jwk.Key](&p256.PublicKey)
		require.NoError(t, err)
		require.NoError(t, ecJWK.Set(jwk.AlgorithmKey, jwa.ES384()))
		_, err = NewJWSVerifier(nil, ecJWK, nil, *NewFields())
		require.Error(t, err)
	})

	t.Run("ec private jwk exports public", func(t *testing.T) {
		ecJWK, err := jwk.Import[jwk.Key](p256)
		require.NoError(t, err)
		alg, raw, err := inferFromJWK(ecJWK)
		require.NoError(t, err)
		require.Equal(t, jwa.ES256().String(), alg.String())
		_, ok := raw.(*ecdsa.PublicKey)
		require.True(t, ok)
	})

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("rsa without alg", func(t *testing.T) {
		rsaJWK, err := jwk.Import[jwk.Key](&rsaPriv.PublicKey)
		require.NoError(t, err)
		_, err = NewJWSVerifier(nil, rsaJWK, nil, *NewFields())
		require.Error(t, err)
	})

	t.Run("rsa with alg", func(t *testing.T) {
		rsaJWK, err := jwk.Import[jwk.Key](&rsaPriv.PublicKey)
		require.NoError(t, err)
		require.NoError(t, rsaJWK.Set(jwk.AlgorithmKey, jwa.RS256()))
		v, err := NewJWSVerifier(nil, rsaJWK, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v)
	})

	t.Run("oct without alg", func(t *testing.T) {
		octJWK, err := jwk.Import[jwk.Key]([]byte("0123456789abcdef0123456789abcdef"))
		require.NoError(t, err)
		_, err = NewJWSVerifier(nil, octJWK, nil, *NewFields())
		require.Error(t, err)
	})

	t.Run("unknown jwk alg", func(t *testing.T) {
		ecJWK, err := jwk.Import[jwk.Key](&p256.PublicKey)
		require.NoError(t, err)
		require.NoError(t, ecJWK.Set(jwk.AlgorithmKey, "A256GCM"))
		_, err = NewJWSVerifier(nil, ecJWK, nil, *NewFields())
		require.Error(t, err)
	})

	mldsaPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	t.Run("mldsa jwk with alg", func(t *testing.T) {
		mldsaJWK, err := jwk.Import[jwk.Key](mldsaPriv.Public().(*mldsa.PublicKey))
		require.NoError(t, err)
		require.NoError(t, mldsaJWK.Set(jwk.AlgorithmKey, jwa.MLDSA44()))
		v, err := NewJWSVerifier(nil, mldsaJWK, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v)
	})

	t.Run("mldsa akp without alg", func(t *testing.T) {
		mldsaJWK, err := jwk.Import[jwk.Key](mldsaPriv.Public().(*mldsa.PublicKey))
		require.NoError(t, err)
		// jwx sets alg on import; strip it to exercise the AKP-requires-alg path.
		require.NoError(t, mldsaJWK.Remove(jwk.AlgorithmKey))
		_, err = NewJWSVerifier(nil, mldsaJWK, nil, *NewFields())
		require.Error(t, err)
	})

	t.Run("mldsa private jwk exports public", func(t *testing.T) {
		mldsaJWK, err := jwk.Import[jwk.Key](mldsaPriv)
		require.NoError(t, err)
		require.NoError(t, mldsaJWK.Set(jwk.AlgorithmKey, jwa.MLDSA44()))
		alg, raw, err := inferFromJWK(mldsaJWK)
		require.NoError(t, err)
		require.Equal(t, jwa.MLDSA44().String(), alg.String())
		_, ok := raw.(*mldsa.PublicKey)
		require.True(t, ok)
	})

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("ed25519 crv without alg", func(t *testing.T) {
		edJWK, err := jwk.Import[jwk.Key](edPub)
		require.NoError(t, err)
		v, err := NewJWSVerifier(nil, edJWK, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v)
	})

	t.Run("ed25519 with matching alg", func(t *testing.T) {
		edJWK, err := jwk.Import[jwk.Key](edPub)
		require.NoError(t, err)
		require.NoError(t, edJWK.Set(jwk.AlgorithmKey, jwa.EdDSA()))
		v, err := NewJWSVerifier(nil, edJWK, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v)
	})

	t.Run("ed25519 with RFC 9864 alg", func(t *testing.T) {
		edJWK, err := jwk.Import[jwk.Key](edPub)
		require.NoError(t, err)
		require.NoError(t, edJWK.Set(jwk.AlgorithmKey, jwa.EdDSAEd25519()))
		allowed, err := NewJWSAlgAllowlist(jwa.EdDSAEd25519())
		require.NoError(t, err)
		v, err := NewJWSVerifier(allowed, edJWK, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v)
	})

	t.Run("ed25519 crv with modern allowlist", func(t *testing.T) {
		edJWK, err := jwk.Import[jwk.Key](edPub)
		require.NoError(t, err)
		allowed, err := NewJWSAlgAllowlist(jwa.EdDSAEd25519())
		require.NoError(t, err)
		v, err := NewJWSVerifier(allowed, edJWK, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v)
	})

	t.Run("ed25519 legacy alg with modern allowlist", func(t *testing.T) {
		edJWK, err := jwk.Import[jwk.Key](edPub)
		require.NoError(t, err)
		require.NoError(t, edJWK.Set(jwk.AlgorithmKey, jwa.EdDSA()))
		allowed, err := NewJWSAlgAllowlist(jwa.EdDSAEd25519())
		require.NoError(t, err)
		v, err := NewJWSVerifier(allowed, edJWK, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v)
	})

	t.Run("ed25519 private jwk exports public", func(t *testing.T) {
		edJWK, err := jwk.Import[jwk.Key](edPriv)
		require.NoError(t, err)
		alg, raw, err := inferFromJWK(edJWK)
		require.NoError(t, err)
		require.Equal(t, jwa.EdDSAEd25519().String(), alg.String())
		got, ok := raw.(ed25519.PublicKey)
		require.True(t, ok)
		require.Equal(t, edPub, got)
	})

	t.Run("p384 jwk from crv", func(t *testing.T) {
		p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		ecJWK, err := jwk.Import[jwk.Key](&p384.PublicKey)
		require.NoError(t, err)
		v, err := NewJWSVerifier(nil, ecJWK, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v)
	})

	t.Run("p521 jwk from crv", func(t *testing.T) {
		p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)
		ecJWK, err := jwk.Import[jwk.Key](&p521.PublicKey)
		require.NoError(t, err)
		v, err := NewJWSVerifier(nil, ecJWK, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v)
	})

	t.Run("withalg rejects jwk", func(t *testing.T) {
		ecJWK, err := jwk.Import[jwk.Key](&p256.PublicKey)
		require.NoError(t, err)
		_, err = NewJWSVerifierWithAlg(nil, jwa.ES256(), ecJWK, nil, *NewFields())
		require.Error(t, err)
	})
}

func TestInferJWSVerifierKey(t *testing.T) {
	t.Run("nil key", func(t *testing.T) {
		_, _, err := inferJWSVerifierKey(nil)
		require.Error(t, err)
	})
	t.Run("typed nil ecdsa", func(t *testing.T) {
		var pub *ecdsa.PublicKey
		_, _, err := inferJWSVerifierKey(pub)
		require.Error(t, err)
	})
	t.Run("typed nil mldsa", func(t *testing.T) {
		var pub *mldsa.PublicKey
		_, _, err := inferJWSVerifierKey(pub)
		require.Error(t, err)
	})
	t.Run("unsupported type", func(t *testing.T) {
		_, _, err := inferJWSVerifierKey([]byte("not-a-key"))
		require.Error(t, err)
	})

	t.Run("ecdsa curves", func(t *testing.T) {
		for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
			priv, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)
			alg, raw, err := inferJWSVerifierKey(&priv.PublicKey)
			require.NoError(t, err)
			require.Equal(t, &priv.PublicKey, raw)
			want, err := algFromECDSACurve(curve)
			require.NoError(t, err)
			require.Equal(t, want.String(), alg.String())
		}
	})

	t.Run("mldsa params", func(t *testing.T) {
		for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
			priv, err := mldsa.GenerateKey(params)
			require.NoError(t, err)
			pub := priv.Public().(*mldsa.PublicKey)
			alg, raw, err := inferJWSVerifierKey(pub)
			require.NoError(t, err)
			require.Equal(t, pub, raw)
			want, err := algFromMLDSAParams(params)
			require.NoError(t, err)
			require.Equal(t, want.String(), alg.String())
		}
	})
}

func TestAlgFromCurveHelpers(t *testing.T) {
	t.Run("jwk curves", func(t *testing.T) {
		cases := []struct {
			crv  jwa.EllipticCurveAlgorithm
			want jwa.SignatureAlgorithm
		}{
			{jwa.P256(), jwa.ES256()},
			{jwa.P384(), jwa.ES384()},
			{jwa.P521(), jwa.ES512()},
			{jwa.Ed25519(), jwa.EdDSAEd25519()},
		}
		for _, tc := range cases {
			got, err := algFromJWKCurve(tc.crv)
			require.NoError(t, err)
			require.Equal(t, tc.want.String(), got.String())
		}
		_, err := algFromJWKCurve(jwa.X25519())
		require.Error(t, err)
	})

	t.Run("ed25519 alg aliases agree", func(t *testing.T) {
		require.True(t, jwsSignatureAlgsAgree(jwa.EdDSA(), jwa.EdDSAEd25519()))
		require.True(t, jwsSignatureAlgsAgree(jwa.EdDSAEd25519(), jwa.EdDSA()))
		require.False(t, jwsSignatureAlgsAgree(jwa.EdDSA(), jwa.ES256()))
	})

	t.Run("ecdsa nil and unsupported", func(t *testing.T) {
		_, err := algFromECDSACurve(nil)
		require.Error(t, err)
		_, err = algFromECDSACurve(elliptic.P224())
		require.Error(t, err)
		_, _, err = inferJWSVerifierKey(&ecdsa.PublicKey{Curve: nil})
		require.Error(t, err)
	})

	t.Run("mldsa unknown params", func(t *testing.T) {
		var z mldsa.Parameters
		_, err := algFromMLDSAParams(z)
		require.Error(t, err)
	})
}
