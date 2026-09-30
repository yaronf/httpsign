package httpsign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/require"
)

// Opaque wrappers: distinct concrete types that only satisfy crypto.Signer.
// Used to exercise HSM/KMS-style keys without matching *ecdsa.PrivateKey etc.

type ecdsaCryptoSigner struct{ priv *ecdsa.PrivateKey }

func (w ecdsaCryptoSigner) Public() crypto.PublicKey { return &w.priv.PublicKey }
func (w ecdsaCryptoSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return w.priv.Sign(r, digest, opts)
}

type rsaCryptoSigner struct{ priv *rsa.PrivateKey }

func (w rsaCryptoSigner) Public() crypto.PublicKey { return &w.priv.PublicKey }
func (w rsaCryptoSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return w.priv.Sign(r, digest, opts)
}

type ed25519CryptoSigner struct{ priv ed25519.PrivateKey }

func (w ed25519CryptoSigner) Public() crypto.PublicKey { return w.priv.Public().(ed25519.PublicKey) }
func (w ed25519CryptoSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return w.priv.Sign(r, digest, opts)
}

// wrongFamilySigner returns an RSA public key while claiming to be used as ES256.
type wrongFamilySigner struct{ pub *rsa.PublicKey }

func (w wrongFamilySigner) Public() crypto.PublicKey { return w.pub }
func (w wrongFamilySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func TestCryptoSignerConstructES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wrap := ecdsaCryptoSigner{priv: priv}

	signer, err := NewJWSSigner(jwa.ES256(), wrap, nil, *NewFields())
	require.NoError(t, err)
	require.NotNil(t, signer)

	verifier, err := NewJWSVerifierWithAlg(nil, jwa.ES256(), wrap, nil, *NewFields())
	require.NoError(t, err)
	require.NotNil(t, verifier)
}

func TestCryptoSignerConstructRS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	wrap := rsaCryptoSigner{priv: priv}

	signer, err := NewJWSSigner(jwa.RS256(), wrap, nil, *NewFields())
	require.NoError(t, err)
	require.NotNil(t, signer)

	verifier, err := NewJWSVerifierWithAlg(nil, jwa.RS256(), wrap, nil, *NewFields())
	require.NoError(t, err)
	require.NotNil(t, verifier)
}

func TestCryptoSignerConstructEdDSA(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	wrap := ed25519CryptoSigner{priv: priv}

	signer, err := NewJWSSigner(jwa.EdDSA(), wrap, nil, *NewFields())
	require.NoError(t, err)
	require.NotNil(t, signer)

	verifier, err := NewJWSVerifierWithAlg(nil, jwa.EdDSA(), wrap, nil, *NewFields())
	require.NoError(t, err)
	require.NotNil(t, verifier)
}

func TestCryptoSignerRoundTripES256RawPublic(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wrap := ecdsaCryptoSigner{priv: priv}

	config := NewSignConfig().setFakeCreated(1618884475).SignAlg(false).SetKeyID("kms1")
	fields := *NewFields().AddHeader("@method").AddHeader("date").AddHeader("content-type").AddQueryParam("pet")
	signer, err := NewJWSSigner(jwa.ES256(), wrap, config, fields)
	require.NoError(t, err)

	req := readRequest(httpreq2)
	sigInput, sig, err := SignRequest("sig1", *signer, req)
	require.NoError(t, err)
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)

	verifier, err := NewJWSVerifierWithAlg(nil, jwa.ES256(), &priv.PublicKey,
		NewVerifyConfig().SetVerifyCreated(false).SetKeyID("kms1"), fields)
	require.NoError(t, err)
	require.NoError(t, VerifyRequest("sig1", *verifier, req))
}

func TestCryptoSignerRoundTripES256SameWrapper(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wrap := ecdsaCryptoSigner{priv: priv}

	config := NewSignConfig().setFakeCreated(1618884475).SignAlg(false).SetKeyID("kms1")
	fields := *NewFields().AddHeader("@method").AddHeader("date").AddHeader("content-type").AddQueryParam("pet")
	signer, err := NewJWSSigner(jwa.ES256(), wrap, config, fields)
	require.NoError(t, err)

	req := readRequest(httpreq2)
	sigInput, sig, err := SignRequest("sig1", *signer, req)
	require.NoError(t, err)
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)

	verifier, err := NewJWSVerifierWithAlg(nil, jwa.ES256(), wrap,
		NewVerifyConfig().SetVerifyCreated(false).SetKeyID("kms1"), fields)
	require.NoError(t, err)
	require.NoError(t, VerifyRequest("sig1", *verifier, req))
}

func TestCryptoSignerRoundTripRS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	wrap := rsaCryptoSigner{priv: priv}

	config := NewSignConfig().setFakeCreated(1618884475).SignAlg(false).SetKeyID("kms-rsa")
	fields := *NewFields().AddHeader("@method").AddHeader("date").AddHeader("content-type").AddQueryParam("pet")
	signer, err := NewJWSSigner(jwa.RS256(), wrap, config, fields)
	require.NoError(t, err)

	req := readRequest(httpreq2)
	sigInput, sig, err := SignRequest("sig1", *signer, req)
	require.NoError(t, err)
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)

	verifier, err := NewJWSVerifierWithAlg(nil, jwa.RS256(), &priv.PublicKey,
		NewVerifyConfig().SetVerifyCreated(false).SetKeyID("kms-rsa"), fields)
	require.NoError(t, err)
	require.NoError(t, VerifyRequest("sig1", *verifier, req))

	verifierWrap, err := NewJWSVerifierWithAlg(nil, jwa.RS256(), wrap,
		NewVerifyConfig().SetVerifyCreated(false).SetKeyID("kms-rsa"), fields)
	require.NoError(t, err)
	require.NoError(t, VerifyRequest("sig1", *verifierWrap, req))
}

func TestCryptoSignerRoundTripEdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	wrap := ed25519CryptoSigner{priv: priv}

	config := NewSignConfig().setFakeCreated(1618884475).SignAlg(false).SetKeyID("kms-ed")
	fields := *NewFields().AddHeader("@method").AddHeader("date").AddHeader("content-type").AddQueryParam("pet")
	signer, err := NewJWSSigner(jwa.EdDSA(), wrap, config, fields)
	require.NoError(t, err)

	req := readRequest(httpreq2)
	sigInput, sig, err := SignRequest("sig1", *signer, req)
	require.NoError(t, err)
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)

	verifier, err := NewJWSVerifierWithAlg(nil, jwa.EdDSA(), pub,
		NewVerifyConfig().SetVerifyCreated(false).SetKeyID("kms-ed"), fields)
	require.NoError(t, err)
	require.NoError(t, VerifyRequest("sig1", *verifier, req))

	verifierWrap, err := NewJWSVerifierWithAlg(nil, jwa.EdDSA(), wrap,
		NewVerifyConfig().SetVerifyCreated(false).SetKeyID("kms-ed"), fields)
	require.NoError(t, err)
	require.NoError(t, VerifyRequest("sig1", *verifierWrap, req))
}

func TestCryptoSignerRejectWrongPublicFamily(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	wrap := wrongFamilySigner{pub: &rsaPriv.PublicKey}

	_, err = NewJWSSigner(jwa.ES256(), wrap, nil, *NewFields())
	require.Error(t, err)
	require.Contains(t, err.Error(), "Public")

	_, err = NewJWSVerifierWithAlg(nil, jwa.ES256(), wrap, nil, *NewFields())
	require.Error(t, err)
	require.Contains(t, err.Error(), "Public")
}

func TestCryptoSignerRejectCurveMismatch(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	wrap := ecdsaCryptoSigner{priv: p384}

	_, err = NewJWSSigner(jwa.ES256(), wrap, nil, *NewFields())
	require.Error(t, err)
	require.Contains(t, err.Error(), "curve")
}

func TestCryptoSignerRejectMLDSA(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	// *mldsa.PrivateKey implements crypto.Signer; opaque wrapper still rejected for ML-DSA policy.
	type mldsaWrap struct{ *mldsa.PrivateKey }
	wrap := mldsaWrap{PrivateKey: priv}

	_, err = NewJWSSigner(jwa.MLDSA44(), wrap, nil, *NewFields())
	require.Error(t, err)
}

func TestCryptoSignerRecoverMalformedEd25519OnECDSAProbe(t *testing.T) {
	// ed25519.PrivateKey implements crypto.Signer; wrong length makes Public() panic.
	bad := ed25519.PrivateKey(strings.Repeat("a", 63))

	err := validateECDSAKey(jwa.ES256(), bad, true)
	require.Error(t, err)

	_, err = NewJWSSigner(jwa.ES256(), bad, nil, *NewFields())
	require.Error(t, err)
}

func TestCryptoSignerRecoverMalformedEd25519OnRSAProbe(t *testing.T) {
	bad := ed25519.PrivateKey(strings.Repeat("a", 63))

	err := validateRSAKey(jwa.RS256(), bad, true)
	require.Error(t, err)

	_, err = NewJWSSigner(jwa.RS256(), bad, nil, *NewFields())
	require.Error(t, err)
}

func TestValidateJWSKeyAlgCryptoSigner(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	require.NoError(t, validateECDSAKey(jwa.ES256(), ecdsaCryptoSigner{priv: p256}, true))
	require.NoError(t, validateECDSAKey(jwa.ES256(), ecdsaCryptoSigner{priv: p256}, false))
	require.NoError(t, validateRSAKey(jwa.RS256(), rsaCryptoSigner{priv: rsaPriv}, true))
	require.NoError(t, validateRSAKey(jwa.RS256(), rsaCryptoSigner{priv: rsaPriv}, false))
	require.NoError(t, validateEd25519Key(jwa.EdDSA(), ed25519CryptoSigner{priv: edPriv}, true))
	require.NoError(t, validateEd25519Key(jwa.EdDSA(), ed25519CryptoSigner{priv: edPriv}, false))
}
