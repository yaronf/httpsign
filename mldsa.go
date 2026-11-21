package httpsign

import (
	"crypto/mldsa"
	"crypto/rand"
	"fmt"
)

// NewMLDSA44Signer returns a Signer for the IANA HTTP Signature Algorithm ml-dsa-44
// (C2SP httpsig-pq / FIPS 204 ML-DSA-44). key must be a non-nil *mldsa.PrivateKey
// for the ML-DSA-44 parameter set. Config may be nil for a default configuration.
func NewMLDSA44Signer(key *mldsa.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	return newMLDSASigner(mldsa.MLDSA44(), "ml-dsa-44", key, config, fields)
}

// NewMLDSA65Signer returns a Signer for the IANA HTTP Signature Algorithm ml-dsa-65
// (C2SP httpsig-pq / FIPS 204 ML-DSA-65). key must be a non-nil *mldsa.PrivateKey
// for the ML-DSA-65 parameter set. Config may be nil for a default configuration.
func NewMLDSA65Signer(key *mldsa.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	return newMLDSASigner(mldsa.MLDSA65(), "ml-dsa-65", key, config, fields)
}

// NewMLDSA87Signer returns a Signer for the IANA HTTP Signature Algorithm ml-dsa-87
// (C2SP httpsig-pq / FIPS 204 ML-DSA-87). key must be a non-nil *mldsa.PrivateKey
// for the ML-DSA-87 parameter set. Config may be nil for a default configuration.
func NewMLDSA87Signer(key *mldsa.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	return newMLDSASigner(mldsa.MLDSA87(), "ml-dsa-87", key, config, fields)
}

func newMLDSASigner(params mldsa.Parameters, alg string, key *mldsa.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	got, err := mldsaParamsFromPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if got != params {
		return nil, fmt.Errorf("key parameter set must be %s", params)
	}
	if config == nil {
		config = NewSignConfig()
	}
	return &Signer{
		key:    key,
		alg:    alg,
		config: config,
		fields: fields,
	}, nil
}

// NewMLDSA44Verifier returns a Verifier for the IANA HTTP Signature Algorithm ml-dsa-44
// (C2SP httpsig-pq / FIPS 204 ML-DSA-44). pub must be a non-nil *mldsa.PublicKey
// for the ML-DSA-44 parameter set. Config may be nil for a default configuration.
func NewMLDSA44Verifier(pub *mldsa.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	return newMLDSAVerifier(mldsa.MLDSA44(), "ml-dsa-44", pub, config, fields)
}

// NewMLDSA65Verifier returns a Verifier for the IANA HTTP Signature Algorithm ml-dsa-65
// (C2SP httpsig-pq / FIPS 204 ML-DSA-65). pub must be a non-nil *mldsa.PublicKey
// for the ML-DSA-65 parameter set. Config may be nil for a default configuration.
func NewMLDSA65Verifier(pub *mldsa.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	return newMLDSAVerifier(mldsa.MLDSA65(), "ml-dsa-65", pub, config, fields)
}

// NewMLDSA87Verifier returns a Verifier for the IANA HTTP Signature Algorithm ml-dsa-87
// (C2SP httpsig-pq / FIPS 204 ML-DSA-87). pub must be a non-nil *mldsa.PublicKey
// for the ML-DSA-87 parameter set. Config may be nil for a default configuration.
func NewMLDSA87Verifier(pub *mldsa.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	return newMLDSAVerifier(mldsa.MLDSA87(), "ml-dsa-87", pub, config, fields)
}

func newMLDSAVerifier(params mldsa.Parameters, alg string, pub *mldsa.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	got, err := mldsaParamsFromPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if got != params {
		return nil, fmt.Errorf("key parameter set must be %s", params)
	}
	if config == nil {
		config = NewVerifyConfig()
	}
	return &Verifier{
		key:    pub,
		alg:    alg,
		config: config,
		fields: fields,
	}, nil
}

func paramsForMLDSAHTTPAlg(alg string) (mldsa.Parameters, error) {
	switch alg {
	case "ml-dsa-44":
		return mldsa.MLDSA44(), nil
	case "ml-dsa-65":
		return mldsa.MLDSA65(), nil
	case "ml-dsa-87":
		return mldsa.MLDSA87(), nil
	default:
		return mldsa.Parameters{}, fmt.Errorf("unknown ML-DSA algorithm %q", alg)
	}
}

// mldsaParamsFromPublicKey returns the parameter set for pub. It checks the
// encoding length before calling Parameters(), which panics on a zero public key.
func mldsaParamsFromPublicKey(pub *mldsa.PublicKey) (mldsa.Parameters, error) {
	if pub == nil {
		return mldsa.Parameters{}, fmt.Errorf("key must not be nil")
	}
	n := len(pub.Bytes())
	var want mldsa.Parameters
	switch n {
	case mldsa.MLDSA44PublicKeySize:
		want = mldsa.MLDSA44()
	case mldsa.MLDSA65PublicKeySize:
		want = mldsa.MLDSA65()
	case mldsa.MLDSA87PublicKeySize:
		want = mldsa.MLDSA87()
	default:
		return mldsa.Parameters{}, fmt.Errorf("invalid ML-DSA public key encoding length %d", n)
	}
	if pub.Parameters() != want {
		return mldsa.Parameters{}, fmt.Errorf("ML-DSA public key parameter set mismatch")
	}
	return want, nil
}

func mldsaParamsFromPrivateKey(key *mldsa.PrivateKey) (mldsa.Parameters, error) {
	if key == nil {
		return mldsa.Parameters{}, fmt.Errorf("key must not be nil")
	}
	return mldsaParamsFromPublicKey(key.PublicKey())
}

func mldsaSign(alg string, key interface{}, buff []byte) ([]byte, error) {
	params, err := paramsForMLDSAHTTPAlg(alg)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("malformed key")
	}
	got, err := mldsaParamsFromPrivateKey(priv)
	if err != nil || got != params {
		return nil, fmt.Errorf("malformed key")
	}
	// Hedged pure ML-DSA with empty context (C2SP httpsig-pq).
	sig, err := priv.Sign(rand.Reader, buff, &mldsa.Options{})
	if err != nil {
		return nil, fmt.Errorf("ML-DSA signature failed")
	}
	return sig, nil
}

func mldsaVerify(alg string, key interface{}, buff, sig []byte) (bool, error) {
	params, err := paramsForMLDSAHTTPAlg(alg)
	if err != nil {
		return false, fmt.Errorf("signature verification failed")
	}
	pub, ok := key.(*mldsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("malformed key")
	}
	// C2SP httpsig-pq HTTP_VERIFY: Kv length and parameter set must match the selected alg.
	got, err := mldsaParamsFromPublicKey(pub)
	if err != nil || got != params {
		return false, fmt.Errorf("signature verification failed")
	}
	if len(sig) != params.SignatureSize() {
		return false, fmt.Errorf("signature verification failed")
	}
	if err := mldsa.Verify(pub, buff, sig, &mldsa.Options{}); err != nil {
		return false, fmt.Errorf("signature verification failed")
	}
	return true, nil
}
