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
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if key.PublicKey().Parameters() != params {
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
	if pub == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if pub.Parameters() != params {
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

func mldsaSign(key interface{}, buff []byte) ([]byte, error) {
	priv, ok := key.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("malformed key")
	}
	// Hedged pure ML-DSA with empty context (C2SP httpsig-pq).
	sig, err := priv.Sign(rand.Reader, buff, &mldsa.Options{})
	if err != nil {
		return nil, fmt.Errorf("ML-DSA signature failed")
	}
	return sig, nil
}

func mldsaVerify(key interface{}, buff, sig []byte) (bool, error) {
	pub, ok := key.(*mldsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("malformed key")
	}
	if len(sig) != pub.Parameters().SignatureSize() {
		return false, fmt.Errorf("signature verification failed")
	}
	if err := mldsa.Verify(pub, buff, sig, &mldsa.Options{}); err != nil {
		return false, fmt.Errorf("signature verification failed")
	}
	return true, nil
}
