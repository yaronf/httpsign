package httpsign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
)

// Signer includes a cryptographic key and configuration of what needs to be signed.
type Signer struct {
	keyID         string
	key           interface{}
	alg           string
	config        *SignConfig
	fields        Fields
	foreignSigner interface{}
}

// NewHMACSHA256Signer returns a new Signer structure. Key must be at least 64 bytes long.
// Config may be nil for a default configuration.
func NewHMACSHA256Signer(keyID string, key []byte, config *SignConfig, fields Fields) (*Signer, error) {
	if key == nil || len(key) < 64 {
		return nil, fmt.Errorf("key must be at least 64 bytes long")
	}
	if keyID == "" {
		return nil, fmt.Errorf("keyID must not be empty")
	}
	if config == nil {
		config = NewSignConfig()
	}
	return &Signer{
		keyID:  keyID,
		key:    key,
		alg:    "hmac-sha256",
		config: config,
		fields: fields,
	}, nil
}

// NewRSASigner returns a new Signer structure. Key is an RSA private key.
// Config may be nil for a default configuration.
func NewRSASigner(keyID string, key rsa.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	if keyID == "" {
		return nil, fmt.Errorf("keyID must not be empty")
	}
	if config == nil {
		config = NewSignConfig()
	}
	return &Signer{
		keyID:  keyID,
		key:    key,
		alg:    "rsa-v1_5-sha256",
		config: config,
		fields: fields,
	}, nil
}

// NewRSAPSSSigner returns a new Signer structure. Key is an RSA private key.
// Config may be nil for a default configuration.
func NewRSAPSSSigner(keyID string, key rsa.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	if keyID == "" {
		return nil, fmt.Errorf("keyID must not be empty")
	}
	if config == nil {
		config = NewSignConfig()
	}
	return &Signer{
		keyID:  keyID,
		key:    key,
		alg:    "rsa-pss-sha512",
		config: config,
		fields: fields,
	}, nil
}

// NewP256Signer returns a new Signer structure. Key is an elliptic curve P-256 private key.
// Config may be nil for a default configuration.
func NewP256Signer(keyID string, key ecdsa.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	if keyID == "" {
		return nil, fmt.Errorf("keyID must not be empty")
	}
	if config == nil {
		config = NewSignConfig()
	}
	return &Signer{
		keyID:  keyID,
		key:    key,
		alg:    "ecdsa-p256-sha256",
		config: config,
		fields: fields,
	}, nil
}

// NewEd25519Signer returns a new Signer structure. Key is an EdDSA Curve 25519 private key.
// Config may be nil for a default configuration.
func NewEd25519Signer(keyID string, key ed25519.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if keyID == "" {
		return nil, fmt.Errorf("keyID must not be empty")
	}
	if config == nil {
		config = NewSignConfig()
	}
	return &Signer{
		keyID:  keyID,
		key:    key,
		alg:    "ed25519",
		config: config,
		fields: fields,
	}, nil
}

// NewEd25519SignerFromSeed returns a new Signer structure. Key is an EdDSA Curve 25519 private key,
// a 32 byte buffer according to RFC 8032.
// Config may be nil for a default configuration.
func NewEd25519SignerFromSeed(keyID string, seed []byte, config *SignConfig, fields Fields) (*Signer, error) {
	if seed == nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed must not be nil, and must have length %d", ed25519.SeedSize)
	}
	key := ed25519.NewKeyFromSeed(seed)
	return NewEd25519Signer(keyID, key, config, fields)
}

// NewJWSSigner creates a generic signer for JWS algorithms, using the go-jwx package. The particular key type for each algorithm
// is documented in that package.
// Config may be nil for a default configuration.
func NewJWSSigner(alg jwa.SignatureAlgorithm, keyID string, key interface{}, config *SignConfig, fields Fields) (*Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if alg == jwa.NoSignature {
		return nil, fmt.Errorf("the NONE signing algorithm is expressly disallowed")
	}
	jwsSigner, err := jws.NewSigner(alg)
	if err != nil {
		return nil, err
	}
	return &Signer{
		keyID:         keyID,
		key:           key,
		alg:           string(alg),
		config:        config,
		fields:        fields,
		foreignSigner: jwsSigner,
	}, nil
}

func (s Signer) sign(buff []byte) ([]byte, error) {
	if s.foreignSigner != nil {
		switch signer := s.foreignSigner.(type) {
		case jws.Signer:
			{
				return signer.Sign(buff, s.key)
			}
		default:
			return nil, fmt.Errorf("expected jws.Signer, got %T", s.foreignSigner)
		}
	}
	switch s.alg {
	case "hmac-sha256":
		mac := hmac.New(sha256.New, s.key.([]byte))
		mac.Write(buff)
		return mac.Sum(nil), nil
	case "rsa-v1_5-sha256":
		hashed := sha256.Sum256(buff)
		key := s.key.(rsa.PrivateKey)
		sig, err := rsa.SignPKCS1v15(nil, &key, crypto.SHA256, hashed[:])
		if err != nil {
			return nil, fmt.Errorf("RSA signature failed")
		}
		return sig, nil
	case "rsa-pss-sha512":
		hashed := sha512.Sum512(buff)
		key := s.key.(rsa.PrivateKey)
		sig, err := rsa.SignPSS(rand.Reader, &key, crypto.SHA512, hashed[:], nil)
		if err != nil {
			return nil, fmt.Errorf("RSA-PSS signature failed")
		}
		return sig, nil
	case "ecdsa-p256-sha256":
		hashed := sha256.Sum256(buff)
		key := s.key.(ecdsa.PrivateKey)
		return ecdsaSignRaw(rand.Reader, &key, hashed[:])
	case "ed25519":
		key := s.key.(ed25519.PrivateKey)
		return ed25519.Sign(key, buff), nil
	default:
		return nil, fmt.Errorf("sign: unknown algorithm \"%s\"", s.alg)
	}
}

// Verifier includes a cryptographic key (typically a public key) and configuration of what needs to be verified.
type Verifier struct {
	keyID           string
	key             interface{}
	alg             string
	config          *VerifyConfig
	fields          Fields
	foreignVerifier interface{}
}

// NewHMACSHA256Verifier generates a new Verifier for HMAC-SHA256 signatures. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
func NewHMACSHA256Verifier(keyID string, key []byte, config *VerifyConfig, fields Fields) (*Verifier, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if len(key) < 64 {
		return nil, fmt.Errorf("key must be at least 64 bytes long")
	}
	if config == nil {
		config = NewVerifyConfig()
	}
	return &Verifier{
		keyID:  keyID,
		key:    key,
		alg:    "hmac-sha256",
		config: config,
		fields: fields,
	}, nil
}

// NewRSAVerifier generates a new Verifier for RSA signatures. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
func NewRSAVerifier(keyID string, key rsa.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	if config == nil {
		config = NewVerifyConfig()
	}
	return &Verifier{
		keyID:  keyID,
		key:    key,
		alg:    "rsa-v1_5-sha256",
		config: config,
		fields: fields,
	}, nil
}

// NewRSAPSSVerifier generates a new Verifier for RSA-PSS signatures. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
func NewRSAPSSVerifier(keyID string, key rsa.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	if config == nil {
		config = NewVerifyConfig()
	}
	return &Verifier{
		keyID:  keyID,
		key:    key,
		alg:    "rsa-pss-sha512",
		config: config,
		fields: fields,
	}, nil
}

// NewP256Verifier generates a new Verifier for ECDSA (P-256) signatures. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
func NewP256Verifier(keyID string, key ecdsa.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	if config == nil {
		config = NewVerifyConfig()
	}
	return &Verifier{
		keyID:  keyID,
		key:    key,
		alg:    "ecdsa-p256-sha256",
		config: config,
		fields: fields,
	}, nil
}

// NewEd25519Verifier generates a new Verifier for EdDSA Curve 25519 signatures. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
func NewEd25519Verifier(keyID string, key ed25519.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if config == nil {
		config = NewVerifyConfig()
	}
	return &Verifier{
		keyID:  keyID,
		key:    key,
		alg:    "ed25519",
		config: config,
		fields: fields,
	}, nil
}

// NewJWSVerifier creates a generic verifier for JWS algorithms, using the go-jwx package. The particular key type for each algorithm
// is documented in that package. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
func NewJWSVerifier(alg jwa.SignatureAlgorithm, key interface{}, keyID string, config *VerifyConfig, fields Fields) (*Verifier, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if alg == jwa.NoSignature {
		return nil, fmt.Errorf("the NONE signing algorithm is expressly disallowed")
	}
	verifier, err := jws.NewVerifier(alg)
	if err != nil {
		return nil, err
	}
	return &Verifier{
		keyID:           keyID,
		key:             key,
		alg:             string(alg),
		config:          config,
		fields:          fields,
		foreignVerifier: verifier,
	}, nil
}

func (v Verifier) verify(buff []byte, sig []byte) (bool, error) {
	if v.foreignVerifier != nil {
		switch verifier := v.foreignVerifier.(type) {
		case jws.Verifier:
			err := verifier.Verify(buff, sig, v.key)
			if err != nil {
				return false, err
			}
			return true, nil
		default:
			return false, fmt.Errorf("expected jws.Verifier, got %T", v.foreignVerifier)
		}
	}

	switch v.alg {
	case "hmac-sha256":
		mac := hmac.New(sha256.New, v.key.([]byte))
		mac.Write(buff)
		return bytes.Equal(mac.Sum(nil), sig), nil
	case "rsa-v1_5-sha256":
		hashed := sha256.Sum256(buff)
		key := v.key.(rsa.PublicKey)
		err := rsa.VerifyPKCS1v15(&key, crypto.SHA256, hashed[:], sig)
		if err != nil {
			return false, fmt.Errorf("RSA verification failed: %w", err)
		}
		return true, nil
	case "rsa-pss-sha512":
		hashed := sha512.Sum512(buff)
		key := v.key.(rsa.PublicKey)
		err := rsa.VerifyPSS(&key, crypto.SHA512, hashed[:], sig, nil)
		if err != nil {
			return false, fmt.Errorf("RSA-PSS verification failed: %w", err)
		}
		return true, nil
	case "ecdsa-p256-sha256":
		hashed := sha256.Sum256(buff)
		key := v.key.(ecdsa.PublicKey)
		return ecdsaVerifyRaw(&key, hashed[:], sig)
	case "ed25519":
		key := v.key.(ed25519.PublicKey)
		verified := ed25519.Verify(key, buff, sig)
		if !verified {
			return false, fmt.Errorf("failed Ed25519 verification")
		}
		return true, nil
	default:
		return false, fmt.Errorf("verify: unknown algorithm \"%s\"", v.alg)
	}
}
