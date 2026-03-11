package httpsign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"

	// JWX v2 - for backward compatibility (used by existing NewJWSSigner/NewJWSVerifier)
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	// JWX v3 - for new V3 functions (used by NewJWSSignerV3/NewJWSVerifierV3)
	jwav3 "github.com/lestrrat-go/jwx/v3/jwa"
	jwsv3 "github.com/lestrrat-go/jwx/v3/jws"
)

// Signer includes a cryptographic key (typically a private key) and configuration of what needs to be signed.
type Signer struct {
	key           interface{}
	alg           string
	config        *SignConfig
	fields        Fields
	foreignSigner interface{}
}

// NewHMACSHA256Signer returns a new Signer structure. Key must be at least 64 bytes long.
// Config may be nil for a default configuration.
func NewHMACSHA256Signer(key []byte, config *SignConfig, fields Fields) (*Signer, error) {
	if len(key) < 64 {
		return nil, fmt.Errorf("key must be at least 64 bytes long")
	}
	if config == nil {
		config = NewSignConfig()
	}
	return &Signer{
		key:    key,
		alg:    "hmac-sha256",
		config: config,
		fields: fields,
	}, nil
}

// NewRSASigner returns a new Signer structure. Key is an RSA private key.
// Config may be nil for a default configuration.
func NewRSASigner(key rsa.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	if config == nil {
		config = NewSignConfig()
	}
	return &Signer{
		key:    key,
		alg:    "rsa-v1_5-sha256",
		config: config,
		fields: fields,
	}, nil
}

// NewRSAPSSSigner returns a new Signer structure. Key is an RSA private key.
// Config may be nil for a default configuration.
func NewRSAPSSSigner(key rsa.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	if config == nil {
		config = NewSignConfig()
	}
	return &Signer{
		key:    key,
		alg:    "rsa-pss-sha512",
		config: config,
		fields: fields,
	}, nil
}

// NewP256Signer returns a new Signer structure. Key is an elliptic curve P-256 private key.
// Config may be nil for a default configuration.
func NewP256Signer(key ecdsa.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	return newECCSigner(key, config, fields, elliptic.P256(), "P-256", "ecdsa-p256-sha256")
}

// NewP384Signer returns a new Signer structure. Key is an elliptic curve P-384 private key.
// Config may be nil for a default configuration.
func NewP384Signer(key ecdsa.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	return newECCSigner(key, config, fields, elliptic.P384(), "P-384", "ecdsa-p384-sha384")
}

func newECCSigner(key ecdsa.PrivateKey, config *SignConfig, fields Fields, curve elliptic.Curve, curveName, alg string) (*Signer, error) {
	if key.Curve != curve {
		return nil, fmt.Errorf("key curve must be %s", curveName)
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

// NewEd25519Signer returns a new Signer structure. Key is an EdDSA Curve 25519 private key.
// Config may be nil for a default configuration.
func NewEd25519Signer(key ed25519.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if config == nil {
		config = NewSignConfig()
	}
	return &Signer{
		key:    key,
		alg:    "ed25519",
		config: config,
		fields: fields,
	}, nil
}

// NewEd25519SignerFromSeed returns a new Signer structure. Key is an EdDSA Curve 25519 private key,
// a 32 byte buffer according to RFC 8032.
// Config may be nil for a default configuration.
func NewEd25519SignerFromSeed(seed []byte, config *SignConfig, fields Fields) (*Signer, error) {
	if seed == nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed must not be nil, and must have length %d", ed25519.SeedSize)
	}
	key := ed25519.NewKeyFromSeed(seed)
	return NewEd25519Signer(key, config, fields)
}

// NewJWSSigner creates a generic signer for JWS algorithms, using the go-jwx v2 package. The particular key type for each algorithm
// is documented in that package.
// Config may be nil for a default configuration.
//
// Note: This function uses jwx v2. For jwx v3 support, use NewJWSSignerV3 instead.
func NewJWSSigner(alg jwa.SignatureAlgorithm, key interface{}, config *SignConfig, fields Fields) (*Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if alg == jwa.NoSignature {
		return nil, fmt.Errorf("the NONE signing algorithm is expressly disallowed")
	}
	if config == nil {
		config = NewSignConfig()
	}
	jwsSigner, err := jws.NewSigner(alg)
	if err != nil {
		return nil, err
	}
	return &Signer{
		key:           key,
		alg:           "",
		config:        config,
		fields:        fields,
		foreignSigner: jwsSigner,
	}, nil
}

// NewJWSSignerV3 creates a generic signer for JWS algorithms, using the go-jwx v3 package. The particular key type for each algorithm
// is documented in that package.
// Config may be nil for a default configuration.
//
// This function uses jwx v3 and is the recommended choice for new code using jwx v3.
// It uses the recommended SignerFor() API which returns Signer2 interface.
func NewJWSSignerV3(alg jwav3.SignatureAlgorithm, key interface{}, config *SignConfig, fields Fields) (*Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if alg == jwav3.NoSignature() {
		return nil, fmt.Errorf("the NONE signing algorithm is expressly disallowed")
	}
	if config == nil {
		config = NewSignConfig()
	}
	jwsSigner, err := jwsv3.SignerFor(alg)
	if err != nil {
		return nil, err
	}
	return &Signer{
		key:           key,
		alg:           "",
		config:        config,
		fields:        fields,
		foreignSigner: jwsSigner,
	}, nil
}

func (s Signer) sign(buff []byte) ([]byte, error) {
	if s.foreignSigner != nil {
		// Try v2 signer first (jws.Signer interface: Sign(payload, key))
		if signerV2, ok := s.foreignSigner.(jws.Signer); ok {
			return signerV2.Sign(buff, s.key)
		}

		// Try v3 Signer2 interface (new recommended API: Sign(key, payload))
		// Note: parameter order is SWAPPED compared to v2!
		type Signer2 interface {
			Sign(key interface{}, payload []byte) ([]byte, error)
		}
		if signerV3, ok := s.foreignSigner.(Signer2); ok {
			return signerV3.Sign(s.key, buff) // Note: key first, payload second
		}

		return nil, fmt.Errorf("expected jws.Signer or Signer2 interface, got %T", s.foreignSigner)
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
		// RFC 9421 Section 3.3.1 requires salt length = hash output length (64 bytes for SHA-512)
		// to match TLS 1.3 and ensure interoperability with WebCrypto and other implementations
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
		sig, err := rsa.SignPSS(rand.Reader, &key, crypto.SHA512, hashed[:], opts)
		if err != nil {
			return nil, fmt.Errorf("RSA-PSS signature failed")
		}
		return sig, nil
	case "ecdsa-p256-sha256":
		hashed := sha256.Sum256(buff)
		key := s.key.(ecdsa.PrivateKey)
		return ecdsaSignRaw(rand.Reader, &key, hashed[:])
	case "ecdsa-p384-sha384":
		hashed := sha512.Sum384(buff)
		key := s.key.(ecdsa.PrivateKey)
		return ecdsaSignRaw(rand.Reader, &key, hashed[:])
	case "ed25519":
		key := s.key.(ed25519.PrivateKey)
		if len(key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("key must be %d bytes long", ed25519.PrivateKeySize)
		}
		return ed25519.Sign(key, buff), nil
	default:
		return nil, fmt.Errorf("sign: unknown algorithm \"%s\"", s.alg)
	}
}

// Verifier includes a cryptographic key (typically a public key) and configuration of what needs to be verified.
type Verifier struct {
	key             interface{}
	alg             string
	config          *VerifyConfig
	fields          Fields
	foreignVerifier interface{}
}

// NewHMACSHA256Verifier generates a new Verifier for HMAC-SHA256 signatures. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
func NewHMACSHA256Verifier(key []byte, config *VerifyConfig, fields Fields) (*Verifier, error) {
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
		key:    key,
		alg:    "hmac-sha256",
		config: config,
		fields: fields,
	}, nil
}

// NewRSAVerifier generates a new Verifier for RSA signatures. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
func NewRSAVerifier(key rsa.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	if config == nil {
		config = NewVerifyConfig()
	}
	return &Verifier{
		key:    key,
		alg:    "rsa-v1_5-sha256",
		config: config,
		fields: fields,
	}, nil
}

// NewRSAPSSVerifier generates a new Verifier for RSA-PSS signatures. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
func NewRSAPSSVerifier(key rsa.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	if config == nil {
		config = NewVerifyConfig()
	}
	return &Verifier{
		key:    key,
		alg:    "rsa-pss-sha512",
		config: config,
		fields: fields,
	}, nil
}

// NewP256Verifier generates a new Verifier for ECDSA (P-256) signatures. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
func NewP256Verifier(key ecdsa.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	return newECCVerifier(key, config, fields, elliptic.P256(), "P-256", "ecdsa-p256-sha256")
}

// NewP384Verifier generates a new Verifier for ECDSA (P-384) signatures. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
func NewP384Verifier(key ecdsa.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	return newECCVerifier(key, config, fields, elliptic.P384(), "P-384", "ecdsa-p384-sha384")
}

func newECCVerifier(key ecdsa.PublicKey, config *VerifyConfig, fields Fields, curve elliptic.Curve, curveName, alg string) (*Verifier, error) {
	if config == nil {
		config = NewVerifyConfig()
	}
	if key.Curve != curve {
		return nil, fmt.Errorf("key curve must be %s", curveName)
	}
	return &Verifier{
		key:    key,
		alg:    alg,
		config: config,
		fields: fields,
	}, nil
}

// NewEd25519Verifier generates a new Verifier for EdDSA Curve 25519 signatures. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
func NewEd25519Verifier(key ed25519.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if config == nil {
		config = NewVerifyConfig()
	}
	return &Verifier{
		key:    key,
		alg:    "ed25519",
		config: config,
		fields: fields,
	}, nil
}

// NewJWSVerifier creates a generic verifier for JWS algorithms, using the go-jwx v2 package. The particular key type for each algorithm
// is documented in that package. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
//
// Note: This function uses jwx v2. For jwx v3 support, use NewJWSVerifierV3 instead.
func NewJWSVerifier(alg jwa.SignatureAlgorithm, key interface{}, config *VerifyConfig, fields Fields) (*Verifier, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if config == nil {
		config = NewVerifyConfig()
	}
	if alg == jwa.NoSignature {
		return nil, fmt.Errorf("the NONE signing algorithm is expressly disallowed")
	}
	verifier, err := jws.NewVerifier(alg)
	if err != nil {
		return nil, err
	}
	return &Verifier{
		key:             key,
		alg:             "",
		config:          config,
		fields:          fields,
		foreignVerifier: verifier,
	}, nil
}

// NewJWSVerifierV3 creates a generic verifier for JWS algorithms, using the go-jwx v3 package. The particular key type for each algorithm
// is documented in that package. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
//
// This function uses jwx v3 and is the recommended choice for new code using jwx v3.
// It uses the recommended VerifierFor() API which returns Verifier2 interface.
func NewJWSVerifierV3(alg jwav3.SignatureAlgorithm, key interface{}, config *VerifyConfig, fields Fields) (*Verifier, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if config == nil {
		config = NewVerifyConfig()
	}
	if alg == jwav3.NoSignature() {
		return nil, fmt.Errorf("the NONE signing algorithm is expressly disallowed")
	}
	verifier, err := jwsv3.VerifierFor(alg)
	if err != nil {
		return nil, err
	}
	return &Verifier{
		key:             key,
		alg:             "",
		config:          config,
		fields:          fields,
		foreignVerifier: verifier,
	}, nil
}

func (v Verifier) verify(buff []byte, sig []byte) (bool, error) {
	if v.foreignVerifier != nil {
		// Try v2 verifier first (jws.Verifier interface: Verify(payload, sig, key))
		if verifierV2, ok := v.foreignVerifier.(jws.Verifier); ok {
			err := verifierV2.Verify(buff, sig, v.key)
			if err != nil {
				// Return opaque error; underlying err discarded for consistency
				return false, fmt.Errorf("signature verification failed")
			}
			return true, nil
		}

		// Try v3 Verifier2 interface (new recommended API: Verify(key, payload, sig))
		// Note: parameter order is DIFFERENT compared to v2!
		type Verifier2 interface {
			Verify(key interface{}, payload, signature []byte) error
		}
		if verifierV3, ok := v.foreignVerifier.(Verifier2); ok {
			err := verifierV3.Verify(v.key, buff, sig) // Note: key first, then payload, then signature
			if err != nil {
				// Return opaque error; underlying err discarded for consistency
				return false, fmt.Errorf("signature verification failed")
			}
			return true, nil
		}

		return false, fmt.Errorf("expected jws.Verifier or Verifier2 interface, got %T", v.foreignVerifier)
	}

	switch v.alg {
	case "hmac-sha256":
		mac := hmac.New(sha256.New, v.key.([]byte))
		mac.Write(buff)
		return subtle.ConstantTimeCompare(mac.Sum(nil), sig) == 1, nil
	case "rsa-v1_5-sha256":
		hashed := sha256.Sum256(buff)
		key := v.key.(rsa.PublicKey)
		err := rsa.VerifyPKCS1v15(&key, crypto.SHA256, hashed[:], sig)
		if err != nil {
			// Return opaque error; underlying crypto err discarded to avoid leaking internals
			return false, fmt.Errorf("signature verification failed")
		}
		return true, nil
	case "rsa-pss-sha512":
		hashed := sha512.Sum512(buff)
		key := v.key.(rsa.PublicKey)
		err := rsa.VerifyPSS(&key, crypto.SHA512, hashed[:], sig, nil)
		if err != nil {
			// Return opaque error; underlying crypto err discarded to avoid leaking internals
			return false, fmt.Errorf("signature verification failed")
		}
		return true, nil
	case "ecdsa-p256-sha256":
		hashed := sha256.Sum256(buff)
		key := v.key.(ecdsa.PublicKey)
		return ecdsaVerifyRaw(&key, hashed[:], sig)
	case "ecdsa-p384-sha384":
		hashed := sha512.Sum384(buff)
		key := v.key.(ecdsa.PublicKey)
		return ecdsaVerifyRaw(&key, hashed[:], sig)
	case "ed25519":
		key := v.key.(ed25519.PublicKey)
		verified := ed25519.Verify(key, buff, sig)
		if !verified {
			return false, fmt.Errorf("signature verification failed")
		}
		return true, nil
	default:
		return false, fmt.Errorf("verify: unknown algorithm \"%s\"", v.alg)
	}
}
