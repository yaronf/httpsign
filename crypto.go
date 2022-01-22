package httpsign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

type Signer struct {
	keyId  string
	key    interface{}
	alg    string
	config *SignConfig
	fields Fields
}

// NewHMACSHA256Signer returns a new Signer structure. Key must be at least 64 bytes long.
// Field names must be all lowercase, config may be nil for a default configuration.
func NewHMACSHA256Signer(keyId string, key []byte, config *SignConfig, fields Fields) (*Signer, error) {
	if key == nil || len(key) < 64 {
		return nil, fmt.Errorf("key must be at least 64 bytes long")
	}
	if keyId == "" {
		return nil, fmt.Errorf("keyId must not be empty")
	}
	if config == nil {
		config = NewSignConfig()
	}
	return &Signer{
		keyId:  keyId,
		key:    key,
		alg:    "hmac-sha256",
		config: config,
		fields: fields,
	}, nil
}

func NewRSASigner(keyId string, key *rsa.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if keyId == "" {
		return nil, fmt.Errorf("keyId must not be empty")
	}
	if config == nil {
		config = NewSignConfig()
	}
	return &Signer{
		keyId:  keyId,
		key:    key,
		alg:    "rsa-v1_5-sha256",
		config: config,
		fields: fields,
	}, nil
}

func NewRSAPSSSigner(keyId string, key *rsa.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if keyId == "" {
		return nil, fmt.Errorf("keyId must not be empty")
	}
	if config == nil {
		config = NewSignConfig()
	}
	return &Signer{
		keyId:  keyId,
		key:    key,
		alg:    "rsa-pss-sha512",
		config: config,
		fields: fields,
	}, nil
}

func NewP256Signer(keyId string, key *ecdsa.PrivateKey, config *SignConfig, fields Fields) (*Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if keyId == "" {
		return nil, fmt.Errorf("keyId must not be empty")
	}
	if config == nil {
		config = NewSignConfig()
	}
	return &Signer{
		keyId:  keyId,
		key:    key,
		alg:    "ecdsa-p256-sha256",
		config: config,
		fields: fields,
	}, nil
}

func (s Signer) sign(buff []byte) ([]byte, error) {
	switch s.alg {
	case "hmac-sha256":
		mac := hmac.New(sha256.New, s.key.([]byte))
		mac.Write(buff)
		return mac.Sum(nil), nil
	case "rsa-v1_5-sha256":
		hashed := sha256.Sum256(buff)
		sig, err := rsa.SignPKCS1v15(nil, s.key.(*rsa.PrivateKey), crypto.SHA256, hashed[:])
		if err != nil {
			return nil, fmt.Errorf("RSA signature failed")
		}
		return sig, nil
	case "rsa-pss-sha512":
		hashed := sha512.Sum512(buff)
		sig, err := rsa.SignPSS(rand.Reader, s.key.(*rsa.PrivateKey), crypto.SHA512, hashed[:], nil)
		if err != nil {
			return nil, fmt.Errorf("RSA-PSS signature failed")
		}
		return sig, nil
	case "ecdsa-p256-sha256":
		hashed := sha256.Sum256(buff)
		return ecdsaSignRaw(rand.Reader, s.key.(*ecdsa.PrivateKey), hashed[:])
	default:
		return nil, fmt.Errorf("sign: unknown algorithm \"%s\"", s.alg)
	}
}

type Verifier struct {
	keyId string
	key   interface{}
	alg   string
	c     *VerifyConfig
	f     Fields
}

// NewHMACSHA256Verifier generates a new verifier for HMAC-SHA256 signatures. Set config to nil for a default configuration.
// Fields is the list of required headers and fields, which may be empty (but this is typically insecure).
func NewHMACSHA256Verifier(keyId string, key []byte, config *VerifyConfig, fields Fields) (*Verifier, error) {
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
		keyId: keyId,
		key:   key,
		alg:   "hmac-sha256",
		c:     config,
		f:     fields,
	}, nil
}

func NewRSAVerifier(keyId string, key *rsa.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if config == nil {
		config = NewVerifyConfig()
	}
	return &Verifier{
		keyId: keyId,
		key:   key,
		alg:   "rsa-v1_5-sha256",
		c:     config,
		f:     fields,
	}, nil
}

func NewRSAPSSVerifier(keyId string, key *rsa.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if config == nil {
		config = NewVerifyConfig()
	}
	return &Verifier{
		keyId: keyId,
		key:   key,
		alg:   "rsa-pss-sha512",
		c:     config,
		f:     fields,
	}, nil
}

func NewP256Verifier(keyId string, key *ecdsa.PublicKey, config *VerifyConfig, fields Fields) (*Verifier, error) {
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}
	if config == nil {
		config = NewVerifyConfig()
	}
	return &Verifier{
		keyId: keyId,
		key:   key,
		alg:   "ecdsa-p256-sha256",
		c:     config,
		f:     fields,
	}, nil
}

func (v Verifier) verify(buff []byte, sig []byte) (bool, error) {
	switch v.alg {
	case "hmac-sha256":
		mac := hmac.New(sha256.New, v.key.([]byte))
		mac.Write(buff)
		return bytes.Equal(mac.Sum(nil), sig), nil
	case "rsa-v1_5-sha256":
		hashed := sha256.Sum256(buff)
		err := rsa.VerifyPKCS1v15(v.key.(*rsa.PublicKey), crypto.SHA256, hashed[:], sig)
		if err != nil {
			return false, fmt.Errorf("RSA verification failed: %w", err)
		}
		return true, nil
	case "rsa-pss-sha512":
		hashed := sha512.Sum512(buff)
		err := rsa.VerifyPSS(v.key.(*rsa.PublicKey), crypto.SHA512, hashed[:], sig, nil)
		if err != nil {
			return false, fmt.Errorf("RSA-PSS verification failed: %w", err)
		}
		return true, nil
	case "ecdsa-p256-sha256":
		hashed := sha256.Sum256(buff)
		return ecdsaVerifyRaw(v.key.(*ecdsa.PublicKey), hashed[:], sig)
		//		return ecdsa.VerifyASN1(v.key.(*ecdsa.PublicKey), hashed[:], sig), nil
	default:
		return false, fmt.Errorf("verify: unknown algorithm \"%s\"", v.alg)
	}
}
