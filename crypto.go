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
	keyId string
	key   interface{}
	alg   string
}

func NewHMACSHA256Signer(keyId string, key []byte) (*Signer, error) {
	if len(key) < 64 {
		return nil, fmt.Errorf("key must be at least 64 bytes long")
	}
	return &Signer{
		keyId: keyId,
		key:   key,
		alg:   "hmac-sha256",
	}, nil
}

func NewRSASigner(keyId string, key rsa.PrivateKey) (*Signer, error) {
	return &Signer{
		keyId: keyId,
		key:   key,
		alg:   "rsa-v1_5-sha256",
	}, nil
}

func NewRSAPSSSigner(keyId string, key rsa.PrivateKey) (*Signer, error) {
	return &Signer{
		keyId: keyId,
		key:   key,
		alg:   "rsa-pss-sha512",
	}, nil
}

func NewP256Signer(keyId string, key ecdsa.PrivateKey) (*Signer, error) {
	return &Signer{
		keyId: keyId,
		key:   key,
		alg:   "ecdsa-p256-sha256",
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
		sig, err := rsa.SignPSS(nil, s.key.(*rsa.PrivateKey), crypto.SHA512, hashed[:], nil)
		if err != nil {
			return nil, fmt.Errorf("RSA signature failed")
		}
		return sig, nil
	case "ecdsa-p256-sha256":
		hashed := sha256.Sum256(buff)
		sig, err := ecdsa.SignASN1(rand.Reader, s.key.(*ecdsa.PrivateKey), hashed[:])
		if err != nil {
			return nil, fmt.Errorf("RSA signature failed")
		}
		return sig, nil
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", s.alg)
	}
}

type Verifier struct {
	keyId string
	key   interface{}
	alg   string
}

func NewHMACSHA256Verifier(keyId string, key []byte) (*Verifier, error) {
	if len(key) < 64 {
		return nil, fmt.Errorf("key must be at least 64 bytes long")
	}
	return &Verifier{
		keyId: keyId,
		key:   key,
		alg:   "hmac-sha256",
	}, nil
}

// TODO more verifiers

func (v Verifier) verify(buff []byte, sig []byte) (bool, error) {
	switch v.alg {
	case "hmac-sha256":
		mac := hmac.New(sha256.New, v.key.([]byte))
		mac.Write(buff)
		return bytes.Equal(mac.Sum(nil), sig), nil
	default:
		return false, fmt.Errorf("unknown algorithm")
	}
}
