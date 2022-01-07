package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

type Signer struct {
	keyId string
	key   interface{}
	alg   string
}

func NewHMACSHA256Signer(keyId string, key []byte) (*Signer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes long")
	}
	return &Signer{
		keyId: keyId,
		key:   key,
		alg:   "hmac-sha256",
	}, nil
}

func (s Signer) sign(buff []byte) ([]byte, error) {
	switch s.alg {
	case "hmac-sha256":
		mac := hmac.New(sha256.New, s.key.([]byte))
		mac.Write(buff)
		return mac.Sum(nil), nil
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", s.alg)
	}
}
