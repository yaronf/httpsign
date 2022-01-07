package main

import "fmt"

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
