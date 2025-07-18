package httpsign

import (
	"crypto/ecdsa"
	"fmt"
	"io"
	"math/big"
)

// These functions extend the ecdsa package by adding raw, JWS-style signatures

func ecdsaSignRaw(rd io.Reader, priv *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("nil private key")
	}
	r, s, err := ecdsa.Sign(rd, priv, hash)
	if err != nil {
		return nil, err
	}
	curve := priv.PublicKey.Params().Name
	lr, ls, err := sigComponentLen(curve)
	if err != nil {
		return nil, err
	}
	rb, sb := make([]byte, lr), make([]byte, ls)
	if r.BitLen() > 8*lr || s.BitLen() > 8*ls {
		return nil, fmt.Errorf("signature values too long")
	}
	r.FillBytes(rb)
	s.FillBytes(sb)
	return append(rb, sb...), nil
}

func ecdsaVerifyRaw(pub *ecdsa.PublicKey, hash []byte, sig []byte) (bool, error) {
	if pub == nil {
		return false, fmt.Errorf("nil public key")
	}
	curve := pub.Params().Name
	lr, ls, err := sigComponentLen(curve)
	if err != nil {
		return false, err
	}
	if len(sig) != lr+ls {
		return false, fmt.Errorf("signature length is %d, expecting %d", len(sig), lr+ls)
	}
	r := new(big.Int)
	r.SetBytes(sig[0:lr])
	s := new(big.Int)
	s.SetBytes(sig[lr : lr+ls])
	return ecdsa.Verify(pub, hash, r, s), nil
}

func sigComponentLen(curve string) (int, int, error) {
	var lr, ls int
	switch curve {
	case "P-256":
		lr = 32
		ls = 32
	case "P-384":
		lr = 48
		ls = 48
	default:
		return 0, 0, fmt.Errorf("unknown curve \"%s\"", curve)
	}
	return lr, ls, nil
}
