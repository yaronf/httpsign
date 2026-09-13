package httpsign

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

// inferJWSVerifierKey resolves a JWS signature algorithm and a raw key suitable for
// NewJWSVerifierWithAlg from a finite set of key types (see docs for NewJWSVerifier).
func inferJWSVerifierKey(key any) (jwa.SignatureAlgorithm, any, error) {
	if key == nil {
		return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf("key must not be nil")
	}
	switch k := key.(type) {
	case jwk.Key:
		return inferFromJWK(k)
	case *ecdsa.PublicKey:
		if k == nil {
			return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf("key must not be nil")
		}
		alg, err := algFromECDSACurve(k.Curve)
		if err != nil {
			return jwa.EmptySignatureAlgorithm(), nil, err
		}
		return alg, k, nil
	case *mldsa.PublicKey:
		if k == nil {
			return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf("key must not be nil")
		}
		alg, err := algFromMLDSAParams(k.Parameters())
		if err != nil {
			return jwa.EmptySignatureAlgorithm(), nil, err
		}
		return alg, k, nil
	default:
		return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf(
			"cannot infer JWS algorithm from %T; use NewJWSVerifierWithAlg or a jwk.Key / *ecdsa.PublicKey / *mldsa.PublicKey",
			key,
		)
	}
}

func inferFromJWK(key jwk.Key) (jwa.SignatureAlgorithm, any, error) {
	alg, err := resolveAlgFromJWK(key)
	if err != nil {
		return jwa.EmptySignatureAlgorithm(), nil, err
	}
	raw, err := jwk.Export[any](key)
	if err != nil {
		return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf("export JWK: %w", err)
	}
	// Prefer public material for verify constructors.
	switch r := raw.(type) {
	case *ecdsa.PrivateKey:
		raw = &r.PublicKey
	case *mldsa.PrivateKey:
		pub, ok := r.Public().(*mldsa.PublicKey)
		if !ok {
			return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf("ML-DSA private key Public() returned %T, want *mldsa.PublicKey", r.Public())
		}
		raw = pub
	case ed25519.PrivateKey:
		pub, ok := r.Public().(ed25519.PublicKey)
		if !ok {
			return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf("Ed25519 private key Public() returned %T, want ed25519.PublicKey", r.Public())
		}
		raw = pub
	}
	return alg, raw, nil
}

// inferJWSSignerKeyFromJWK resolves alg and raw private key material from a private JWK.
func inferJWSSignerKeyFromJWK(key jwk.Key) (jwa.SignatureAlgorithm, any, error) {
	if key == nil {
		return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf("key must not be nil")
	}
	if err := requirePrivateJWKForSign(key); err != nil {
		return jwa.EmptySignatureAlgorithm(), nil, err
	}
	alg, err := resolveAlgFromJWK(key)
	if err != nil {
		return jwa.EmptySignatureAlgorithm(), nil, err
	}
	raw, err := jwk.Export[any](key)
	if err != nil {
		return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf("export JWK: %w", err)
	}
	return alg, raw, nil
}

func requirePrivateJWKForSign(key jwk.Key) error {
	priv, err := jwk.IsPrivateKey(key)
	if err != nil {
		// Symmetric oct keys are not AsymmetricKey; they are valid HMAC signing material.
		if key.KeyType() == jwa.OctetSeq() {
			return nil
		}
		return fmt.Errorf("JWK is not usable for signing: %w", err)
	}
	if !priv {
		return fmt.Errorf("JWK must be a private key for signing")
	}
	return nil
}

func resolveAlgFromJWK(key jwk.Key) (jwa.SignatureAlgorithm, error) {
	var fromAlg jwa.SignatureAlgorithm
	var hasAlg bool
	if ka, ok := key.Algorithm(); ok {
		sig, ok := jwa.LookupSignatureAlgorithm(ka.String())
		if !ok {
			return jwa.EmptySignatureAlgorithm(), fmt.Errorf("JWK alg %q is not a known JWS signature algorithm", ka.String())
		}
		fromAlg = sig
		hasAlg = true
	}

	fromStruct, hasStruct, err := structuralAlgFromJWK(key)
	if err != nil {
		return jwa.EmptySignatureAlgorithm(), err
	}

	switch {
	case hasAlg && hasStruct:
		if !jwsSignatureAlgsAgree(fromAlg, fromStruct) {
			return jwa.EmptySignatureAlgorithm(), fmt.Errorf(
				"JWK alg %s disagrees with structural mapping %s", fromAlg, fromStruct,
			)
		}
		// Prefer the JWK's stated alg; EdDSA ↔ Ed25519 are treated as agreeing (RFC 9864).
		return fromAlg, nil
	case hasAlg:
		return fromAlg, nil
	case hasStruct:
		return fromStruct, nil
	default:
		return jwa.EmptySignatureAlgorithm(), fmt.Errorf(
			"cannot infer JWS algorithm from JWK (kty=%s): set alg, or use NewJWSSigner / NewJWSVerifierWithAlg",
			key.KeyType(),
		)
	}
}

type jwkHasCrv interface {
	Crv() (jwa.EllipticCurveAlgorithm, bool)
}


func structuralAlgFromJWK(key jwk.Key) (jwa.SignatureAlgorithm, bool, error) {
	switch key.KeyType() {
	case jwa.EC(), jwa.OKP():
		crvKey, ok := key.(jwkHasCrv)
		if !ok {
			return jwa.EmptySignatureAlgorithm(), false, fmt.Errorf("JWK kty=%s missing curve", key.KeyType())
		}
		crv, ok := crvKey.Crv()
		if !ok {
			return jwa.EmptySignatureAlgorithm(), false, fmt.Errorf("JWK kty=%s missing crv", key.KeyType())
		}
		alg, err := algFromJWKCurve(crv)
		if err != nil {
			return jwa.EmptySignatureAlgorithm(), false, err
		}
		return alg, true, nil
	case jwa.RSA(), jwa.OctetSeq(), jwa.AKP():
		// RSA/oct ambiguous without alg; AKP requires alg (RFC 9964).
		return jwa.EmptySignatureAlgorithm(), false, nil
	default:
		return jwa.EmptySignatureAlgorithm(), false, nil
	}
}

func algFromJWKCurve(crv jwa.EllipticCurveAlgorithm) (jwa.SignatureAlgorithm, error) {
	switch crv {
	case jwa.P256():
		return jwa.ES256(), nil
	case jwa.P384():
		return jwa.ES384(), nil
	case jwa.P521():
		return jwa.ES512(), nil
	case jwa.Ed25519():
		// RFC 9864 name; legacy JWK alg "EdDSA" still agrees via jwsSignatureAlgsAgree.
		return jwa.EdDSAEd25519(), nil
	default:
		return jwa.EmptySignatureAlgorithm(), fmt.Errorf("cannot infer JWS algorithm from crv %s", crv)
	}
}

// jwsSignatureAlgsAgree reports whether two registry algs are the same crypto choice.
// Legacy "EdDSA" and RFC 9864 "Ed25519" both mean Ed25519 signatures in jwx v4.
func jwsSignatureAlgsAgree(a, b jwa.SignatureAlgorithm) bool {
	if a.String() == b.String() {
		return true
	}
	return isEd25519JWSAlg(a) && isEd25519JWSAlg(b)
}

func isEd25519JWSAlg(alg jwa.SignatureAlgorithm) bool {
	switch alg {
	case jwa.EdDSA(), jwa.EdDSAEd25519():
		return true
	default:
		return false
	}
}

func algFromECDSACurve(curve elliptic.Curve) (jwa.SignatureAlgorithm, error) {
	if curve == nil {
		return jwa.EmptySignatureAlgorithm(), fmt.Errorf("ECDSA key has nil curve")
	}
	switch curve {
	case elliptic.P256():
		return jwa.ES256(), nil
	case elliptic.P384():
		return jwa.ES384(), nil
	case elliptic.P521():
		return jwa.ES512(), nil
	default:
		return jwa.EmptySignatureAlgorithm(), fmt.Errorf("cannot infer JWS algorithm from ECDSA curve %s", curve.Params().Name)
	}
}

func algFromMLDSAParams(params mldsa.Parameters) (jwa.SignatureAlgorithm, error) {
	switch params {
	case mldsa.MLDSA44():
		return jwa.MLDSA44(), nil
	case mldsa.MLDSA65():
		return jwa.MLDSA65(), nil
	case mldsa.MLDSA87():
		return jwa.MLDSA87(), nil
	default:
		return jwa.EmptySignatureAlgorithm(), fmt.Errorf("cannot infer JWS algorithm from ML-DSA parameter set %s", params)
	}
}

func rejectJWKKey(key any) error {
	if _, ok := key.(jwk.Key); ok {
		return fmt.Errorf("jwk.Key is not accepted here; use NewJWSVerifier to infer alg from the JWK")
	}
	return nil
}

func rejectJWKKeyForSigner(key any) error {
	if _, ok := key.(jwk.Key); ok {
		return fmt.Errorf("jwk.Key is not accepted here; use NewJWSSignerFromJWK to infer alg from the JWK")
	}
	return nil
}
