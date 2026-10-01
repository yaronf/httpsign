package httpsign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
)

// validateJWSKeyAlg checks that key is an appropriate Go type for alg, without using
// jws.AlgorithmsForKey (deprecated; not a compatibility API; over-broad for ECDSA/ML-DSA).
// When signing is true, asymmetric keys must be private; when false, they must be public.
// HMAC keys are symmetric and accepted for either role.
//
// Classical algs (RSA, ECDSA, Ed25519) and ML-DSA also accept an opaque crypto.Signer
// (HSM/KMS-backed keys, etc.) whose Public() reports the expected key shape — valid for
// both sign and verify (verify is local via Public()). Default jwx ML-DSA signing still
// requires *mldsa.PrivateKey; callers using an opaque Signer for ML-DSA must register a
// custom jws.Signer (jws.RegisterSigner) that accepts crypto.Signer. ML-DSA is foreign-JWS
// only — not a native RFC 9421 algorithm.
// JWK wrappers are rejected here so callers convert first (NewJWSSignerFromJWK / preferred verify).
func validateJWSKeyAlg(alg jwa.SignatureAlgorithm, key any, signing bool) error {
	switch alg {
	case jwa.HS256(), jwa.HS384(), jwa.HS512():
		return validateHMACKey(alg, key)
	case jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512():
		return validateRSAKey(alg, key, signing)
	case jwa.ES256(), jwa.ES384(), jwa.ES512():
		return validateECDSAKey(alg, key, signing)
	case jwa.EdDSA(), jwa.EdDSAEd25519():
		return validateEd25519Key(alg, key, signing)
	case jwa.MLDSA44(), jwa.MLDSA65(), jwa.MLDSA87():
		return validateMLDSAKey(alg, key, signing)
	default:
		// Passthrough: unknown/new jwx algs are left to jws.SignerFor / VerifierFor.
		// Keep hardening above for known classical/PQ algs only.
		return nil
	}
}

func validateHMACKey(alg jwa.SignatureAlgorithm, key any) error {
	k, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("algorithm %s requires []byte key, got %T", alg, key)
	}
	// RFC 7518 §3.2: key at least as large as the hash output.
	var minLen int
	switch alg {
	case jwa.HS256():
		minLen = 32
	case jwa.HS384():
		minLen = 48
	case jwa.HS512():
		minLen = 64
	default:
		return fmt.Errorf("unsupported HMAC algorithm %s", alg)
	}
	if len(k) < minLen {
		return fmt.Errorf("algorithm %s requires a key of at least %d bytes (RFC 7518), got %d", alg, minLen, len(k))
	}
	return nil
}

// publicFromSigner returns Public() for a crypto.Signer. Recovers from panics
// (e.g. malformed ed25519.PrivateKey) so cross-family probes return a normal miss.
func publicFromSigner(key any) (pub crypto.PublicKey, ok bool) {
	signer, isSigner := key.(crypto.Signer)
	if !isSigner || signer == nil {
		return nil, false
	}
	defer func() {
		if recover() != nil {
			pub = nil
			ok = false
		}
	}()
	pub = signer.Public()
	if pub == nil {
		return nil, false
	}
	return pub, true
}

func errNeedKeyType(alg jwa.SignatureAlgorithm, kind, gotType string) error {
	return fmt.Errorf("algorithm %s requires an %s key, got %s", alg, kind, gotType)
}

func errNeedKeyTypeFromSigner(alg jwa.SignatureAlgorithm, kind, gotType, pubType string) error {
	return fmt.Errorf("algorithm %s requires an %s key, got %s (Public %s)", alg, kind, gotType, pubType)
}

func typeString(v any) string { return fmt.Sprintf("%T", v) }

func validateRSAKey(alg jwa.SignatureAlgorithm, key any, signing bool) error {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k == nil {
			return fmt.Errorf("algorithm %s: nil RSA private key", alg)
		}
		if !signing {
			return fmt.Errorf("algorithm %s requires an RSA public key for verification", alg)
		}
	case rsa.PrivateKey:
		if !signing {
			return fmt.Errorf("algorithm %s requires an RSA public key for verification", alg)
		}
	case *rsa.PublicKey:
		if k == nil {
			return fmt.Errorf("algorithm %s: nil RSA public key", alg)
		}
		if signing {
			return fmt.Errorf("algorithm %s requires an RSA private key for signing", alg)
		}
	case rsa.PublicKey:
		if signing {
			return fmt.Errorf("algorithm %s requires an RSA private key for signing", alg)
		}
	default:
		pub, sok := publicFromSigner(key)
		if !sok {
			return errNeedKeyType(alg, "RSA", typeString(key))
		}
		switch rp := pub.(type) {
		case *rsa.PublicKey:
			if rp == nil {
				return fmt.Errorf("algorithm %s: nil RSA public key", alg)
			}
		case rsa.PublicKey:
			// ok
		default:
			return errNeedKeyTypeFromSigner(alg, "RSA", typeString(key), typeString(pub))
		}
		// Opaque crypto.Signer with RSA Public(): allowed for sign and verify.
	}
	return nil
}

// validateECDSAKey enforces RFC 7518 §3.4: ES256/ES384/ES512 bind to P-256/P-384/P-521.
// jwx's SignerFor path does not enforce this.
func validateECDSAKey(alg jwa.SignatureAlgorithm, key any, signing bool) error {
	curve, err := ecdsaCurveFor(alg, key, signing)
	if err != nil {
		return err
	}
	if curve == nil {
		return fmt.Errorf("algorithm %s: ECDSA key has nil curve", alg)
	}
	var want elliptic.Curve
	switch alg {
	case jwa.ES256():
		want = elliptic.P256()
	case jwa.ES384():
		want = elliptic.P384()
	case jwa.ES512():
		want = elliptic.P521()
	default:
		return fmt.Errorf("unsupported ECDSA algorithm %s", alg)
	}
	if curve != want {
		return fmt.Errorf("algorithm %s requires curve %s, got %s", alg, want.Params().Name, curve.Params().Name)
	}
	return nil
}

// ecdsaCurveFor returns the curve for a concrete ECDSA key or an opaque crypto.Signer
// whose Public() is ECDSA. Role checks (private vs public) apply only to concrete keys;
// Signers are accepted for both sign and verify.
func ecdsaCurveFor(alg jwa.SignatureAlgorithm, key any, signing bool) (elliptic.Curve, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k == nil {
			return nil, errNeedKeyType(alg, "ECDSA", typeString(key))
		}
		if !signing {
			return nil, fmt.Errorf("algorithm %s requires an ECDSA public key for verification", alg)
		}
		return k.Curve, nil
	case ecdsa.PrivateKey:
		if !signing {
			return nil, fmt.Errorf("algorithm %s requires an ECDSA public key for verification", alg)
		}
		return k.Curve, nil
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errNeedKeyType(alg, "ECDSA", typeString(key))
		}
		if signing {
			return nil, fmt.Errorf("algorithm %s requires an ECDSA private key for signing", alg)
		}
		return k.Curve, nil
	case ecdsa.PublicKey:
		if signing {
			return nil, fmt.Errorf("algorithm %s requires an ECDSA private key for signing", alg)
		}
		return k.Curve, nil
	default:
		pub, ok := publicFromSigner(key)
		if !ok {
			return nil, errNeedKeyType(alg, "ECDSA", typeString(key))
		}
		switch ep := pub.(type) {
		case *ecdsa.PublicKey:
			if ep == nil {
				return nil, errNeedKeyTypeFromSigner(alg, "ECDSA", typeString(key), typeString(pub))
			}
			return ep.Curve, nil
		case ecdsa.PublicKey:
			return ep.Curve, nil
		default:
			return nil, errNeedKeyTypeFromSigner(alg, "ECDSA", typeString(key), typeString(pub))
		}
	}
}

func validateEd25519Key(alg jwa.SignatureAlgorithm, key any, signing bool) error {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return fmt.Errorf("algorithm %s: Ed25519 private key must be %d bytes, got %d", alg, ed25519.PrivateKeySize, len(k))
		}
		if !signing {
			return fmt.Errorf("algorithm %s requires an Ed25519 public key for verification", alg)
		}
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf("algorithm %s: Ed25519 public key must be %d bytes, got %d", alg, ed25519.PublicKeySize, len(k))
		}
		if signing {
			return fmt.Errorf("algorithm %s requires an Ed25519 private key for signing", alg)
		}
	case *ed25519.PrivateKey:
		if k == nil || len(*k) != ed25519.PrivateKeySize {
			return fmt.Errorf("algorithm %s: invalid Ed25519 private key", alg)
		}
		if !signing {
			return fmt.Errorf("algorithm %s requires an Ed25519 public key for verification", alg)
		}
	case *ed25519.PublicKey:
		if k == nil || len(*k) != ed25519.PublicKeySize {
			return fmt.Errorf("algorithm %s: invalid Ed25519 public key", alg)
		}
		if signing {
			return fmt.Errorf("algorithm %s requires an Ed25519 private key for signing", alg)
		}
	default:
		pub, sok := publicFromSigner(key)
		if !sok {
			return errNeedKeyType(alg, "Ed25519", typeString(key))
		}
		switch ep := pub.(type) {
		case ed25519.PublicKey:
			if len(ep) != ed25519.PublicKeySize {
				return fmt.Errorf("algorithm %s: Ed25519 public key must be %d bytes, got %d", alg, ed25519.PublicKeySize, len(ep))
			}
		case *ed25519.PublicKey:
			if ep == nil || len(*ep) != ed25519.PublicKeySize {
				return fmt.Errorf("algorithm %s: invalid Ed25519 public key", alg)
			}
		default:
			return errNeedKeyTypeFromSigner(alg, "Ed25519", typeString(key), typeString(pub))
		}
		// Opaque crypto.Signer with Ed25519 Public(): allowed for sign and verify.
	}
	return nil
}

// validateMLDSAKey enforces that an ML-DSA JWS algorithm matches the key's parameter set.
// jwx also rejects mismatches at Sign/Verify for raw keys; this fails earlier at NewJWS* construction.
func validateMLDSAKey(alg jwa.SignatureAlgorithm, key any, signing bool) error {
	got, err := mldsaParamsFor(alg, key, signing)
	if err != nil {
		return err
	}
	var want mldsa.Parameters
	switch alg {
	case jwa.MLDSA44():
		want = mldsa.MLDSA44()
	case jwa.MLDSA65():
		want = mldsa.MLDSA65()
	case jwa.MLDSA87():
		want = mldsa.MLDSA87()
	default:
		return fmt.Errorf("unsupported ML-DSA algorithm %s", alg)
	}
	if got != want {
		return fmt.Errorf("algorithm %s requires ML-DSA parameter set %s, got %s", alg, want, got)
	}
	return nil
}

// mldsaParamsFor returns the parameter set for a concrete crypto/mldsa key or an opaque
// crypto.Signer whose Public() is *mldsa.PublicKey. Role checks apply only to concrete keys;
// Signers are accepted for both sign and verify.
func mldsaParamsFor(alg jwa.SignatureAlgorithm, key any, signing bool) (mldsa.Parameters, error) {
	switch k := key.(type) {
	case *mldsa.PrivateKey:
		if k == nil {
			return mldsa.Parameters{}, errNeedKeyType(alg, "crypto/mldsa", typeString(key))
		}
		if !signing {
			return mldsa.Parameters{}, fmt.Errorf("algorithm %s requires an ML-DSA public key for verification", alg)
		}
		return k.PublicKey().Parameters(), nil
	case *mldsa.PublicKey:
		if k == nil {
			return mldsa.Parameters{}, errNeedKeyType(alg, "crypto/mldsa", typeString(key))
		}
		if signing {
			return mldsa.Parameters{}, fmt.Errorf("algorithm %s requires an ML-DSA private key for signing", alg)
		}
		return k.Parameters(), nil
	default:
		pub, ok := publicFromSigner(key)
		if !ok {
			return mldsa.Parameters{}, errNeedKeyType(alg, "crypto/mldsa", typeString(key))
		}
		mp, ok := pub.(*mldsa.PublicKey)
		if !ok || mp == nil {
			return mldsa.Parameters{}, errNeedKeyTypeFromSigner(alg, "crypto/mldsa", typeString(key), typeString(pub))
		}
		return mp.Parameters(), nil
	}
}
