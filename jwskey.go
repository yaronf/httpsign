package httpsign

import (
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
// HMAC keys are symmetric and accepted for either role. Only raw stdlib key types are
// accepted; crypto.Signer / JWK wrappers are rejected here so callers convert first.
func validateJWSKeyAlg(alg jwa.SignatureAlgorithm, key interface{}, signing bool) error {
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
		return fmt.Errorf("unsupported JWS algorithm %s", alg)
	}
}

func validateHMACKey(alg jwa.SignatureAlgorithm, key interface{}) error {
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

func validateRSAKey(alg jwa.SignatureAlgorithm, key interface{}, signing bool) error {
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
		return fmt.Errorf("algorithm %s requires an RSA key, got %T", alg, key)
	}
	return nil
}

// validateECDSAKey enforces RFC 7518 §3.4: ES256/ES384/ES512 bind to P-256/P-384/P-521.
// jwx's SignerFor path does not enforce this.
func validateECDSAKey(alg jwa.SignatureAlgorithm, key interface{}, signing bool) error {
	curve, isPrivate, ok := ecdsaKeyOf(key)
	if !ok {
		return fmt.Errorf("algorithm %s requires an ECDSA key, got %T", alg, key)
	}
	if signing && !isPrivate {
		return fmt.Errorf("algorithm %s requires an ECDSA private key for signing", alg)
	}
	if !signing && isPrivate {
		return fmt.Errorf("algorithm %s requires an ECDSA public key for verification", alg)
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

func ecdsaKeyOf(key interface{}) (curve elliptic.Curve, isPrivate, ok bool) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k == nil {
			return nil, false, false
		}
		return k.Curve, true, true
	case ecdsa.PrivateKey:
		return k.Curve, true, true
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, false, false
		}
		return k.Curve, false, true
	case ecdsa.PublicKey:
		return k.Curve, false, true
	default:
		return nil, false, false
	}
}

func validateEd25519Key(alg jwa.SignatureAlgorithm, key interface{}, signing bool) error {
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
		return fmt.Errorf("algorithm %s requires an Ed25519 key, got %T", alg, key)
	}
	return nil
}

// validateMLDSAKey enforces that an ML-DSA JWS algorithm matches the key's parameter set.
// jwx also rejects mismatches at Sign/Verify; this fails earlier at NewJWS* construction.
func validateMLDSAKey(alg jwa.SignatureAlgorithm, key interface{}, signing bool) error {
	got, isPrivate, ok := mldsaKeyOf(key)
	if !ok {
		return fmt.Errorf("algorithm %s requires a crypto/mldsa key, got %T", alg, key)
	}
	if signing && !isPrivate {
		return fmt.Errorf("algorithm %s requires an ML-DSA private key for signing", alg)
	}
	if !signing && isPrivate {
		return fmt.Errorf("algorithm %s requires an ML-DSA public key for verification", alg)
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

func mldsaKeyOf(key interface{}) (params mldsa.Parameters, isPrivate, ok bool) {
	switch k := key.(type) {
	case *mldsa.PrivateKey:
		if k == nil {
			return mldsa.Parameters{}, false, false
		}
		return k.PublicKey().Parameters(), true, true
	case *mldsa.PublicKey:
		if k == nil {
			return mldsa.Parameters{}, false, false
		}
		return k.Parameters(), false, true
	default:
		return mldsa.Parameters{}, false, false
	}
}
