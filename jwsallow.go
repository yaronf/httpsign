package httpsign

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
)

// JWSAlgAllowlist is a non-empty set of permitted jwa signature algorithms for foreign JWS verify.
// Pass nil to NewJWSVerifier / NewJWSVerifierWithAlg to skip alg policy (lazy / tests).
// Prefer a real allowlist whenever key selection (e.g. keyid) can be attacker-influenced.
type JWSAlgAllowlist struct {
	algs map[string]struct{}
}

// resolveRegisteredJWSAlg requires alg to be in the jwx signature-algorithm registry and
// rejects empty / "none". Returns the canonical registry value so handcrafted
// jwa.NewSignatureAlgorithm("HS256") is normalized to jwa.HS256() for key checks.
// Unregistered strings (e.g. "NONE", "hs256") are rejected — jwx SignerFor/VerifierFor
// may still accept them; we do not.
func resolveRegisteredJWSAlg(alg jwa.SignatureAlgorithm) (jwa.SignatureAlgorithm, error) {
	name := alg.String()
	if name == "" {
		return jwa.EmptySignatureAlgorithm(), fmt.Errorf("JWS algorithm must not be empty")
	}
	canonical, ok := jwa.LookupSignatureAlgorithm(name)
	if !ok {
		return jwa.EmptySignatureAlgorithm(), fmt.Errorf("unknown or unregistered JWS algorithm %q", name)
	}
	if canonical == jwa.NoSignature() {
		return jwa.EmptySignatureAlgorithm(), fmt.Errorf("the NONE signing algorithm is expressly disallowed")
	}
	return canonical, nil
}

// NewJWSAlgAllowlist builds an allowlist. Rejects an empty list, unregistered algs, and none.
func NewJWSAlgAllowlist(algs ...jwa.SignatureAlgorithm) (*JWSAlgAllowlist, error) {
	if len(algs) == 0 {
		return nil, fmt.Errorf("JWS algorithm allowlist must not be empty")
	}
	set := make(map[string]struct{}, len(algs))
	for _, alg := range algs {
		canonical, err := resolveRegisteredJWSAlg(alg)
		if err != nil {
			return nil, err
		}
		set[canonical.String()] = struct{}{}
	}
	return &JWSAlgAllowlist{algs: set}, nil
}

// Contains reports whether alg is permitted. A nil receiver does not contain any alg
// (callers should treat nil allowlist as “skip policy” before calling Contains).
// Comparison is by algorithm name string; constructors resolve to registry values first.
// Legacy "EdDSA" and RFC 9864 "Ed25519" are treated as equivalent.
func (a *JWSAlgAllowlist) Contains(alg jwa.SignatureAlgorithm) bool {
	if a == nil {
		return false
	}
	if _, ok := a.algs[alg.String()]; ok {
		return true
	}
	if !isEd25519JWSAlg(alg) {
		return false
	}
	_, legacy := a.algs[jwa.EdDSA().String()]
	_, modern := a.algs[jwa.EdDSAEd25519().String()]
	return legacy || modern
}

func checkJWSAlgAllowed(allowed *JWSAlgAllowlist, alg jwa.SignatureAlgorithm) error {
	if allowed == nil {
		return nil
	}
	if !allowed.Contains(alg) {
		return fmt.Errorf("JWS algorithm %s is not in the allowlist", alg)
	}
	return nil
}
