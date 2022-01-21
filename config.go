package httpsign

// SignConfig contains additional configuration for the signer.
type SignConfig struct {
	signAlg         bool
	signCreated     bool
	fakeCreated     int64
	requestResponse struct{ name, signature string }
}

// NewSignConfig generates a default configuration.
func NewSignConfig() *SignConfig {
	return &SignConfig{
		signAlg:     true,
		signCreated: true,
		fakeCreated: 0,
	}
}

// SignAlg indicates that an "alg" signature parameters must be generated and signed (default: true).
func (c *SignConfig) SignAlg(b bool) *SignConfig {
	c.signAlg = b
	return c
}

// SignCreated indicates that a "created" signature parameters must be generated and signed (default: true).
func (c *SignConfig) SignCreated(b bool) *SignConfig {
	c.signCreated = b
	return c
}

// setFakeCreated indicates that the specified Unix timestamp must be used instead of the current time
// (default: 0, meaning use current time). Only used for testing.
func (c *SignConfig) setFakeCreated(ts int64) *SignConfig {
	c.fakeCreated = ts
	return c
}

// SetRequestResponse allows the server to indicate signature name and signature that
// it had received from a client and include it in the signature input
func (c *SignConfig) SetRequestResponse(name, signature string) *SignConfig {
	// TODO
	c.requestResponse = struct{ name, signature string }{name, signature}
	return c
}

// VerifyConfig contains additional configuration for the verifier.
type VerifyConfig struct {
}

// NewVerifyConfig generates a default configuration.
func NewVerifyConfig() *VerifyConfig {
	return &VerifyConfig{
		// TODO
	}
}
