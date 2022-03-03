// Package httpsign signs HTTP requests and responses as defined in draft-ietf-httpbis-message-signatures.
// See https://datatracker.ietf.org/doc/draft-ietf-httpbis-message-signatures/ for the latest draft version.
//
// For client-side message signing and verification, use the Client wrapper.
// Alternatively you can use SignRequest, VerifyResponse etc. directly, but this is more complicated.
// For server-side operation,
// WrapHandler installs a wrapper around a normal HTTP message handler.
package httpsign
