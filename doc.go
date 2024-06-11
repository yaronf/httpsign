// Package httpsign signs HTTP requests and responses as defined in RFC 9421, formerly draft-ietf-httpbis-message-signatures.
//
// For client-side message signing and verification, use the Client wrapper.
// Alternatively you can use SignRequest, VerifyResponse etc. directly, but this is more complicated.
// For server-side operation,
// WrapHandler installs a wrapper around a normal HTTP message handler.
// Digest functionality (creation and validation of the Content-Digest header) is available automatically
// through the Client and WrapHandler interfaces, otherwise it is available separately.
package httpsign
