// Package httpsign signs HTTP requests and responses as defined in draft-ietf-httpbis-message-signatures.
// See https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-07.html.
//
// For client-side message signing, use the Client wrapper. Alternatively, use SignRequest, VerifyResponse directly,
// but this is more complicated.
// For server-side operation,
// WrapHandler installs a wrapper around a normal HTTP message handler.
package httpsign

import (
	"encoding/base64"
	"fmt"
	"github.com/dunglas/httpsfv"
	"net/http"
	"time"
)

func signMessage(config SignConfig, signatureName string, signer Signer, parsedMessage parsedMessage,
	fields Fields) (sigInputHeader string, signature string, err error) {
	sigParams, err := generateSigParams(&config, signer.keyID, signer.alg, fields)
	if err != nil {
		return "", "", err
	}
	sigInputHeader = fmt.Sprintf("%s=%s", signatureName, sigParams)
	signatureInput, err := generateSignatureInput(parsedMessage, fields, sigParams)
	if err != nil {
		return "", "", err
	}
	signature, err = generateSignature(signatureName, signer, signatureInput)
	if err != nil {
		return "", "", err
	}
	return sigInputHeader, signature, nil
}

func generateSignature(name string, signer Signer, input string) (string, error) {
	raw, err := signer.sign([]byte(input))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s=%s", name, encodeBytes(raw)), nil
}

func encodeBytes(raw []byte) string {
	return ":" + base64.StdEncoding.EncodeToString(raw) + ":"
}

func generateSignatureInput(message parsedMessage, fields Fields, params string) (string, error) {
	mf, err := matchFields(message.components, fields)
	if err != nil {
		return "", err
	}
	inp := ""
	for _, c := range mf {
		f, err := c.f.asSignatureInput()
		if err != nil {
			return "", fmt.Errorf("could not marshal %v", c.f)
		}
		for _, v := range c.v {
			inp += fmt.Sprintf("%s: %s\n", f, v)
		}
	}
	inp += fmt.Sprintf("\"%s\": %s", "@signature-params", params)
	// log.Println("inp:", "\n"+inp)
	return inp, nil
}

func generateSigParams(config *SignConfig, keyID, alg string, fields Fields) (string, error) {
	p := httpsfv.NewParams()
	var createdTime int64
	if config.fakeCreated != 0 {
		createdTime = config.fakeCreated
	} else {
		createdTime = time.Now().Unix()
	}
	if config.signCreated {
		p.Add("created", createdTime)
	}
	if config.expires != 0 {
		p.Add("expires", config.expires)
	}
	if config.nonce != "" {
		p.Add("nonce", config.nonce)
	}
	if config.signAlg {
		p.Add("alg", alg)
	}
	p.Add("keyid", keyID)
	return fields.asSignatureInput(p)
}

//
// SignRequest signs an HTTP request. Returns the Signature-Input and the Signature header values.
//
func SignRequest(signatureName string, signer Signer, req *http.Request) (signatureInput, signature string, err error) {
	if req == nil {
		return "", "", fmt.Errorf("nil request")
	}
	if signatureName == "" {
		return "", "", fmt.Errorf("empty signature name")
	}
	if signer.config.requestResponse != nil {
		return "", "", fmt.Errorf("use request-response only to sign responses")
	}
	parsedMessage, err := parseRequest(req)
	if err != nil {
		return "", "", err
	}
	return signMessage(*signer.config, signatureName, signer, *parsedMessage, signer.fields)
}

//
// SignResponse signs an HTTP response. Returns the Signature-Input and the Signature header values.
//
func SignResponse(signatureName string, signer Signer, res *http.Response) (signatureInput, signature string, err error) {
	if res == nil {
		return "", "", fmt.Errorf("nil response")
	}
	if signatureName == "" {
		return "", "", fmt.Errorf("empty signature name")
	}
	parsedMessage, err := parseResponse(res)
	if err != nil {
		return "", "", err
	}
	extendedFields := addPseudoHeaders(parsedMessage, signer.config.requestResponse, signer.fields)
	return signMessage(*signer.config, signatureName, signer, *parsedMessage, extendedFields)
}

// Handle the special header-like @request-response
func addPseudoHeaders(message *parsedMessage, rr *requestResponse, fields Fields) Fields {
	if rr != nil {
		rrfield := field{
			name:      "@request-response",
			flagName:  "key",
			flagValue: rr.name,
		}
		message.components[rrfield] = []string{rr.signature}
		return append(fields, rrfield)
	}
	return fields
}

//
// VerifyRequest verifies a signed HTTP request. Returns an error if verification failed for any reason, otherwise nil.
//
func VerifyRequest(signatureName string, verifier Verifier, req *http.Request) (err error) {
	if req == nil {
		return fmt.Errorf("nil request")
	}
	if signatureName == "" {
		return fmt.Errorf("empty signature name")
	}
	if verifier.config.requestResponse != nil {
		return fmt.Errorf("use request-response only to verify responses")
	}
	parsedMessage, err := parseRequest(req)
	if err != nil {
		return err
	}
	return verifyMessage(*verifier.config, signatureName, verifier, *parsedMessage, verifier.fields)
}

// RequestDetails parses a signed request and returns the key ID and optionally the algorithm used in the given signature.
func RequestDetails(signatureName string, req *http.Request) (keyID, alg string, err error) {
	if req == nil {
		return "", "", fmt.Errorf("nil request")
	}
	if signatureName == "" {
		return "", "", fmt.Errorf("empty signature name")
	}
	parsedMessage, err := parseRequest(req)
	if err != nil {
		return "", "", err
	}
	return messageKeyID(signatureName, *parsedMessage)
}

// ResponseDetails parses a signed response and returns the key ID and optionally the algorithm used in the given signature.
func ResponseDetails(signatureName string, res *http.Response) (keyID, alg string, err error) {
	if res == nil {
		return "", "", fmt.Errorf("nil response")
	}
	if signatureName == "" {
		return "", "", fmt.Errorf("empty signature name")
	}
	parsedMessage, err := parseResponse(res)
	if err != nil {
		return "", "", err
	}
	return messageKeyID(signatureName, *parsedMessage)
}

// GetRequestSignature returns the base64-encoded signature, parsed from a signed request.
// This is useful for the request-response feature.
func GetRequestSignature(req *http.Request, signatureName string) (string, error) {
	if req == nil {
		return "", fmt.Errorf("nil request")
	}
	if signatureName == "" {
		return "", fmt.Errorf("empty signature name")
	}
	parsedMessage, err := parseRequest(req)
	if err != nil {
		return "", err
	}
	ws, found := parsedMessage.components[*fromDictHeader("signature", signatureName)]
	if !found {
		return "", fmt.Errorf("missing \"signature\" header for \"%s\"", signatureName)
	}
	if len(ws) > 1 {
		return "", fmt.Errorf("more than one \"signature\" value for \"%s\"", signatureName)
	}
	sigHeader := ws[0]
	sigRaw, err := parseWantSignature(sigHeader)
	if err != nil {
		return "", err
	}
	return encodeBytes(sigRaw), nil
}

func messageKeyID(signatureName string, parsedMessage parsedMessage) (keyID, alg string, err error) {
	si, found := parsedMessage.components[*fromDictHeader("signature-input", signatureName)]
	if !found {
		return "", "", fmt.Errorf("missing \"signature-input\" header, or cannot find \"%s\"", signatureName)
	}
	if len(si) > 1 {
		return "", "", fmt.Errorf("more than one \"signature-input\" for %s", signatureName)
	}
	signatureInput := si[0]
	psi, err := parseSignatureInput(signatureInput, signatureName)
	if err != nil {
		return
	}
	keyIDParam, ok := psi.params["keyid"]
	if !ok {
		return "", "", fmt.Errorf("missing \"keyid\" parameter")
	}
	keyID, ok = keyIDParam.(string)
	if !ok {
		return "", "", fmt.Errorf("malformed \"keyid\" parameter")
	}
	algParam, ok := psi.params["alg"] // "alg" is optional
	if ok {
		alg, ok = algParam.(string)
		if !ok {
			return "", "", fmt.Errorf("malformed \"alg\" parameter")
		}
	}
	return keyID, alg, nil
}

//
// VerifyResponse verifies a signed HTTP response. Returns an error if verification failed for any reason, otherwise nil.
//
func VerifyResponse(signatureName string, verifier Verifier, res *http.Response) (err error) {
	if res == nil {
		return fmt.Errorf("nil response")
	}
	if signatureName == "" {
		return fmt.Errorf("empty signature name")
	}
	parsedMessage, err := parseResponse(res)
	if err != nil {
		return err
	}
	extendedFields := addPseudoHeaders(parsedMessage, verifier.config.requestResponse, verifier.fields)
	return verifyMessage(*verifier.config, signatureName, verifier, *parsedMessage, extendedFields)
}

func verifyMessage(config VerifyConfig, name string, verifier Verifier, message parsedMessage, fields Fields) error {
	wsi, found := message.components[*fromDictHeader("signature-input", name)]
	if !found {
		return fmt.Errorf("missing \"signature-input\" header, or cannot find signature \"%s\"", name)
	}
	if len(wsi) > 1 {
		return fmt.Errorf("multiple \"signature-header\" values for %s", name)
	}
	wantSignatureInput := wsi[0]
	ws, found := message.components[*fromDictHeader("signature", name)]
	if !found {
		return fmt.Errorf("missing \"signature\" header")
	}
	if len(ws) > 1 {
		return fmt.Errorf("multiple \"signature\" values for %s", name)
	}
	wantSignature := ws[0]
	delete(message.components, *fromDictHeader("signature-input", name))
	delete(message.components, *fromDictHeader("signature", name))
	wantSigRaw, err := parseWantSignature(wantSignature)
	if err != nil {
		return err
	}
	psiSig, err := parseSignatureInput(wantSignatureInput, name)
	if err != nil {
		return err
	}
	if !(psiSig.fields.contains(&fields)) {
		return fmt.Errorf("actual signature does not cover all required fields")
	}
	err = applyVerificationPolicy(psiSig, config)
	if err != nil {
		return err
	}
	signatureInput, err := generateSignatureInput(message, psiSig.fields, psiSig.origSigParams)
	if err != nil {
		return err
	}
	return verifySignature(verifier, signatureInput, wantSigRaw)
}

func applyVerificationPolicy(psi *psiSignature, config VerifyConfig) error {
	err := applyPolicyCreated(psi, config)
	if err != nil {
		return err
	}
	err2 := applyPolicyAlgs(psi, config)
	if err2 != nil {
		return err2
	}
	err3 := applyPolicyExpired(psi, config)
	if err3 != nil {
		return err3
	}
	return nil
}

func applyPolicyExpired(psi *psiSignature, config VerifyConfig) error {
	if config.rejectExpired {
		now := time.Now()
		expiresParam, ok := psi.params["expires"]
		if ok {
			expires, ok := expiresParam.(int64)
			if !ok {
				return fmt.Errorf("malformed \"expires\" parameter")
			}
			expiresTime := time.Unix(expires, 0)
			if now.After(expiresTime) {
				return fmt.Errorf("expired signature")
			}
		}
	}
	return nil
}

func applyPolicyAlgs(psi *psiSignature, config VerifyConfig) error {
	if len(config.allowedAlgs) > 0 {
		algParam, ok := psi.params["alg"]
		if !ok {
			return fmt.Errorf("missing \"alg\" parameter")
		}
		alg, ok := algParam.(string)
		if !ok {
			return fmt.Errorf("malformed \"alg\" parameter")
		}
		var algFound = false
		for _, a := range config.allowedAlgs {
			if a == alg {
				algFound = true
			}
		}
		if !algFound {
			return fmt.Errorf("\"alg\" parameter not allowed by policy")
		}
	}
	return nil
}

func applyPolicyCreated(psi *psiSignature, config VerifyConfig) error {
	if config.verifyCreated {
		now := time.Now()
		createdParam, ok := psi.params["created"]
		if !ok {
			return fmt.Errorf("missing \"created\" parameter")
		}
		created, ok := createdParam.(int64)
		if !ok {
			return fmt.Errorf("malformed \"created\" parameter")
		}
		createdTime := time.Unix(created, 0)
		if createdTime.After(now.Add(config.notNewerThan)) {
			return fmt.Errorf("message appears to be too new, check for clock skew")
		}
		if createdTime.Add(config.notOlderThan).Before(now) {
			return fmt.Errorf("message is too old, check for replay")
		}
	}
	return nil
}

func verifySignature(verifier Verifier, input string, signature []byte) error {
	verified, err := verifier.verify([]byte(input), signature)
	if !verified && (err == nil) {
		err = fmt.Errorf("bad signature, check key or signature value")
	}
	return err
}

type psiSignature struct {
	signatureName string
	origSigParams string
	fields        Fields
	params        map[string]interface{}
}

func parseSignatureInput(input string, sigName string) (*psiSignature, error) {
	sigs, err := httpsfv.UnmarshalDictionary([]string{sigName + "=" + input}) // yes this is a hack, there is no UnmarshalInnerList
	if err != nil {
		return nil, fmt.Errorf("could not parse Signature-Input as dictionary: %w", err)
	}
	memberForName, _ := sigs.Get(sigName)
	fieldsList, ok := memberForName.(httpsfv.InnerList)
	osp, err := httpsfv.Marshal(fieldsList) // undocumented functionality
	if err != nil {
		return nil, fmt.Errorf("could not marshal inner list: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("Signature-Input: signature %s does not have an inner list", sigName)
	}
	var f Fields
	for _, ff := range fieldsList.Items {
		fname, ok := ff.Value.(string)
		if !ok {
			return nil, fmt.Errorf("Signature-Input: value is not a string")
		}
		if ff.Params == nil || len(ff.Params.Names()) == 0 {
			f = append(f, *fromHeaderName(fname))
		} else {
			if len(ff.Params.Names()) > 1 {
				return nil, fmt.Errorf("more than one param for \"%s\"", fname)
			}
			flagNames := ff.Params.Names()
			flagName := flagNames[0]
			flagValue, _ := ff.Params.Get(flagName)
			fv := flagValue.(string)
			f = append(f, field{
				name:      fname,
				flagName:  flagName,
				flagValue: fv,
			})
		}
	}
	params := map[string]interface{}{}
	ps := fieldsList.Params
	for _, p := range (*ps).Names() {
		pp, ok := ps.Get(p)
		if !ok {
			return nil, fmt.Errorf("could not read param \"%s\"", p)
		}
		params[p] = pp
	}
	return &psiSignature{sigName, osp, f, params}, nil
}

func parseWantSignature(wantSignature string) ([]byte, error) {
	wantSigItem, err := httpsfv.UnmarshalItem([]string{wantSignature})
	if err != nil {
		return nil, fmt.Errorf("unexpected value in signature field: %s", err)
	}
	wantSigRaw, ok := wantSigItem.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("could not parse raw signature")
	}
	return wantSigRaw, nil
}
