// Package httpsign signs HTTP requests and responses as defined in draft-ietf-httpbis-message-signatures.
// See https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-07.html.
//
// For client-side message signing, use SignRequest, VerifyResponse etc. For server-side operation,
// WrapHandler installs a wrapper around a normal HTTP message handler.
package httpsign

import (
	"encoding/base64"
	"fmt"
	"github.com/dunglas/httpsfv"
	"net/http"
	"strings"
	"time"
)

func signMessage(config SignConfig, signatureName string, signer Signer, parsedMessage parsedMessage,
	fields Fields) (sigInputHeader string, signature string, err error) {
	err = validateFields(fields)
	if err != nil {
		return "", "", err
	}
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

func validateFields(fields Fields) error {
	for _, f := range fields {
		if f.name != strings.ToLower(f.name) {
			return fmt.Errorf("field \"%s\" is not lowercase", f.name)
		}
		// Note that using "signature" and "signature-input" is allowed
	}
	return nil
}

func generateSignature(name string, signer Signer, input string) (string, error) {
	raw, err := signer.sign([]byte(input))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s=:%s:", name, base64.StdEncoding.EncodeToString(raw)), nil
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
	addPseudoHeaders(parsedMessage, *signer.config)
	return signMessage(*signer.config, signatureName, signer, *parsedMessage, signer.fields)
}

func addPseudoHeaders(message *parsedMessage, config SignConfig) {
	if config.requestResponse.name != "" {
		message.components[*fromHeaderName("@request-response")] = []string{config.requestResponse.signature}
		// TODO and what about the name? (request-response)
	}
}

//
// VerifyRequest verifies a signed HTTP request. Returns true if verification was successful.
//
func VerifyRequest(signatureName string, verifier Verifier, req *http.Request) (verified bool, err error) {
	if req == nil {
		return false, fmt.Errorf("nil request")
	}
	if signatureName == "" {
		return false, fmt.Errorf("empty signature name")
	}
	parsedMessage, err := parseRequest(req)
	if err != nil {
		return false, err
	}
	return verifyMessage(*verifier.c, signatureName, verifier, *parsedMessage, verifier.f)
}

// RequestKeyID parses a signed request and returns the key ID used in the given signature.
func RequestKeyID(signatureName string, req *http.Request) (string, error) {
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
	return messageKeyID(signatureName, *parsedMessage)
}

// ResponseKeyID parses a signed response and returns the key ID used in the given signature.
func ResponseKeyID(signatureName string, res *http.Response) (string, error) {
	if res == nil {
		return "", fmt.Errorf("nil response")
	}
	if signatureName == "" {
		return "", fmt.Errorf("empty signature name")
	}
	parsedMessage, err := parseResponse(res)
	if err != nil {
		return "", err
	}
	return messageKeyID(signatureName, *parsedMessage)
}

func messageKeyID(signatureName string, parsedMessage parsedMessage) (string, error) {
	si, found := parsedMessage.components[*fromHeaderName("signature-input")]
	if !found {
		return "", fmt.Errorf("missing \"signature-input\" header")
	}
	signatureInput := si[0]
	psi, err := parseSignatureInput(signatureInput, signatureName)
	if err != nil {
		return "", err
	}
	keyIDParam, ok := psi.params["keyid"]
	if !ok {
		return "", fmt.Errorf("missing \"keyid\" parameter")
	}
	keyID, ok := keyIDParam.(string)
	if !ok {
		return "", fmt.Errorf("malformed \"keyid\" parameter")
	}
	return keyID, nil
}

//
// VerifyResponse verifies a signed HTTP response. Returns true if verification was successful.
//
func VerifyResponse(signatureName string, verifier Verifier, res *http.Response) (verified bool, err error) {
	if res == nil {
		return false, fmt.Errorf("nil response")
	}
	if signatureName == "" {
		return false, fmt.Errorf("empty signature name")
	}
	parsedMessage, err := parseResponse(res)
	if err != nil {
		return false, err
	}
	return verifyMessage(*verifier.c, signatureName, verifier, *parsedMessage, verifier.f)
}

func verifyMessage(config VerifyConfig, name string, verifier Verifier, message parsedMessage, fields Fields) (bool, error) {
	wsi, found := message.components[*fromHeaderName("signature-input")]
	if !found {
		return false, fmt.Errorf("missing \"signature-input\" header")
	}
	wantSignatureInput := wsi[0]
	ws, found := message.components[*fromHeaderName("signature")]
	if !found {
		return false, fmt.Errorf("missing \"signature\" header")
	}
	wantSignature := ws[0]
	delete(message.components, *fromHeaderName("signature-input"))
	delete(message.components, *fromHeaderName("signature"))
	err := validateFields(fields)
	if err != nil {
		return false, err
	}
	wantSigRaw, err := parseWantSignature(wantSignature, name)
	if err != nil {
		return false, err
	}
	psiSig, err := parseSignatureInput(wantSignatureInput, name)
	if err != nil {
		return false, err
	}
	if !(psiSig.fields.contains(&fields)) {
		return false, fmt.Errorf("actual signature does not cover all required fields")
	}
	err = applyVerificationPolicy(psiSig, config)
	if err != nil {
		return false, err
	}
	signatureInput, err := generateSignatureInput(message, psiSig.fields, psiSig.origSigParams)
	if err != nil {
		return false, err
	}
	verified, err := verifySignature(verifier, signatureInput, wantSigRaw)
	return verified, err
}

func applyVerificationPolicy(psi *psiSignature, config VerifyConfig) error {
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
	if config.verifyAlg && len(config.allowedAlgs) > 0 {
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

func verifySignature(verifier Verifier, input string, signature []byte) (bool, error) {
	verified, err := verifier.verify([]byte(input), signature)
	if !verified && err == nil {
		err = fmt.Errorf("bad signature, check key or signature value")
	}
	return verified, err
}

type psiSignature struct {
	signatureName string
	origSigParams string
	fields        Fields
	params        map[string]interface{}
}

type parsedSignatureInput struct {
	signatures []psiSignature
}

func parseSignatureInput(input string, name string) (*psiSignature, error) {
	psi := parsedSignatureInput{}
	sigs, err := httpsfv.UnmarshalDictionary([]string{input})
	if err != nil {
		return nil, fmt.Errorf("could not parse Signature-Input as list: %w", err)
	}
	for _, name := range sigs.Names() {
		memberForName, ok := sigs.Get(name)
		if !ok {
			return nil, fmt.Errorf("could not parse Signature-Input for signature %s", name)
		}
		fieldsList, ok := memberForName.(httpsfv.InnerList)
		osp, err := httpsfv.Marshal(fieldsList) // undocumented functionality
		if err != nil {
			return nil, fmt.Errorf("could not marshal inner list: %w", err)
		}
		if !ok {
			return nil, fmt.Errorf("Signature-Input: signature %s does not have an inner list", name)
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
		psi.signatures = append(psi.signatures, psiSignature{name, osp, f, params})
	}
	for _, s := range psi.signatures {
		if s.signatureName == name {
			return &s, nil
		}
	}
	return nil, fmt.Errorf("couldn't find signature input for \"%s\"", name)
}

func parseWantSignature(wantSignature string, name string) ([]byte, error) {
	parsedSignature, err := httpsfv.UnmarshalDictionary([]string{wantSignature})
	if err != nil {
		return nil, fmt.Errorf("could not parse signature field: %w", err)
	}
	wantSigValue, found := parsedSignature.Get(name)
	if !found {
		return nil, fmt.Errorf("could not find signature \"%s\"", name)
	}
	wantSigItem, ok := wantSigValue.(httpsfv.Item)
	if !ok {
		return nil, fmt.Errorf("unexpected value in signature field")
	}
	wantSigRaw, ok := wantSigItem.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("could not parse raw signature")
	}
	return wantSigRaw, nil
}
