// Package httpsign signs HTTP requests and responses as defined in draft-ietf-httpbis-message-signatures.
// See https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-07.html.
package httpsign

import (
	"encoding/base64"
	"fmt"
	"github.com/dunglas/httpsfv"
	"log"
	"net/http"
	"strings"
	"time"
)

func signMessage(config Config, signatureName string, signer Signer, parsedMessage parsedMessage,
	fields []string) (sigInputHeader string, signature string, err error) {
	err = validateFields(fields)
	if err != nil {
		return "", "", err
	}
	sigParams := generateSigParams(config, signer.keyId, signer.alg, fields)
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

func validateFields(fields []string) error {
	for _, f := range fields {
		if f != strings.ToLower(f) {
			return fmt.Errorf("field is not lowercase: %s", f)
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
	return fmt.Sprintf("%s=:%s:", name, base64.StdEncoding.EncodeToString(raw)), nil // TODO
}

func generateSignatureInput(message parsedMessage, fields []string, params string) (string, error) {
	mf, err := matchFields(message.components, fields)
	if err != nil {
		return "", err
	}
	inp := ""
	for _, c := range mf {
		inp += fmt.Sprintf("\"%s\": %s\n", c.name, c.value)
	}
	inp += fmt.Sprintf("\"%s\": %s", "@signature-params", params)
	log.Println("Sig input:")
	log.Println(inp)
	return inp, nil
}

func generateSigParams(config Config, keyId, alg string, fields []string) string {
	var sp string
	if len(fields) == 0 {
		sp = "();"
	} else {
		sp = "(" + fmt.Sprintf("\"%s\"", fields[0])
		for i := 1; i < len(fields); i++ {
			sp += fmt.Sprintf(" \"%s\"", fields[i])
		}
		sp += ");"
	}
	var createdTime int64
	if config.fakeCreated != 0 {
		createdTime = config.fakeCreated
	} else {
		createdTime = time.Now().Unix()
	}
	if config.signCreated {
		sp += fmt.Sprintf("created=%d;", createdTime)
	}
	if config.signAlg {
		sp += fmt.Sprintf("alg=\"%s\";", alg)
	}
	sp += fmt.Sprintf("keyid=\"%s\"", keyId)
	return sp
}

//
// SignRequest signs an HTTP request. You must supply a Signer structure, a Config configuration,
// and a list of fields to be signed (all lowercase). Returns the Signature-Input and the Signature header values.
//
func SignRequest(config Config, signatureName string, signer Signer, req *http.Request, fields []string) (string, string, error) {
	parsedMessage, err := parseRequest(req)
	if err != nil {
		return "", "", err
	}
	return signMessage(config, signatureName, signer, *parsedMessage, fields)
}

//
// SignResponse signs an HTTP response. You must supply a Signer structure, a Config configuration,
// and a list of fields to be signed (all lowercase). Returns the Signature-Input and the Signature header values.
//
func SignResponse(config Config, signatureName string, signer Signer, res *http.Response, fields []string) (string, string, error) {
	parsedMessage, err := parseResponse(res)
	if err != nil {
		return "", "", nil
	}
	return signMessage(config, signatureName, signer, *parsedMessage, fields)
}

//
// VerifyRequest verifies a signed HTTP request. You must supply a Verifier structure,
// and a list of fields that are expected to be signed (all lowercase). Returns true if verification was successful.
//
func VerifyRequest(signatureName string, verifier Verifier, req *http.Request, fields []string) (bool, error) {
	parsedMessage, err := parseRequest(req)
	if err != nil {
		return false, err
	}
	return verifyMessage(signatureName, verifier, *parsedMessage, fields)
}

func verifyMessage(name string, verifier Verifier, message parsedMessage, fields []string) (bool, error) {
	wantSignatureInput, found := message.components["signature-input"]
	if !found {
		return false, fmt.Errorf("missing \"signature-input\" header")
	}
	wantSignature, found := message.components["signature"]
	if !found {
		return false, fmt.Errorf("missing \"signature\" header")
	}
	delete(message.components, "signature-input")
	delete(message.components, "signature")
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
	if !compareFields(psiSig.fields, fields) {
		return false, fmt.Errorf("actual signature does not cover all required fields")
	}
	// TODO: apply policy, e.g. are some sig parameters required
	signatureInput, err := generateSignatureInput(message, psiSig.fields, psiSig.origSigParams)
	if err != nil {
		return false, err
	}
	verified, err := verifySignature(name, verifier, signatureInput, wantSigRaw)
	return verified, err
}

func verifySignature(name string, verifier Verifier, input string, signature []byte) (bool, error) {
	return verifier.verify([]byte(input), signature)
}

//  compareFields verify that all required fields are in seeFields (yes, this is O(n^2))
func compareFields(seenFields []string, requiredFields []string) bool {
outer:
	for _, f1 := range requiredFields {
		for _, f2 := range seenFields {
			if f1 == f2 {
				continue outer
			}
		}
		return false
	}
	return true
}

type psiSignature struct {
	signatureName string
	origSigParams string
	fields        []string
	params        map[string]interface{}
}

type parsedSignatureInput struct {
	signatures []psiSignature
}

func parseSignatureInput(input string, name string) (*psiSignature, error) {
	psi := parsedSignatureInput{}
	sigs, err := httpsfv.UnmarshalDictionary([]string{input})
	if err != nil {
		return nil, fmt.Errorf("could not parse Signature-Input as list")
	}
	for _, name := range sigs.Names() {
		memberForName, ok := sigs.Get(name)
		if !ok {
			return nil, fmt.Errorf("could not parse Signature-Input for signature %s", name)
		}
		fieldsList, ok := memberForName.(httpsfv.InnerList)
		osp, err := httpsfv.Marshal(fieldsList) // undocumented functionality
		if err != nil {
			return nil, fmt.Errorf("could not marshal inner list")
		}
		if !ok {
			return nil, fmt.Errorf("Signature-Input: signature %s does not have an inner list", name)
		}
		var f []string
		for _, ff := range fieldsList.Items {
			fname, ok := ff.Value.(string)
			if !ok {
				return nil, fmt.Errorf("Signature-Input: value is not a string")
			}
			f = append(f, fname)
		}
		params := map[string]interface{}{}
		ps := memberForName.(httpsfv.InnerList).Params // assertion already checked
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
	return nil, fmt.Errorf("couldn't find signature input for %s", name)
}

func parseWantSignature(wantSignature string, name string) ([]byte, error) {
	parsedSignature, err := httpsfv.UnmarshalDictionary([]string{wantSignature})
	if err != nil {
		return nil, fmt.Errorf("could not parse signature field")
	}
	wantSigValue, found := parsedSignature.Get(name)
	if !found {
		return nil, fmt.Errorf("could not find signature: %s", name)
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
