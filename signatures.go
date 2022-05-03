package httpsign

import (
	"fmt"
	"github.com/dunglas/httpsfv"
	"net/http"
	"strings"
	"time"
)

func signMessage(config SignConfig, signatureName string, signer Signer, parsedMessage parsedMessage,
	fields Fields) (signatureInput, signature, signatureBase string, err error) {
	filtered := filterOptionalFields(fields, parsedMessage)
	sigParams, err := generateSigParams(&config, signer.keyID, signer.alg, signer.foreignSigner, filtered)
	if err != nil {
		return "", "", "", err
	}
	signatureInput = fmt.Sprintf("%s=%s", signatureName, sigParams)
	signatureBase, err = generateSignatureBase(parsedMessage, filtered, sigParams)
	if err != nil {
		return "", "", "", err
	}
	signature, err = generateSignature(signatureName, signer, signatureBase)
	if err != nil {
		return "", "", "", err
	}
	return signatureInput, signature, signatureBase, nil
}

func filterOptionalFields(fields Fields, message parsedMessage) Fields {
	filtered := *NewFields()
	for _, f := range fields.f {
		if !f.isOptional() {
			filtered.f = append(filtered.f, f)
		} else {
			_, err := generateFieldValues(f, message)
			if err == nil { // value was found
				ff := f.copy()
				ff.unmarkOptional()
				filtered.f = append(filtered.f, ff)
			}
		}
	}
	return filtered
}

func generateSignature(name string, signer Signer, input string) (string, error) {
	raw, err := signer.sign([]byte(input))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s=%s", name, encodeBytes(raw)), nil
}

func encodeBytes(raw []byte) string {
	i := httpsfv.NewItem(raw)
	s, _ := httpsfv.Marshal(i)
	return s
}

func generateSignatureBase(message parsedMessage, fields Fields, params string) (string, error) {
	inp := ""
	for _, c := range fields.f {
		f, err := c.asSignatureBase()
		if err != nil {
			return "", fmt.Errorf("could not marshal %v", f)
		}
		fieldValues, err := generateFieldValues(c, message)
		if err != nil {
			return "", err
		}
		for _, v := range fieldValues {
			inp += fmt.Sprintf("%s: %s\n", f, v)
		}
	}
	inp += fmt.Sprintf("\"%s\": %s", "@signature-params", params)
	// log.Println("inp:", "\n"+inp)
	return inp, nil
}

func generateFieldValues(f field, message parsedMessage) ([]string, error) {
	ok, name := f.headerName()
	if ok {
		if strings.HasPrefix(name, "@") { // derived component
			vv, found := message.derived[name]
			if !found {
				return nil, fmt.Errorf("derived header %s not found", name)
			}
			return []string{vv}, nil
		}
		return message.getHeader(name, f.structuredField())
	}
	ok, name = f.queryParam()
	if ok {
		vals, found := message.qParams[name]
		if !found {
			return nil, fmt.Errorf("query parameter %s not found", name)
		}
		return vals, nil
	}
	ok, hdr, key := f.dictHeader()
	if ok {
		return message.getDictHeader(hdr, key)
	}
	return nil, fmt.Errorf("unrecognized field %s", f)
}

func (message *parsedMessage) getHeader(hdr string, structured bool) ([]string, error) {
	vv, found := message.headers[hdr] // normal header, cannot use "Values" on lowercased header name
	if !found {
		return nil, fmt.Errorf("header %s not found", hdr)
	}
	if !structured {
		return []string{foldFields(vv)}, nil
	}
	sfv, err := httpsfv.UnmarshalDictionary(vv)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal %s, possibly not a structured field: %w", hdr, err)
	}
	s, err := httpsfv.Marshal(sfv)
	if err != nil {
		return nil, fmt.Errorf("could not re-marshal %s", hdr)
	}
	return []string{s}, nil
}

func (message *parsedMessage) getDictHeader(hdr, member string) ([]string, error) {
	vals, found := message.headers[hdr]
	if !found {
		return nil, fmt.Errorf("dictionary header %s not found", hdr)
	}
	dict, err := httpsfv.UnmarshalDictionary(vals)
	if err != nil {
		return nil, fmt.Errorf("cannot parse dictionary for %s: %w", hdr, err)
	}
	v, found := dict.Get(member)
	if !found {
		return nil, fmt.Errorf("cannot find member %s of dictionary %s", member, hdr)
	}
	switch v.(type) {
	case httpsfv.Item:
		vv, err := httpsfv.Marshal(v.(httpsfv.Item))
		if err != nil {
			return nil, fmt.Errorf("malformed dictionry member %s: %v", hdr, err)
		}
		return []string{vv}, nil
	case httpsfv.InnerList:
		vv, err := httpsfv.Marshal(v.(httpsfv.InnerList))
		if err != nil {
			return nil, fmt.Errorf("malformed dictionry member %s: %v", hdr, err)
		}
		return []string{vv}, nil
	default:
		return nil, fmt.Errorf("unexpected dictionary value")
	}
}

func generateSigParams(config *SignConfig, keyID, alg string, foreignSigner interface{}, fields Fields) (string, error) {
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
		if foreignSigner != nil {
			return "", fmt.Errorf("cannot use the alg parameter with a JWS signer")
		}
		p.Add("alg", alg)
	}
	p.Add("keyid", keyID)
	return fields.asSignatureInput(p)
}

//
// SignRequest signs an HTTP request. Returns the Signature-Input and the Signature header values.
//
func SignRequest(signatureName string, signer Signer, req *http.Request) (signatureInput, signature string, err error) {
	signatureInput, signature, signatureBase, err := signRequestDebug(signatureName, signer, req)
	_ = signatureBase
	return
}

// Same as SignRequest, but also returns the raw signature input string
func signRequestDebug(signatureName string, signer Signer, req *http.Request) (signatureInput, signature, signatureBase string, err error) {
	if req == nil {
		return "", "", "", fmt.Errorf("nil request")
	}
	if signatureName == "" {
		return "", "", "", fmt.Errorf("empty signature name")
	}
	parsedMessage, err := parseRequest(req)
	if err != nil {
		return "", "", "", err
	}
	return signMessage(*signer.config, signatureName, signer, *parsedMessage, signer.fields)
}

//
// SignResponse signs an HTTP response. Returns the Signature-Input and the Signature header values.
//
func SignResponse(signatureName string, signer Signer, res *http.Response) (signatureInput, signature string, err error) {
	signatureInput, signature, signatureBase, err := signResponseDebug(signatureName, signer, res)
	_ = signatureBase
	return
}

func signResponseDebug(signatureName string, signer Signer, res *http.Response) (signatureInput, signature, signatureBase string, err error) {
	if res == nil {
		return "", "", "", fmt.Errorf("nil response")
	}
	if signatureName == "" {
		return "", "", "", fmt.Errorf("empty signature name")
	}
	parsedMessage, err := parseResponse(res)
	if err != nil {
		return "", "", "", err
	}
	return signMessage(*signer.config, signatureName, signer, *parsedMessage, signer.fields)
}

//
// VerifyRequest verifies a signed HTTP request. Returns an error if verification failed for any reason, otherwise nil.
func VerifyRequest(signatureName string, verifier Verifier, req *http.Request) error {
	_, err := verifyRequestDebug(signatureName, verifier, req)
	return err
}

func verifyRequestDebug(signatureName string, verifier Verifier, req *http.Request) (signatureBase string, err error) {
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
	return verifyMessage(*verifier.config, signatureName, verifier, *parsedMessage, verifier.fields)
}

// MessageDetails aggregates the details of a signed message
type MessageDetails struct {
	KeyID, Alg string
	Fields     Fields
}

// RequestDetails parses a signed request and returns the key ID and optionally the algorithm used in the given signature.
func RequestDetails(signatureName string, req *http.Request) (details *MessageDetails, err error) {
	if req == nil {
		return nil, fmt.Errorf("nil request")
	}
	if signatureName == "" {
		return nil, fmt.Errorf("empty signature name")
	}
	parsedMessage, err := parseRequest(req)
	if err != nil {
		return nil, err
	}
	return messageDetails(signatureName, *parsedMessage)
}

// ResponseDetails parses a signed response and returns the key ID and optionally the algorithm used in the given signature.
func ResponseDetails(signatureName string, res *http.Response) (details *MessageDetails, err error) {
	if res == nil {
		return nil, fmt.Errorf("nil response")
	}
	if signatureName == "" {
		return nil, fmt.Errorf("empty signature name")
	}
	parsedMessage, err := parseResponse(res)
	if err != nil {
		return nil, err
	}
	return messageDetails(signatureName, *parsedMessage)
}

func messageDetails(signatureName string, parsedMessage parsedMessage) (details *MessageDetails, err error) {
	si, err := parsedMessage.getDictHeader("signature-input", signatureName)
	if err != nil {
		return nil, fmt.Errorf("missing \"Signature-Input\" header, or cannot find \"%s\": %w", signatureName, err)
	}
	if len(si) > 1 {
		return nil, fmt.Errorf("more than one \"Signature-Input\" for %s", signatureName)
	}
	signatureInput := si[0]
	psi, err := parseSignatureInput(signatureInput, signatureName)
	if err != nil {
		return
	}
	keyIDParam, ok := psi.params["keyid"]
	if !ok {
		return nil, fmt.Errorf("missing \"keyid\" parameter")
	}
	keyID, ok := keyIDParam.(string)
	if !ok {
		return nil, fmt.Errorf("malformed \"keyid\" parameter")
	}
	var alg string
	algParam, ok := psi.params["alg"] // "alg" is optional
	if ok {
		alg, ok = algParam.(string)
		if !ok {
			return nil, fmt.Errorf("malformed \"alg\" parameter")
		}
	}
	return &MessageDetails{
		KeyID:  keyID,
		Alg:    alg,
		Fields: psi.fields,
	}, nil
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
	_, err = verifyMessage(*verifier.config, signatureName, verifier, *parsedMessage, verifier.fields)
	return err
}

func verifyMessage(config VerifyConfig, name string, verifier Verifier, message parsedMessage, fields Fields) (string, error) {
	wsi, err := message.getDictHeader("signature-input", name)
	if err != nil {
		return "", fmt.Errorf("missing \"signature-input\" header, or cannot find signature \"%s\": %w", name, err)
	}
	if len(wsi) > 1 {
		return "", fmt.Errorf("multiple \"signature-header\" values for %s", name)
	}
	wantSignatureInput := wsi[0]
	ws, err := message.getDictHeader("signature", name)
	if err != nil {
		return "", fmt.Errorf("missing \"signature\" header")
	}
	if len(ws) > 1 {
		return "", fmt.Errorf("multiple \"signature\" values for %s", name)
	}
	wantSignature := ws[0]
	wantSigRaw, err := parseWantSignature(wantSignature)
	if err != nil {
		return "", err
	}
	psiSig, err := parseSignatureInput(wantSignatureInput, name)
	if err != nil {
		return "", err
	}
	filtered := filterOptionalFields(fields, message)
	if !(psiSig.fields.contains(&filtered)) {
		return "", fmt.Errorf("actual signature does not cover all required fields")
	}
	err = applyVerificationPolicy(verifier, message, psiSig, config)
	if err != nil {
		return "", err
	}
	signatureBase, err := generateSignatureBase(message, psiSig.fields, psiSig.origSigParams)
	if err != nil {
		return "", err
	}
	return signatureBase, verifySignature(verifier, signatureBase, wantSigRaw)
}

func applyVerificationPolicy(verifier Verifier, message parsedMessage, psi *psiSignature, config VerifyConfig) error {
	err := applyPolicyCreated(psi, message, config)
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
	err4 := applyPolicyOthers(verifier, psi, config)
	if err4 != nil {
		return err4
	}
	return nil
}

func applyPolicyOthers(verifier Verifier, psi *psiSignature, config VerifyConfig) error {
	if config.verifyKeyID {
		keyidParam, ok := psi.params["keyid"]
		if ok {
			keyID, ok := keyidParam.(string)
			if !ok {
				return fmt.Errorf("malformed \"keyid\" parameter")
			}
			if keyID != verifier.keyID {
				return fmt.Errorf("wrong keyid \"%s\"", keyID)
			}
		}
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

func applyPolicyCreated(psi *psiSignature, message parsedMessage, config VerifyConfig) error {
	if !config.verifyCreated && config.dateWithin != 0 {
		return fmt.Errorf("cannot verify Date header if Created parameter is not verified")
	}
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

		if config.dateWithin != 0 {
			dateHdr, ok := message.headers["date"]
			if ok {
				if len(dateHdr) > 1 {
					return fmt.Errorf("multiple Date headers")
				}
				date, err := http.ParseTime(dateHdr[0])
				if err != nil {
					return fmt.Errorf("cannot parse Date header: %w", err)
				}
				if createdTime.After(date.Add(config.dateWithin)) ||
					date.After(createdTime.Add(config.dateWithin)) {
					return fmt.Errorf("the Date header is not within time window of Created parameter")
				}
			}
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
		f.f = append(f.f, field(ff))
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
