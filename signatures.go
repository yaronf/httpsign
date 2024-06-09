package httpsign

import (
	"errors"
	"fmt"
	"github.com/dunglas/httpsfv"
	"io"
	"net/http"
	"strings"
	"time"
)

func signMessage(config SignConfig, signatureName string, signer Signer, parsedMessage, parsedAssocMessage *parsedMessage,
	fields Fields) (signatureInput, signature, signatureBase string, err error) {
	filtered := filterOptionalFields(fields, parsedMessage, parsedAssocMessage)
	err = applyFieldConstraints(fields)
	if err != nil {
		return "", "", "", err
	}
	sigParams, err := generateSigParams(&config, signer.alg, signer.foreignSigner, filtered)
	if err != nil {
		return "", "", "", err
	}
	signatureInput = fmt.Sprintf("%s=%s", signatureName, sigParams)
	signatureBase, err = generateSignatureBase(parsedMessage, parsedAssocMessage, filtered, sigParams)
	if err != nil {
		return "", "", "", err
	}
	signature, err = generateSignature(signatureName, signer, signatureBase)
	if err != nil {
		return "", "", "", err
	}
	return signatureInput, signature, signatureBase, nil
}

func applyFieldConstraints(fields Fields) error {
	binaryFields := map[string]bool{"set-cookie": true}
	for _, f := range fields.f {
		name, err := f.name()
		if err != nil {
			return fmt.Errorf("malformed field")
		}
		if binaryFields[name] && !f.binarySequence() {
			return fmt.Errorf("field %s should be a binary sequence", name)
		}
	}
	return nil
}

func filterOptionalFields(fields Fields, message, assocMessage *parsedMessage) Fields {
	filtered := *NewFields()
	for _, f := range fields.f {
		if !f.optional() {
			filtered.f = append(filtered.f, f)
		} else {
			if !f.associatedRequest() {
				_, err := generateFieldValues(f, *message)
				if err == nil { // value was found
					ff := f.copy()
					ff.unmarkOptional()
					filtered.f = append(filtered.f, ff)
				}
			} else if assocMessage != nil {
				_, err := generateFieldValues(f, *assocMessage)
				if err == nil { // value was found
					ff := f.copy()
					ff.unmarkOptional()
					filtered.f = append(filtered.f, ff)
				}
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

func generateSignatureBase(message, assocMessage *parsedMessage, fields Fields, params string) (string, error) {
	inp := ""
	for _, c := range fields.f {
		f, err := c.asSignatureBase()
		if err != nil {
			return "", fmt.Errorf("could not marshal %v", f)
		}
		var fieldValues []string
		if !c.associatedRequest() {
			fieldValues, err = generateFieldValues(c, *message)
			if err != nil {
				return "", err
			}
		} else {
			if assocMessage == nil {
				return "", fmt.Errorf("required field %s but no associated message", c.String())
			}
			fieldValues, err = generateFieldValues(c, *assocMessage)
			if err != nil {
				return "", err
			}
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
		return message.getHeader(name, f.structuredField(), f.binarySequence(), f.trailer())
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
		return message.getDictHeader(hdr, f.trailer(), key)
	}
	return nil, fmt.Errorf("unrecognized field %s", f)
}

func (message *parsedMessage) getHeader(hdr string, structured, binary, trailer bool) ([]string, error) {
	if structured && binary {
		return nil, fmt.Errorf("the \"bs\" and \"sf\" flags are incompatible")
	}
	vv, err := message.getRawHeader(hdr, trailer)
	if err != nil {
		return nil, err
	}
	if binary {
		s := encodeBytes([]byte(vv[0]))
		for _, v := range vv[1:] {
			s += ", " + encodeBytes([]byte(v))
		}
		return []string{s}, nil
	} else if structured {
		sfv, err := httpsfv.UnmarshalDictionary(vv)
		if err != nil {
			return nil, fmt.Errorf("could not unmarshal %s, possibly not a structured field: %w", hdr, err)
		}
		s, err := httpsfv.Marshal(sfv)
		if err != nil {
			return nil, fmt.Errorf("could not re-marshal %s", hdr)
		}
		return []string{s}, nil
	} else {
		return []string{foldFields(vv)}, nil
	}
}

func (message *parsedMessage) getRawHeader(hdr string, trailer bool) ([]string, error) {
	var vv []string
	var found bool
	if !trailer {
		vv, found = message.headers[hdr] // normal header, cannot use "Values" on lowercased header name
	} else {
		vv, found = message.trailers[hdr]
	}
	if !found {
		return nil, fmt.Errorf("header %s not found", hdr)
	}
	return vv, nil
}

func (message *parsedMessage) getDictHeader(hdr string, trailer bool, member string) ([]string, error) {
	vals, err := message.getRawHeader(hdr, trailer)
	if err != nil {
		return nil, err
	}
	return lookupMember(hdr, vals, member)
}

var errHeaderNotFound = fmt.Errorf("header not found")

// Note: no support for Signature headers that straddle header and trailer (which is probably illegal HTTP)
func getDictHeader(headers http.Header, hdr string, member string) ([]string, error) {
	if headers == nil {
		return nil, errHeaderNotFound
	}
	normalized := normalizeHeaderNames(headers)
	vals, found := normalized[hdr]
	if !found {
		return nil, errHeaderNotFound
	}
	return lookupMember(hdr, vals, member)
}

func lookupMember(hdr string, vals []string, member string) ([]string, error) {
	dict, err := httpsfv.UnmarshalDictionary(vals)
	if err != nil {
		return nil, fmt.Errorf("cannot parse dictionary for %s: %w", hdr, err)
	}
	v, found := dict.Get(member)
	if !found {
		return nil, fmt.Errorf("cannot find member %s of dictionary %s", member, hdr)
	}
	switch v := v.(type) { // fixed per Staticcheck S1034
	case httpsfv.Item:
		vv, err := httpsfv.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("malformed dictionry member %s: %v", hdr, err)
		}
		return []string{vv}, nil
	case httpsfv.InnerList:
		vv, err := httpsfv.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("malformed dictionry member %s: %v", hdr, err)
		}
		return []string{vv}, nil
	default:
		return nil, fmt.Errorf("unexpected dictionary value")
	}
}

// quotedString returns s ready to be quoted per quoted-string in RFC 7230.
// Credit: https://stackoverflow.com/a/68154993/955670
func quotedString(s string) (string, error) {
	var result strings.Builder
	result.Grow(len(s)) // optimize for case where no \ are added.

	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b < ' ' && b != '\t') || b == 0x7f {
			return "", fmt.Errorf("invalid byte %0x", b)
		}
		if b == '\\' || b == '"' {
			result.WriteByte('\\')
		}
		result.WriteByte(b)
	}
	return result.String(), nil
}

func generateSigParams(config *SignConfig, alg string, foreignSigner interface{}, fields Fields) (string, error) {
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
		qNonce, err := quotedString(config.nonce)
		if err != nil {
			return "", fmt.Errorf("malformed nonce: %w", err)
		}
		p.Add("nonce", qNonce)
	}
	if config.signAlg {
		if foreignSigner != nil {
			return "", fmt.Errorf("cannot use the alg parameter with a JWS signer")
		}
		p.Add("alg", alg)
	}
	if config.tag != "" {
		qContext, err := quotedString(config.tag)
		if err != nil {
			return "", fmt.Errorf("malformed tag: %w", err)
		}
		p.Add("tag", qContext)
	}
	if config.keyID != nil {
		if *config.keyID == "" {
			return "", fmt.Errorf("key ID must not be an empty string")
		}
		p.Add("keyid", *config.keyID)
	}
	return fields.asSignatureInput(p)
}

// SignRequest signs an HTTP request. Returns the Signature-Input and the Signature header values.
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
	withTrailers := signer.fields.hasTrailerFields(false)
	parsedMessage, err := parseRequest(req, withTrailers)
	if err != nil {
		return "", "", "", err
	}
	return signMessage(*signer.config, signatureName, signer, parsedMessage, nil, signer.fields)
}

// SignResponse signs an HTTP response. Returns the Signature-Input and the Signature header values.
// The req parameter (optional) is the associated request.
func SignResponse(signatureName string, signer Signer, res *http.Response, req *http.Request) (signatureInput, signature string, err error) {
	signatureInput, signature, signatureBase, err := signResponseDebug(signatureName, signer, res, req)
	_ = signatureBase
	return
}

func signResponseDebug(signatureName string, signer Signer, res *http.Response, req *http.Request) (signatureInput, signature, signatureBase string, err error) {
	if res == nil {
		return "", "", "", fmt.Errorf("nil response")
	}
	if signatureName == "" {
		return "", "", "", fmt.Errorf("empty signature name")
	}
	resWithTrailers := signer.fields.hasTrailerFields(false)
	parsedRes, err := parseResponse(res, resWithTrailers)
	if err != nil {
		return "", "", "", err
	}
	reqWithTrailers := signer.fields.hasTrailerFields(true)
	parsedReq, err := parseRequest(req, reqWithTrailers)
	if err != nil {
		return "", "", "", err
	}
	return signMessage(*signer.config, signatureName, signer, parsedRes, parsedReq, signer.fields)
}

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
	withTrailers, wantSigRaw, psiSig, err := extractSignatureFields(signatureName, &verifier, req.Header, req.Trailer, &req.Body)
	if err != nil {
		return "", err
	}
	parsedMessage, err := parseRequest(req, withTrailers)
	if err != nil {
		return "", err
	}
	return verifyMessage(*verifier.config, verifier, parsedMessage, nil, verifier.fields,
		wantSigRaw, psiSig)
}

// MessageDetails aggregates the details of a signed message, for a given signature
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
	_, _, psiSig, err := extractSignatureFields(signatureName, nil, req.Header, req.Trailer, &req.Body)
	if err != nil {
		return nil, fmt.Errorf("could not extract signature: %w", err)
	}
	return signatureDetails(psiSig)
}

// ResponseDetails parses a signed response and returns the key ID and optionally the algorithm used in the given signature.
func ResponseDetails(signatureName string, res *http.Response) (details *MessageDetails, err error) {
	if res == nil {
		return nil, fmt.Errorf("nil response")
	}
	if signatureName == "" {
		return nil, fmt.Errorf("empty signature name")
	}
	_, _, psiSig, err := extractSignatureFields(signatureName, nil, res.Header, res.Trailer, &res.Body)
	if err != nil {
		return nil, fmt.Errorf("could not extract signature: %w", err)
	}
	return signatureDetails(psiSig)
}

// RequestSignatureNames returns the list of signature names present in a request (empty list if none found).
// This is useful
// if signature names are not known in advance. Set withTrailers only if the entire message
// needs to be read because signature headers appear in trailers. Trailers are very uncommon
// and come at a performance cost.
func RequestSignatureNames(req *http.Request, withTrailers bool) ([]string, error) {
	parsedMessage, err := parseRequest(req, withTrailers)
	if err != nil {
		return nil, fmt.Errorf("could not parse request: %w", err)
	}
	return messageSignatureNames(parsedMessage, withTrailers)
}

// ResponseSignatureNames returns the list of signature names present in a response (empty list if none found).
// This is useful
// if signature names are not known in advance. Set withTrailers only if the entire message
// needs to be read because signature headers appear in trailers. Trailers are very uncommon
// and come at a performance cost.
func ResponseSignatureNames(res *http.Response, withTrailers bool) ([]string, error) {
	parsedMessage, err := parseResponse(res, withTrailers)
	if err != nil {
		return nil, fmt.Errorf("could not parse response: %w", err)
	}
	return messageSignatureNames(parsedMessage, withTrailers)
}

func messageSignatureNames(parsedMessage *parsedMessage, withTrailers bool) ([]string, error) {
	//lint:ignore SA1008 the Header type expects canonicalized names, tough
	signatureField := parsedMessage.headers["signature"]
	dict, err := httpsfv.UnmarshalDictionary(signatureField)
	if err != nil {
		return nil, fmt.Errorf("cannot parse signature field: %w", err)
	}
	names := dict.Names()
	if withTrailers {
		//lint:ignore SA1008 the Header type expects canonicalized names, tough
		signatureField := parsedMessage.trailers["signature"]
		dict, err := httpsfv.UnmarshalDictionary(signatureField)
		if err != nil {
			return nil, fmt.Errorf("cannot parse signature field in trailers: %w", err)
		}
		names = append(names, dict.Names()...)
	}
	return names, nil
}

func signatureDetails(signature *psiSignature) (details *MessageDetails, err error) {
	keyIDParam, ok := signature.params["keyid"]
	if !ok {
		return nil, fmt.Errorf("missing \"keyid\" parameter")
	}
	keyID, ok := keyIDParam.(string)
	if !ok {
		return nil, fmt.Errorf("malformed \"keyid\" parameter")
	}
	var alg string
	algParam, ok := signature.params["alg"] // "alg" is optional
	if ok {
		alg, ok = algParam.(string)
		if !ok {
			return nil, fmt.Errorf("malformed \"alg\" parameter")
		}
	}
	return &MessageDetails{
		KeyID:  keyID,
		Alg:    alg,
		Fields: signature.fields,
	}, nil
}

// VerifyResponse verifies a signed HTTP response. Returns an error if verification failed for any reason, otherwise nil.
func VerifyResponse(signatureName string, verifier Verifier, res *http.Response, req *http.Request) error {
	_, err := verifyResponseDebug(signatureName, verifier, res, req)
	return err
}

func verifyResponseDebug(signatureName string, verifier Verifier, res *http.Response, req *http.Request) (signatureBase string, err error) {
	if res == nil {
		return "", fmt.Errorf("nil response")
	}
	if signatureName == "" {
		return "", fmt.Errorf("empty signature name")
	}
	resWithTrailers, wantSigRaw, psiSig, err := extractSignatureFields(signatureName, &verifier, res.Header, res.Trailer, &res.Body)
	if err != nil {
		return "", err
	}
	parsedMessage, err := parseResponse(res, resWithTrailers)
	if err != nil {
		return "", err
	}
	// Read the associated request with trailers if the verifier requests its trailers, or there are signed trailer
	// covered in the signature
	reqWithTrailers := verifier.fields.hasTrailerFields(true) || psiSig.fields.hasTrailerFields(true)
	parsedAssocMessage, err := parseRequest(req, reqWithTrailers)
	if err != nil {
		return "", err
	}
	signatureBase, err = verifyMessage(*verifier.config, verifier, parsedMessage, parsedAssocMessage,
		verifier.fields, wantSigRaw, psiSig)
	return signatureBase, err
}

func extractSignatureFields(signatureName string, verifier *Verifier,
	headers http.Header, trailers http.Header, body *io.ReadCloser) (bool, []byte, *psiSignature, error) {
	/*
		Parse trailers if:
		- A trailer field needs to be verified
		- The Signature or Signature-Input headers are not found
		- A trailer field was covered in the signature
	*/
	var needTrailers = false
	if verifier != nil {
		needTrailers = needTrailers || verifier.fields.hasTrailerFields(false)
	}
	sigRaw, parsedSigInput, err := signatureFieldsFromHeaders(headers, signatureName)
	if err != nil {
		if errors.Is(err, errHeaderNotFound) {
			_, err := duplicateBody(body)
			if err != nil {
				return false, nil, nil, err
			}
			sigRaw, parsedSigInput, err = signatureFieldsFromHeaders(trailers, signatureName)
			if err != nil {
				return false, nil, nil, err
			}
			needTrailers = true
		} else {
			return false, nil, nil, err
		}
	}
	needTrailers = needTrailers || parsedSigInput.fields.hasTrailerFields(false)
	return needTrailers, sigRaw, parsedSigInput, nil
}

func verifyMessage(config VerifyConfig, verifier Verifier, message, assocMessage *parsedMessage,
	fields Fields, wantSigRaw []byte, psiSig *psiSignature) (string, error) {
	filtered := filterOptionalFields(fields, message, assocMessage)
	if !(psiSig.fields.contains(&filtered)) {
		return "", fmt.Errorf("actual signature does not cover all required fields")
	}
	err := applyVerificationPolicy(*message, psiSig, config)
	if err != nil {
		return "", err
	}
	signatureBase, err := generateSignatureBase(message, assocMessage, psiSig.fields, psiSig.origSigParams)
	if err != nil {
		return "", err
	}
	return signatureBase, verifySignature(verifier, signatureBase, wantSigRaw)
}

func signatureFieldsFromHeaders(header http.Header, name string) ([]byte, *psiSignature, error) {
	wsi, err := getDictHeader(header, "signature-input", name)
	if err != nil {
		return nil, nil, err
	}
	if len(wsi) > 1 {
		return nil, nil, fmt.Errorf("multiple \"signature-header\" values for %s", name)
	}
	wantSignatureInput := wsi[0]
	ws, err := getDictHeader(header, "signature", name)
	if err != nil {
		return nil, nil, err
	}
	if len(ws) > 1 {
		return nil, nil, fmt.Errorf("multiple \"signature\" values for %s", name)
	}
	wantSignature := ws[0]
	wantSigRaw, err := parseWantSignature(wantSignature)
	if err != nil {
		return nil, nil, err
	}
	psiSig, err := parseSignatureInput(wantSignatureInput, name)
	if err != nil {
		return nil, nil, err
	}
	return wantSigRaw, psiSig, nil
}

func applyVerificationPolicy(message parsedMessage, psi *psiSignature, config VerifyConfig) error {
	err := applyPolicyCreated(psi, message, config)
	if err != nil {
		return err
	}
	err2 := applyPolicyAlgs(psi, config)
	if err2 != nil {
		return err2
	}
	err3 := applyPolicyContexts(psi, config)
	if err3 != nil {
		return err3
	}
	err4 := applyPolicyExpired(psi, config)
	if err4 != nil {
		return err4
	}
	err5 := applyPolicyOthers(psi, config)
	if err5 != nil {
		return err5
	}
	return nil
}

func applyPolicyOthers(psi *psiSignature, config VerifyConfig) error {
	if config.keyID != nil {
		keyidParam, ok := psi.params["keyid"]
		if ok {
			keyID, ok := keyidParam.(string)
			if !ok {
				return fmt.Errorf("malformed \"keyid\" parameter")
			}
			if keyID != *config.keyID {
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

func applyPolicyContexts(psi *psiSignature, config VerifyConfig) error {
	if len(config.allowedTags) > 0 {
		ctxParam, ok := psi.params["tag"]
		if !ok {
			return fmt.Errorf("missing \"tag\" parameter")
		}
		ctx, ok := ctxParam.(string)
		if !ok {
			return fmt.Errorf("malformed \"tag\" parameter")
		}
		var ctxFound = false
		for _, c := range config.allowedTags {
			if c == ctx {
				ctxFound = true
			}
		}
		if !ctxFound {
			return fmt.Errorf("\"tag\" parameter not allowed by policy")
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
			dateHdr, ok := message.headers["Date"]
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
