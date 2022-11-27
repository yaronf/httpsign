package httpsign

import (
	"fmt"
	"github.com/dunglas/httpsfv"
	"strings"
)

// Fields is a list of fields to be signed or verified. To initialize, use Headers or for more complex
// cases, NewFields followed by a chain of Add... methods.
//
// Several component types may be marked as optional. When signing a message, an optional component (e.g., header)
// is signed if it exists in the message to be signed, otherwise it is not included in the signature input.
// Upon verification, a field marked optional must be included in the signed components if it appears at all.
// This allows for intuitive handling of application components (headers, query parameters) whose presence in
// the message depends on application logic. Please do NOT use this functionality for headers that may legitimately be
// added by a proxy, such as X-Forwarded-For.
type Fields struct {
	f []field
}

// The SFV representation of a field is name;flagName="flagValue"
// Note that this is a subset of SFV, we only support string-valued params, and only one param
// per field for now.
type field httpsfv.Item

func (f field) String() string {
	i := httpsfv.Item(f)
	s, err := httpsfv.Marshal(i)
	if err == nil {
		return s
	}
	return fmt.Sprintf("malformed field: %v", err)
}

func (f field) Equal(f2 field) bool {
	n1, err1 := f.name()
	n2, err2 := f2.name()
	if err1 == nil && err2 == nil && n1 == n2 {
		for _, p := range f.Params.Names() {
			v1, _ := f.Params.Get(p)
			v2, ok := f2.Params.Get(p)
			if !ok || v1 != v2 {
				return false
			}
		}
		for _, p := range f2.Params.Names() {
			v1, _ := f2.Params.Get(p)
			v2, ok := f.Params.Get(p)
			if !ok || v1 != v2 {
				return false
			}
		}
		return true
	}
	return false
}

// Headers is a simple way to generate a Fields list, where only simple header names and derived headers
// are needed.
func Headers(hs ...string) Fields {
	fs := NewFields()
	return *fs.AddHeaders(hs...)
}

// AddHeaders adds a list of simple or derived header names.
func (fs *Fields) AddHeaders(hs ...string) *Fields {
	for _, h := range hs {
		fs.f = append(fs.f, *fromHeaderName(h))
	}
	return fs
}

// NewFields returns an empty list of fields.
func NewFields() *Fields {
	fs := Fields{}
	return &fs
}

func (f field) name() (string, error) {
	i := httpsfv.Item(f)
	n, ok := i.Value.(string)
	if !ok {
		return "", fmt.Errorf("field has a non-string value")
	}
	return n, nil
}

func fromHeaderName(hdr string) *field {
	h := strings.ToLower(hdr)
	f := field(httpsfv.NewItem(h))
	return &f
}

func (f field) headerName() (bool, string) {
	_, ok1 := f.Params.Get("name")
	_, ok2 := f.Params.Get("key")
	if !ok1 && !ok2 {
		return true, f.Value.(string)
	}
	return false, ""
}

// AddHeader appends a bare header name, e.g. "cache-control".
func (fs *Fields) AddHeader(hdr string) *Fields {
	return fs.AddHeaderExt(hdr, false, false, false, false)
}

// AddHeaderExt appends a bare header name, e.g. "cache-control". See type documentation
// for details on optional parameters. The component can be marked as coming from an associated request.
func (fs *Fields) AddHeaderExt(hdr string, optional bool, binarySequence bool, associatedRequest bool, trailer bool) *Fields {
	f := fromHeaderName(hdr)
	f.markField(optional, associatedRequest, trailer)
	if binarySequence {
		f.markBinarySequence()
	}
	fs.f = append(fs.f, *f)
	return fs
}

func fromQueryParam(qp string) *field {
	q := strings.ToLower(qp)
	i := httpsfv.NewItem("@query-param")
	i.Params.Add("name", q)
	f := field(i)
	return &f
}

func (f field) queryParam() (bool, string) {
	name, err := f.name()
	if err == nil && name == "@query-param" {
		v, ok := httpsfv.Item(f).Params.Get("name")
		if ok {
			return true, v.(string)
		}
	}
	return false, ""
}

// AddQueryParam indicates a request for a specific query parameter to be signed.
func (fs *Fields) AddQueryParam(qp string) *Fields {
	return fs.AddQueryParamExt(qp, false, false, false)
}

// AddQueryParamExt indicates a request for a specific query parameter to be signed. See type documentation
// for details on optional parameters. The component can be marked as coming from an associated request.
func (fs *Fields) AddQueryParamExt(qp string, optional, associatedRequest, trailer bool) *Fields {
	f := fromQueryParam(qp)
	f.markField(optional, associatedRequest, trailer)
	fs.f = append(fs.f, *f)
	return fs
}

func fromDictHeader(hdr, key string) *field {
	h := strings.ToLower(hdr)
	i := httpsfv.NewItem(h)
	i.Params.Add("key", key)
	f := field(i)
	return &f
}

func (f field) dictHeader() (ok bool, hdr, key string) {
	v, ok := f.Params.Get("key")
	if ok {
		return true, f.Value.(string), v.(string)
	}
	return false, "", ""
}

// AddDictHeader indicates that out of a header structured as a dictionary, a specific key value is signed/verified.
func (fs *Fields) AddDictHeader(hdr, key string) *Fields {
	return fs.AddDictHeaderExt(hdr, key, false, false, false)
}

// AddDictHeaderExt indicates that out of a header structured as a dictionary, a specific key value is signed/verified.
// See type documentation
// for details on optional parameters. The component can be marked as coming from an associated request.
func (fs *Fields) AddDictHeaderExt(hdr, key string, optional, associatedRequest, trailer bool) *Fields {
	f := fromDictHeader(hdr, key)
	f.markField(optional, associatedRequest, trailer)
	fs.f = append(fs.f, *f)
	return fs
}

func fromStructuredField(hdr string) *field {
	h := strings.ToLower(hdr)
	i := httpsfv.NewItem(h)
	i.Params.Add("sf", true)
	f := field(i)
	return &f
}

func (f field) structuredField() bool {
	v, ok := f.Params.Get("sf")
	return ok && v.(bool)
}

func (f field) binarySequence() bool {
	v, ok := f.Params.Get("bs")
	return ok && v.(bool)
}

func (f field) trailer() bool {
	v, ok := f.Params.Get("tr")
	return ok && v.(bool)
}

func (f field) optional() bool {
	v, ok := f.Params.Get("optional")
	return ok && v.(bool)
}

func (f field) associatedRequest() bool {
	v, ok := f.Params.Get("req")
	return ok && v.(bool)
}

// AddStructuredField indicates that a header should be interpreted as a structured field, per RFC 8941.
func (fs *Fields) AddStructuredField(hdr string) *Fields {
	return fs.AddStructuredFieldExt(hdr, false, false, false)
}

// AddStructuredFieldExt indicates that a header should be interpreted as a structured field, per RFC 8941.
// See type documentation
// for details on optional parameters. The component can be marked as coming from an associated request.
func (fs *Fields) AddStructuredFieldExt(hdr string, optional, associatedRequest, trailer bool) *Fields {
	f := fromStructuredField(hdr)
	f.markField(optional, associatedRequest, trailer)
	fs.f = append(fs.f, *f)
	return fs
}

func (f field) toItem() httpsfv.Item {
	return httpsfv.Item(f)
}

func (f field) asSignatureBase() (string, error) {
	s, err := httpsfv.Marshal(f.toItem())
	return s, err
}

func (f field) markField(optional bool, associatedRequest bool, trailer bool) {
	if optional {
		f.markOptional()
	}
	if associatedRequest {
		f.markAssociatedRequest()
	}
	if trailer {
		f.markTrailer()
	}
}

func (f field) markFlag(name string) {
	if f.Params == nil {
		f.Params = httpsfv.NewParams()
	}
	f.Params.Add(name, true)
}

func (f field) markOptional() {
	f.markFlag("optional")
}

func (f field) markBinarySequence() {
	f.markFlag("bs")
}

func (f field) markAssociatedRequest() {
	f.markFlag("req")
}

func (f field) markTrailer() {
	f.markFlag("tr")
}

func (f field) unmarkOptional() {
	if f.Params == nil {
		f.Params = httpsfv.NewParams()
	}
	f.Params.Del("optional")
}

// Not a full deep copy, but good enough for mutating params
func (f field) copy() field {
	ff := field{
		Value: f.Value,
	}
	if f.Params == nil {
		ff.Params = nil
	} else {
		ff.Params = httpsfv.NewParams()
		for _, n := range f.Params.Names() {
			v, _ := f.Params.Get(n)
			ff.Params.Add(n, v)
		}
	}
	return ff
}

func (fs *Fields) asSignatureInput(p *httpsfv.Params) (string, error) {
	il := httpsfv.InnerList{
		Items:  []httpsfv.Item{},
		Params: httpsfv.NewParams(),
	}
	for _, f := range fs.f {
		il.Items = append(il.Items, f.toItem())
	}
	il.Params = p
	s, err := httpsfv.Marshal(il)
	return s, err
}

// contains verifies that all required fields are in the given list of fields (yes, this is O(n^2)).
func (fs *Fields) contains(requiredFields *Fields) bool {
outer:
	for _, f1 := range requiredFields.f {
		for _, f2 := range fs.f {
			if f1.Equal(f2) {
				continue outer
			}
		}
		return false
	}
	return true
}

func (fs *Fields) hasHeader(name string) bool {
	h := *fromHeaderName(name)
	for _, f := range fs.f {
		if f.Equal(h) {
			return true
		}
	}
	return false
}
