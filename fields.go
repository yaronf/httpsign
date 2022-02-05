package httpsign

import (
	"fmt"
	"github.com/dunglas/httpsfv"
	"strings"
)

// Fields is a list of fields to be signed. To initialize, use Headers or for more complex
// cases, NewFields followed by a chain of Add... methods.
type Fields struct {
	f []field
}

// The SFV representation of a field is name;flagName="flagValue"
// Note that this is a subset of SFV, we only support string-valued params, and only one param
// per field for now.
type field struct {
	name                string
	flagName, flagValue string
}

func (f *field) String() string {
	if f.flagName == "" {
		return f.name
	}
	return fmt.Sprintf("%s;%s=\"%s\"", f.name, f.flagName, f.flagValue)
}

// Headers is a simple way to generate a Fields list, where only simple header names and derived headers
// are needed.
func Headers(hs ...string) Fields {
	fs := NewFields()
	return *fs.AddHeaders(hs...)
}

// AddHeaders adds a list of simple or derived header names
func (fs *Fields) AddHeaders(hs ...string) *Fields {
	for _, h := range hs {
		fs.f = append(fs.f, *fromHeaderName(h))
	}
	return fs
}

// NewFields return an empty list of fields
func NewFields() *Fields {
	fs := Fields{}
	return &fs
}

func fromHeaderName(hdr string) *field {
	h := strings.ToLower(hdr)
	f := field{h, "", ""}
	return &f
}

// AddHeader appends a bare header name, e.g. "cache-control"
func (fs *Fields) AddHeader(hdr string) *Fields {
	f := fromHeaderName(hdr)
	fs.f = append(fs.f, *f)
	return fs
}

func fromQueryParam(qp string) *field {
	q := strings.ToLower(qp)
	f := field{"@query-params", "name", q}
	return &f
}

// AddQueryParam indicates a request for a specific query parameter to be signed
func (fs *Fields) AddQueryParam(qp string) *Fields {
	f := fromQueryParam(qp)
	fs.f = append(fs.f, *f)
	return fs
}

func fromDictHeader(hdr, key string) *field {
	h := strings.ToLower(hdr)
	f := field{h, "key", key}
	return &f
}

// AddDictHeader indicates that out of a header structured as a dictionary, a specific key value is signed/verified
func (fs *Fields) AddDictHeader(hdr, key string) *Fields {
	f := fromDictHeader(hdr, key)
	fs.f = append(fs.f, *f)
	return fs
}

func fromStructuredField(hdr string) *field {
	h := strings.ToLower(hdr)
	f := field{h, "sf", ""}
	return &f
}

// AddStructuredField indicates that a header should be interpreted as a structured field, per RFC 8941
func (fs *Fields) AddStructuredField(hdr string) *Fields {
	f := fromStructuredField(hdr)
	fs.f = append(fs.f, *f)
	return fs
}

func (f field) toItem() httpsfv.Item {
	p := httpsfv.NewParams()
	if f.flagName == "sf" { //special case
		p.Add(f.flagName, true)
	} else if f.flagName != "" {
		p.Add(f.flagName, f.flagValue)
	}
	i := httpsfv.Item{
		Value:  f.name,
		Params: p,
	}
	return i
}

func (f field) asSignatureInput() (string, error) {
	s, err := httpsfv.Marshal(f.toItem())
	return s, err
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

//  contains verifies that all required fields are in the given list of fields (yes, this is O(n^2))
func (fs *Fields) contains(requiredFields *Fields) bool {
outer:
	for _, f1 := range requiredFields.f {
		for _, f2 := range fs.f {
			if f1 == f2 {
				continue outer
			}
		}
		return false
	}
	return true
}
