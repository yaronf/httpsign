package httpsign

import (
	"github.com/dunglas/httpsfv"
	"strings"
)

// Fields is a list of fields to be signed. To initialize, use HeaderList or for more complex
// cases, NewFields followed by a chain of Add... methods.
type Fields []field

type field struct {
	name                string
	flagName, flagValue string
}

// HeaderList is a simple way to generate a Fields list, where only simple header names and specialty headers
// are needed.
func HeaderList(hs []string) Fields {
	f := []field{}
	for _, h := range hs {
		hd := strings.ToLower(h) // loop variable scope pitfall!
		f = append(f, field{hd, "", ""})
	}
	return f
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

// AddHeaderName appends a bare header name, e.g. "cache-control"
func (fs *Fields) AddHeaderName(hdr string) *Fields {
	f := fromHeaderName(hdr)
	*fs = append(*fs, *f)
	return fs
}

// addHeaderAndFlag appends a header name, a flag and a value. This eventually results
// in the signature input "header-name";name="val"
func (fs *Fields) addHeaderAndFlag(hdr, flagName, flagValue string) *Fields {
	h := strings.ToLower(hdr)
	fn := strings.ToLower(flagName)
	fv := flagValue
	*fs = append(*fs, field{h, fn, fv})
	return fs
}

func fromQueryParam(qp string) *field {
	q := strings.ToLower(qp)
	name := "@query-params"
	flagName := "name"
	f := field{name, flagName, q}
	return &f
}

// AddQueryParam indicates a request for a specific query parameter to be signed
func (fs *Fields) AddQueryParam(qp string) *Fields {
	f := fromQueryParam(qp)
	*fs = append(*fs, *f)
	return fs
}

// AddDictHeader indicates that a specific instance of a header is to be signed
func (fs *Fields) AddDictHeader(hdr, key string) *Fields {
	k := strings.ToLower(key)
	return fs.addHeaderAndFlag(hdr, "key", k)
}

type AdditionalParams []param

type param struct {
	name, value string
}

func NewAdditionalParams() AdditionalParams {
	return []param{}
}

func (ap *AdditionalParams) AddParam(name, value string) *AdditionalParams {
	n := strings.ToLower(name) // but not the value!
	*ap = append(*ap, param{n, value})
	return ap
}

func (f field) asSignatureInput() (string, error) {
	p := httpsfv.NewParams()
	if f.flagName != "" {
		p.Add(f.flagName, f.flagValue)
	}
	i := httpsfv.Item{
		Value:  f.name,
		Params: p,
	}
	s, err := httpsfv.Marshal(i)
	return s, err
}

func (fs *Fields) asSignatureInput(ap AdditionalParams) (string, error) {
	il := httpsfv.InnerList{
		Items:  []httpsfv.Item{},
		Params: httpsfv.NewParams(),
	}
	for _, f := range *fs {
		if f.flagName == "" {
			il.Items = append(il.Items, httpsfv.Item{
				Value:  f.name,
				Params: httpsfv.NewParams(),
			})
		} else {
			p := httpsfv.NewParams()
			p.Add(f.flagName, f.flagValue)
			il.Items = append(il.Items, httpsfv.Item{
				Value:  f.name,
				Params: p,
			})
		}
	}
	if len(ap) > 0 {
		for _, p := range ap {
			il.Params.Add(p.name, p.value)
		}
	}
	s, err := httpsfv.Marshal(il)
	return s, err
}

//  compareFields verify that all required fields are in seenFields (yes, this is O(n^2))
func (seenFields *Fields) contains(requiredFields *Fields) bool {
outer:
	for _, f1 := range *requiredFields {
		for _, f2 := range *seenFields {
			if f1 == f2 {
				continue outer
			}
		}
		return false
	}
	return true
}
