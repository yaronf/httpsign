package httpsign

import (
	"fmt"
	"github.com/dunglas/httpsfv"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// some fields (specifically, query params) may appear more than once, and those occurrences are ordered.
type components map[field][]string

type parsedMessage struct {
	components components
}

type fvPair struct {
	f field
	v []string
}

func matchFields(comps components, fields Fields) ([]fvPair, error) {
	// Components for signature are ordered, thus an array of pairs and not a map
	matched := make([]fvPair, 0)
	for _, f := range fields {
		if v, found := comps[f]; found {
			matched = append(matched, fvPair{f, v})
		} else {
			return nil, fmt.Errorf("missing component \"%s\"", f.name)
		}
	}
	return matched, nil
}

func parseRequest(req *http.Request) (*parsedMessage, error) {
	err := validateMessageHeaders(req.Header)
	if err != nil {
		return nil, err
	}
	components := components{}
	generateReqSpecialtyComponents(req, components)
	err = generateHeaderComponents(req.Header, components)
	if err != nil {
		return nil, err
	}
	values, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("cannot parse query: %s", req.URL.RawQuery)
	}
	generateQueryParams(values, components)

	return &parsedMessage{components}, nil
}

func generateQueryParams(v map[string][]string, components components) {
	for name, values := range v {
		components[*fromQueryParam(name)] = values
	}
}

func parseResponse(res *http.Response) (*parsedMessage, error) {
	err := validateMessageHeaders(res.Header)
	if err != nil {
		return nil, err
	}
	components := components{}
	generateResSpecialtyComponents(res, components)
	err = generateHeaderComponents(res.Header, components)
	if err != nil {
		return nil, err
	}

	return &parsedMessage{components}, nil
}

func validateMessageHeaders(header http.Header) error {
	// Go accepts header names that start with "@", which is forbidden by the RFC
	for k := range header {
		if strings.HasPrefix(k, "@") {
			return fmt.Errorf("potentially malicious header detected \"%s\"", k)
		}
	}
	return nil
}

func generateHeaderComponents(headers http.Header, components components) error {
	for hdrName, val := range headers {
		lower := strings.ToLower(hdrName)
		dict, err := httpsfv.UnmarshalDictionary(val)
		if err == nil { // dictionary
			for _, name := range dict.Names() {
				v, _ := dict.Get(name)
				switch v.(type) {
				case httpsfv.Item:
					vv, err := httpsfv.Marshal(v.(httpsfv.Item))
					if err != nil {
						return fmt.Errorf("malformed dictionry member %s: %v", name, err)
					}
					components[*fromDictHeader(lower, name)] = []string{vv}
				case httpsfv.InnerList:
					vv, err := httpsfv.Marshal(v.(httpsfv.InnerList))
					if err != nil {
						return fmt.Errorf("malformed dictionry member %s: %v", name, err)
					}
					components[*fromDictHeader(lower, name)] = []string{vv}
				default:
					return fmt.Errorf("unexpected dictionary value")
				}
			}
		} else {
			components[*fromHeaderName(lower)] = []string{foldFields(val)}
		}
	}
	return nil
}

func foldFields(fields []string) string {
	ff := strings.TrimSpace(fields[0])
	for i := 1; i < len(fields); i++ {
		ff += ", " + strings.TrimSpace(fields[i])
	}
	return ff
}

func specialtyComponent(name, v string, components components) {
	components[*fromHeaderName(name)] = []string{v}
}

func generateReqSpecialtyComponents(req *http.Request, components components) {
	specialtyComponent("@method", scMethod(req), components)
	theURL := req.URL
	specialtyComponent("@target-uri", scTargetURI(theURL), components)
	specialtyComponent("@path", scPath(theURL), components)
	specialtyComponent("@authority", scAuthority(req), components)
	specialtyComponent("@scheme", scScheme(theURL), components)
	specialtyComponent("@request-target", scRequestTarget(theURL), components)
	specialtyComponent("@query", scQuery(theURL), components)
	// @request-response does not belong here
}

func scPath(theURL *url.URL) string {
	return theURL.EscapedPath()
}

func scQuery(url *url.URL) string {
	return "?" + url.RawQuery
}

func scRequestTarget(url *url.URL) string {
	return url.Path
}

func scScheme(url *url.URL) string {
	if url.Scheme == "" {
		return "http"
	}
	return url.Scheme
}

func scAuthority(req *http.Request) string {
	return req.Host
}

func scTargetURI(url *url.URL) string {
	return url.String()
}

func scMethod(req *http.Request) string {
	return req.Method
}

func generateResSpecialtyComponents(res *http.Response, components components) {
	specialtyComponent("@status", scStatus(res), components)
}

func scStatus(res *http.Response) string {
	return strconv.Itoa(res.StatusCode)
}
