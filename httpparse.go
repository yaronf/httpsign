package httpsign

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// some fields (specifically, query params) may appear more than once, and those occurrences are ordered.
type components map[string]string

type parsedMessage struct {
	derived components
	url     *url.URL
	headers http.Header
	qParams url.Values
}

func parseRequest(req *http.Request) (*parsedMessage, error) {
	err := validateMessageHeaders(req.Header)
	if err != nil {
		return nil, err
	}
	values, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("cannot parse query: %s", req.URL.RawQuery)
	}
	url := req.URL
	if url.Host == "" {
		url.Host = req.Host
	}
	if url.Scheme == "" {
		if req.TLS == nil {
			url.Scheme = "http"
		} else {
			url.Scheme = "https"
		}
	}
	return &parsedMessage{derived: generateReqDerivedComponents(req), url: url, headers: normalizeHeaderNames(req.Header), qParams: values}, nil
}

func normalizeHeaderNames(header http.Header) http.Header {
	var t http.Header = http.Header{}
	for k, v := range header {
		t[strings.ToLower(k)] = v
	}
	return t
}

func parseResponse(res *http.Response) (*parsedMessage, error) {
	err := validateMessageHeaders(res.Header)
	if err != nil {
		return nil, err
	}

	return &parsedMessage{derived: generateResDerivedComponents(res), url: nil, headers: normalizeHeaderNames(res.Header)}, nil
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

func foldFields(fields []string) string {
	ff := strings.TrimSpace(fields[0])
	for i := 1; i < len(fields); i++ {
		ff += ", " + strings.TrimSpace(fields[i])
	}
	return ff
}

func specialtyComponent(name, v string, components components) {
	components[name] = v
}

func generateReqDerivedComponents(req *http.Request) components {
	components := components{}
	specialtyComponent("@method", scMethod(req), components)
	theURL := req.URL
	specialtyComponent("@target-uri", scTargetURI(theURL), components)
	specialtyComponent("@path", scPath(theURL), components)
	specialtyComponent("@authority", scAuthority(req), components)
	specialtyComponent("@scheme", scScheme(theURL), components)
	specialtyComponent("@request-target", scRequestTarget(theURL), components)
	specialtyComponent("@query", scQuery(theURL), components)
	// @request-response does not belong here
	return components
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

func generateResDerivedComponents(res *http.Response) components {
	components := components{}
	specialtyComponent("@status", scStatus(res), components)
	return components
}

func scStatus(res *http.Response) string {
	return strconv.Itoa(res.StatusCode)
}
