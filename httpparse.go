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
	derived           components
	url               *url.URL
	headers, trailers http.Header // we abuse this type: names are lowercase instead of canonicalized
	qParams           url.Values
}

func parseRequest(req *http.Request, withTrailers bool) (*parsedMessage, error) {
	if req == nil {
		return nil, nil
	}
	err := validateMessageHeaders(req.Header)
	if err != nil {
		return nil, err
	}
	if withTrailers {
		_, err = duplicateBody(&req.Body) // read the entire body to populate the trailers
		if err != nil {
			return nil, fmt.Errorf("cannot duplicate request body: %w", err)
		}
		err = validateMessageHeaders(req.Trailer)
		if err != nil {
			return nil, fmt.Errorf("could not validate trailers: %w", err)
		}
	}
	// Query params are only obtained from the URL (i.e. not from the message body, when using application/x-www-form-urlencoded)
	// So we are not vulnerable to the issue described in Sec. "Ambiguous Handling of Query Elements" of the draft.
	values, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("cannot parse query: %s", req.URL.RawQuery)
	}
	escaped := reEncodeQPs(values)
	u := req.URL
	if u.Host == "" {
		u.Host = req.Host
	}
	if u.Scheme == "" {
		if req.TLS == nil {
			u.Scheme = "http"
		} else {
			u.Scheme = "https"
		}
	}
	return &parsedMessage{derived: generateReqDerivedComponents(req), url: u, headers: normalizeHeaderNames(req.Header),
		trailers: normalizeHeaderNames(req.Trailer), qParams: escaped}, nil
}

func reEncodeQPs(values url.Values) url.Values {
	escaped := url.Values{}
	for key, v := range values { // Re-escape query parameters, both names and values
		escapedKey := QueryEscapeForSignature(key)
		escaped[escapedKey] = make([]string, len(values[key]))
		for key2 := range v {
			escaped[escapedKey][key2] = QueryEscapeForSignature(values[key][key2])
		}
	}
	return escaped
}

func normalizeHeaderNames(header http.Header) http.Header {
	if header == nil {
		return nil
	}
	var t = http.Header{}
	for k, v := range header {
		t[strings.ToLower(k)] = v
	}
	return t
}

func parseResponse(res *http.Response, withTrailers bool) (*parsedMessage, error) {
	err := validateMessageHeaders(res.Header)
	if err != nil {
		return nil, err
	}
	if withTrailers {
		_, err = duplicateBody(&res.Body) // read the entire body to populate the trailers
		if err != nil {
			return nil, fmt.Errorf("cannot duplicate request body: %w", err)
		}
		err = validateMessageHeaders(res.Trailer)
		if err != nil {
			return nil, fmt.Errorf("could not validate trailers: %w", err)
		}
	}

	return &parsedMessage{derived: generateResDerivedComponents(res), url: nil,
		headers: normalizeHeaderNames(res.Header)}, nil
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

func derivedComponent(name, v string, components components) {
	components[name] = v
}

func generateReqDerivedComponents(req *http.Request) components {
	components := components{}
	derivedComponent("@method", scMethod(req), components)
	theURL := req.URL
	derivedComponent("@target-uri", scTargetURI(theURL), components)
	derivedComponent("@path", scPath(theURL), components)
	derivedComponent("@authority", scAuthority(req), components)
	derivedComponent("@scheme", scScheme(theURL), components)
	derivedComponent("@request-target", scRequestTarget(theURL), components)
	derivedComponent("@query", scQuery(theURL), components)
	return components
}

func scPath(theURL *url.URL) string {
	return theURL.EscapedPath()
}

func scQuery(url *url.URL) string {
	return "?" + url.RawQuery
}

func scRequestTarget(url *url.URL) string {
	if url.RawQuery == "" {
		return url.Path
	}
	return url.Path + "?" + url.RawQuery
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
	derivedComponent("@status", scStatus(res), components)
	return components
}

func scStatus(res *http.Response) string {
	return strconv.Itoa(res.StatusCode)
}
