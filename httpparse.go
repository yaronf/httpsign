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

	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}

	msg := &Message{
		method:    req.Method,
		url:       req.URL,
		headers:   req.Header,
		trailers:  req.Trailer,
		body:      &req.Body,
		authority: req.Host,
		scheme:    scheme,
	}

	return parseMessage(msg, withTrailers)
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
	msg := &Message{
		statusCode: &res.StatusCode,
		headers:    res.Header,
		trailers:   res.Trailer,
		body:       &res.Body,
	}

	return parseMessage(msg, withTrailers)
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
	if len(fields) == 0 {
		return ""
	}
	ff := strings.TrimSpace(fields[0])
	for i := 1; i < len(fields); i++ {
		ff += ", " + strings.TrimSpace(fields[i])
	}
	return ff
}

func derivedComponent(name, v string, components components) {
	components[name] = v
}

func generateReqDerivedComponents(method string, u *url.URL, authority string, components components) {
	derivedComponent("@method", method, components)
	derivedComponent("@target-uri", scTargetURI(u), components)
	derivedComponent("@path", scPath(u), components)
	derivedComponent("@authority", authority, components)
	derivedComponent("@scheme", scScheme(u), components)
	derivedComponent("@request-target", scRequestTarget(u), components)
	derivedComponent("@query", scQuery(u), components)
}

func scPath(theURL *url.URL) string {
	return theURL.EscapedPath()
}

func scQuery(url *url.URL) string {
	return "?" + url.RawQuery
}

func scRequestTarget(url *url.URL) string {
	path := url.Path
	if path == "" {
		path = "/" // Normalize path, issue #8, and see https://www.rfc-editor.org/rfc/rfc9110#section-4.2.3
	}
	if url.RawQuery == "" {
		return path
	}
	return path + "?" + url.RawQuery
}

func scScheme(url *url.URL) string {
	if url.Scheme == "" {
		return "http"
	}
	return url.Scheme
}

func scTargetURI(url *url.URL) string {
	return url.String()
}

func scStatus(statusCode int) string {
	return strconv.Itoa(statusCode)
}

func parseMessage(msg *Message, withTrailers bool) (*parsedMessage, error) {
	if msg == nil {
		return nil, nil
	}

	err := validateMessageHeaders(msg.headers)
	if err != nil {
		return nil, err
	}

	if withTrailers {
		if msg.body != nil {
			_, err = duplicateBody(msg.body)
			if err != nil {
				return nil, fmt.Errorf("cannot duplicate message body: %w", err)
			}
		}
		err = validateMessageHeaders(msg.trailers)
		if err != nil {
			return nil, fmt.Errorf("could not validate trailers: %w", err)
		}
	}

	derived := components{}
	var u *url.URL
	var qParams url.Values

	if msg.method != "" || msg.url != nil {
		if msg.method == "" || msg.url == nil {
			return nil, fmt.Errorf("invalid state: method or url without the other")
		}

		u = msg.url
		if u == nil {
			u = &url.URL{Path: "/"}
		}
		if u.Host == "" && msg.authority != "" {
			u.Host = msg.authority
		}
		if u.Scheme == "" {
			if msg.scheme != "" {
				u.Scheme = msg.scheme
			} else {
				u.Scheme = "http"
			}
		}

		if u.RawQuery != "" {
			values, err := url.ParseQuery(u.RawQuery)
			if err != nil {
				return nil, fmt.Errorf("cannot parse query: %s", u.RawQuery)
			}
			qParams = reEncodeQPs(values)
		}

		generateReqDerivedComponents(msg.method, u, msg.authority, derived)
	} else if msg.statusCode != nil {
		derivedComponent("@status", scStatus(*msg.statusCode), derived)
	} else {
		return nil, fmt.Errorf("invalid state: method and url, or status required")
	}

	return &parsedMessage{
		derived:  derived,
		url:      u,
		headers:  normalizeHeaderNames(msg.headers),
		trailers: normalizeHeaderNames(msg.trailers),
		qParams:  qParams,
	}, nil
}
