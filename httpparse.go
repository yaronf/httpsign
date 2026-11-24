package httpsign

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/text/encoding/unicode"
)

// some fields (specifically, query params) may appear more than once, and those occurrences are ordered.
type components map[string]string

type parsedMessage struct {
	derived           components
	url               *url.URL
	headers, trailers http.Header // we abuse this type: names are lowercase instead of canonicalized
	qParams           url.Values
}

func parseRequest(req *http.Request, withTrailers bool, maxBodySize int64, schemeOverride string) (*parsedMessage, error) {
	if req == nil {
		return nil, fmt.Errorf("nil request")
	}

	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	if schemeOverride != "" {
		scheme = schemeOverride
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

	return parseMessage(msg, withTrailers, maxBodySize)
}

func parseQueryForSignature(query string) url.Values {
	escaped := url.Values{}
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		escaped.Add(QueryEscapeForSignature(decodeQueryComponent(name)), QueryEscapeForSignature(decodeQueryComponent(value)))
	}
	return escaped
}

func decodeQueryComponent(value string) string {
	var decoded strings.Builder
	for position := 0; position < len(value); position++ {
		switch value[position] {
		case '+':
			decoded.WriteByte(' ')
		case '%':
			if position+2 < len(value) {
				if octet, err := hex.DecodeString(value[position+1 : position+3]); err == nil {
					decoded.WriteByte(octet[0])
					position += 2
					continue
				}
			}
			decoded.WriteByte('%')
		default:
			decoded.WriteByte(value[position])
		}
	}
	result, _ := unicode.UTF8.NewDecoder().String(decoded.String())
	return result
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

func parseResponse(res *http.Response, withTrailers bool, maxBodySize int64) (*parsedMessage, error) {
	msg := &Message{
		statusCode: &res.StatusCode,
		headers:    res.Header,
		trailers:   res.Trailer,
		body:       &res.Body,
	}

	return parseMessage(msg, withTrailers, maxBodySize)
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

func parseMessage(msg *Message, withTrailers bool, maxBodySize int64) (*parsedMessage, error) {
	if msg == nil {
		return nil, fmt.Errorf("message must not be nil")
	}

	err := validateMessageHeaders(msg.headers)
	if err != nil {
		return nil, err
	}
	err = validateMessageHeaders(msg.trailers)
	if err != nil {
		return nil, fmt.Errorf("could not validate trailers: %w", err)
	}

	if withTrailers {
		if msg.body != nil {
			_, err = duplicateBody(msg.body, maxBodySize)
			if err != nil {
				return nil, fmt.Errorf("cannot duplicate message body: %w", err)
			}
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
			qParams = parseQueryForSignature(u.RawQuery)
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
