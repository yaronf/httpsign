package httpsign

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type parsedMessage struct {
	components map[string]string
}

type component struct {
	name, value string
}

func matchFields(components map[string]string, fields []string) ([]component, error) {
	// Components for signature are ordered, thus an array of pairs and not a map
	matched := make([]component, 0)
	for _, f := range fields {
		if c, found := components[f]; found {
			matched = append(matched, component{f, c})
		} else {
			return nil, fmt.Errorf("missing component: %s", f)
		}
	}
	return matched, nil
}

func parseRequest(req *http.Request) (*parsedMessage, error) {
	err := validateMessageHeaders(req.Header)
	if err != nil {
		return nil, err
	}
	components := map[string]string{}
	generateReqSpecialtyComponents(req, components)
	generateHeaderComponents(req.Header, components)

	return &parsedMessage{components}, nil
}

func parseResponse(res *http.Response) (*parsedMessage, error) {
	err := validateMessageHeaders(res.Header)
	if err != nil {
		return nil, err
	}
	components := map[string]string{}
	generateResSpecialtyComponents(res, components)
	generateHeaderComponents(res.Header, components)

	return &parsedMessage{components}, nil
}

func validateMessageHeaders(header http.Header) error {
	// Go accepts header names that start with "@", which is forbidden by the RFC
	for k := range header {
		if strings.HasPrefix(k, "@") {
			return fmt.Errorf("potentially malicious header detected: %s", k)
		}
	}
	return nil
}

func generateHeaderComponents(headers http.Header, components map[string]string) {
	for key, val := range headers {
		components[strings.ToLower(key)] = foldFields(val)
	}
}

func foldFields(fields []string) string {
	ff := strings.TrimSpace(fields[0])
	for i := 1; i < len(fields); i++ {
		ff += ", " + strings.TrimSpace(fields[i])
	}
	return ff
}

func generateReqSpecialtyComponents(req *http.Request, components map[string]string) {
	components["@method"] = scMethod(req)
	theUrl := req.URL
	components["@target-uri"] = scTargetUri(theUrl)
	components["@authority"] = scAuthority(req)
	components["@scheme"] = scScheme(theUrl)
	components["@request-target"] = scRequestTarget(theUrl)
	components["@query"] = scQuery(theUrl)
	// @request-response does not belong here
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
	} else {
		return url.Scheme
	}
}

func scAuthority(req *http.Request) string {
	return req.Host
}

func scTargetUri(url *url.URL) string {
	return url.String()
}

func scMethod(req *http.Request) string {
	return req.Method
}

func generateResSpecialtyComponents(res *http.Response, components map[string]string) {
	components["@status"] = scStatus(res)
}

func scStatus(res *http.Response) string {
	return strconv.Itoa(res.StatusCode)
}
