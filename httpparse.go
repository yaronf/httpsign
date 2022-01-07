package main

import (
	"net/http"
	"strings"
)

type parsedMessage struct {
	components map[string]string
}

func matchFields(components map[string]string, fields []string) map[string]string {
	mf := map[string]string{}
	for _, f := range fields {
		if c, found := components[f]; found {
			mf[f] = c
		}
	}
	return mf
}

func ParseRequest(req *http.Request) parsedMessage {
	components := map[string]string{}
	generateReqSpecialtyComponents(req, components)
	generateHeaderComponents(req.Header, components)

	return parsedMessage{components}
}

func ParseResponse(res *http.Response) parsedMessage {
	components := map[string]string{}
	generateResSpecialtyComponents(res, components)
	generateHeaderComponents(res.Header, components)

	return parsedMessage{components}
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
	components["@method"] = req.Method
	url := req.URL
	components["@target-uri"] = url.String()
	components["@authority"] = url.Host
	components["@scheme"] = url.Scheme
	components["@request-target"] = url.Path
}

func generateResSpecialtyComponents(res *http.Response, components map[string]string) {
	components["@status"] = res.Status
}
