package httpsign

import (
	"bufio"
	"bytes"
	"github.com/andreyvit/diff"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"text/template"
)

var httpreq5 = ``

var wantFields = `"kuku": my awesome header
"@query": ?k1=v1&k2
"@method": GET
"@target-uri": http://127.0.0.1:{{.Port}}/?k1=v1&k2
"@signature-params": ("kuku" "@query" "@method" "@target-uri");alg="hmac-sha256";keyid="key1"`

func execTemplate(t template.Template, name string, data interface{}) (string, error) {
	buf := &bytes.Buffer{}
	err := t.ExecuteTemplate(buf, name, data)
	return buf.String(), err
}

func newClientRequest(t *testing.T, method, url, body string) *http.Request {
	in := strings.NewReader(body)
	req, err := http.NewRequest(method, url, bufio.NewReader(in))
	if err != nil {
		t.Errorf("could not read request")
	}
	return req
}

var ts *httptest.Server // global, so can be used *inside* the server, too

func TestHTTP11(t *testing.T) {
	simpleHandler := func(w http.ResponseWriter, r *http.Request) {
		proto := r.Proto
		if proto != "HTTP/1.1" {
			t.Errorf("expected HTTP/1.1, got %s", proto)
		}
		sp := bytes.Split([]byte(ts.URL), []byte(":"))
		portval, err := strconv.Atoi(string(sp[2]))
		if err != nil {
			t.Errorf("cannot parse server port number")
		}
		tpl, err := template.New("fields").Parse(wantFields)
		if err != nil {
			t.Errorf("could not parse template")
		}
		type inputs struct{ Port int }
		wf, err := execTemplate(*tpl, "fields", inputs{Port: portval})
		verifier, err := NewHMACSHA256Verifier("key1", bytes.Repeat([]byte{0x03}, 64),
			NewVerifyConfig().SetVerifyCreated(false),
			Headers("@query"))
		if err != nil {
			t.Errorf("could not create verifier")
		}
		sigInput, err := verifyRequestDebug("sig1", *verifier, r)
		if err != nil {
			t.Errorf("failed to verify request: sig input: %s\nerr: %v", sigInput, err)
		}

		if sigInput != wf {
			// t.Errorf("expected: %s\ngot: %s\n", wantFields, sigInput)
			t.Errorf("unexpected fields: %s\n", diff.CharacterDiff(sigInput, wantFields))
		} // TODO: copy Host from request/response to URL if empty in URL
		w.WriteHeader(200)
	}
	ts = httptest.NewServer(http.HandlerFunc(simpleHandler))
	defer ts.Close()

	signer, err := NewHMACSHA256Signer("key1", bytes.Repeat([]byte{0x03}, 64),
		NewSignConfig().SignCreated(false),
		Headers("kuku", "@query", "@method", "@target-uri"))
	client := NewDefaultClient("sig1", signer, nil, nil)
	req := newClientRequest(t, "GET", ts.URL+"/"+"?k1=v1&k2", httpreq5)
	req.Header.Set("Kuku", "my awesome header")
	res, err := client.Do(req)
	if err != nil {
		t.Errorf("%v", err)
	}
	if res != nil {
		_, err = io.ReadAll(res.Body)
		_ = res.Body.Close()
		if err != nil {
			t.Errorf("%v", err)
		}

		if res.Status != "200 OK" {
			t.Errorf("Bad status returned")
		}
	}
}
